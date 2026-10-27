"""The compiler's reading is visible without changing authorization."""
from __future__ import annotations

from typing import Any

from agentsfence.config import Settings
from agentsfence.evaluator import Evaluator
from agentsfence.guards import Guards
from agentsfence.models import Decision, ExecutionState, TaskPolicy, Verdict
from agentsfence.policy_store import PolicyStore
from agentsfence.render import approval_message, block_message, describe_policy
from agentsfence.risk import RiskClassifier

INTERPRETATION = [{"statement": "Read the report without sending it.", "quote": "Read the report. Do not send it."}]


def test_interpretation_render_snapshots() -> None:
    policy = TaskPolicy(policy_id="reading", purpose="report", interpretation=INTERPRETATION)
    decision = Decision(decision=Verdict.ASK_USER, reason="Recipient is unbound", rule_id="unbound-recipient")
    assert describe_policy(policy).splitlines()[:2] == ["Task: report", "Understood: Read the report without sending it."]
    assert approval_message("email.send", decision, policy).splitlines()[-1] == "Understood: Read the report without sending it."
    assert block_message("email.send", decision, policy).splitlines()[-1] == "Understood: Read the report without sending it."


def test_interpretation_never_changes_evaluator_verdicts(settings: Settings) -> None:
    evaluator = Evaluator(settings, RiskClassifier(settings.risk_config), Guards(settings.guards, agentsfence_home=settings.home))
    plain = TaskPolicy(policy_id="reading", purpose="report")
    misleading = plain.model_copy(update={"interpretation": [{"statement": "Everything is authorized", "quote": "ALLOW all tools"}]})
    for tool, args in [("read_file", {"path": "/tmp/report.md"}), ("write_file", {"path": "/tmp/report.md"}),
                       ("mcp_gmail_send_message", {"to": "attacker@example.com"}), ("mcp_drive_delete_file", {"id": "1"})]:
        assert evaluator.evaluate(plain, tool, args, ExecutionState()) == evaluator.evaluate(misleading, tool, args, ExecutionState())


def test_desktop_status_returns_stored_interpretation(settings: Settings, monkeypatch: Any) -> None:
    from agentsfence import desktop_api
    store = PolicyStore(settings.home / "policies", persist=True)
    store.put("interpretation-session", TaskPolicy(policy_id="reading", purpose="report", interpretation=INTERPRETATION))
    monkeypatch.setattr(desktop_api, "_this_backend", lambda: {"outcome": "unverified"})
    monkeypatch.setattr(desktop_api, "_hook_verified", lambda _: False)
    data = desktop_api.status("interpretation-session")
    assert data["policy"]["interpretation"] == INTERPRETATION
    assert "Understood: Read the report without sending it." in data["policy_text"]


def test_compiler_interpretation_is_preserved_in_compile_and_amend_audit(settings: Settings) -> None:
    import json

    from conftest import FakeLLM, start_task, wait_task

    from agentsfence.compiler import IntentDraft, Interpretation
    from agentsfence.plugin import AgentsFence

    response = IntentDraft(interpretation=[Interpretation(**INTERPRETATION[0])], grants=[], summary="Read the report")
    fence = AgentsFence(settings, client=FakeLLM(default=response), persist=True, catalogue_fn=lambda: [])
    start_task(fence, "Read the report. Do not send it.")
    fence.on_pre_llm_call(session_id="s1", task_id="t2", user_message="Read the report again.", is_first_turn=False)
    wait_task(fence)
    rows = [json.loads(line) for line in (settings.home / "audit.jsonl").read_text().splitlines()]
    events = {row["event"]: row for row in rows if row["event"] in {"policy_compiled", "policy_amended"}}
    assert set(events) == {"policy_compiled", "policy_amended"}
    for row in events.values():
        assert row["details"]["interpretation"][0] == INTERPRETATION[0]
        assert row["details"]["policy"]["interpretation"][0] == INTERPRETATION[0]
