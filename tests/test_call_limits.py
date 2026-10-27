"""Semantic per-grant limits and deterministic reservation accounting."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import FakeLLM, draft, start_task, tool, verdict
from intent_fixtures import Evidence

from agentsfence.compiler import PolicyCompiler
from agentsfence.config import Settings
from agentsfence.evaluator import Evaluator
from agentsfence.guards import Guards
from agentsfence.models import ExecutionState, RiskClass, TaskPolicy, ToolConstraint, Verdict
from agentsfence.risk import RiskClassifier

URL = "https://agentsfence-alpha.vercel.app/test/office-update/"


def compile_with(settings: Settings, request: str, **fields: Any) -> Any:
    llm = FakeLLM(default=draft(purpose="task", **fields).intents(request))
    return PolicyCompiler(settings, RiskClassifier(settings.risk_config), llm).compile(request)


def test_read_intent_without_a_limit_allows_a_re_read(settings: Settings) -> None:
    """The model represents an object count without inventing a call limit."""
    result = compile_with(settings, f"Summarize {URL} in three bullets.",
                          allowed_capabilities=["web.fetch"], allowed_external_domains=["agentsfence-alpha.vercel.app"],
                          tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": None}})
    constraint = result.policy.tool_constraints["web.fetch"]
    assert constraint.max_calls is None and constraint.allowed_domains == ["agentsfence-alpha.vercel.app"]
    evaluator = Evaluator(settings, RiskClassifier(settings.risk_config), Guards(settings.guards, agentsfence_home=settings.home))
    state = ExecutionState()
    for _ in range(2):  # the second fetch with a larger char_limit is no longer blocked
        decision = evaluator.evaluate(result.policy, "web_extract", {"urls": [URL], "char_limit": 20000}, state)
        assert decision.decision is Verdict.ALLOW, decision.reason
        state.calls_by_key["web.fetch"] = state.calls_by_key.get("web.fetch", 0) + 1


@pytest.mark.parametrize("request_text", [
    f"Fetch {URL} once and summarize it.",
    f"Open {URL} only once, then summarize it.",
    f"Read the page at {URL} just one time.",
])
def test_a_limit_the_user_binds_to_the_read_is_kept(settings: Settings, request_text: str) -> None:
    result = compile_with(settings, request_text, allowed_capabilities=["web.fetch"],
                          tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": 1}})
    assert result.policy.tool_constraints["web.fetch"].max_calls == 1  # retained from the model's span-bound intent


@pytest.mark.parametrize("request_text", [
    f"Read one report from {URL} and summarize it.",   # an object count
    f"Check {URL} twice and tell me if it changed.",   # repetition, possibly many calls
    f"Once the page at {URL} loads, summarize it.",     # "once" as a conjunction
])
def test_counts_that_do_not_limit_a_read_never_validate_a_limit(settings: Settings, request_text: str) -> None:
    result = compile_with(settings, request_text, allowed_capabilities=["web.fetch"],
                          tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": None}})
    assert result.policy.tool_constraints["web.fetch"].max_calls is None


def test_consequential_limits_are_preserved(settings: Settings) -> None:
    result = compile_with(
        settings, f"Summarize {URL} and save the summary to ~/agentsfence-selftest/summary.md. "
                  "Then email it to john@example.com.",
        allowed_capabilities=["web.fetch", "file.write", "email.send"],
        allowed_risk_classes=[RiskClass.READ, RiskClass.LOCAL_WRITE, RiskClass.COMMUNICATION],
        allow_local_writes=True, allow_external_writes=True, allowed_recipients=["john@example.com"],
        allowed_paths=["~/agentsfence-selftest/summary.md"],
        tool_constraints={"file.write": {"allowed_paths": ["~/agentsfence-selftest/summary.md"], "max_calls": 1},
                          "email.send": {"allowed_recipients": ["john@example.com"], "max_calls": 1},
                          "web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": None}},
        evidence=[Evidence(permission="LOCAL_WRITE", quote="save the summary to ~/agentsfence-selftest/summary.md"),
                  Evidence(permission="COMMUNICATION", quote="email it to john@example.com")])
    limits = {k: c.max_calls for k, c in result.policy.tool_constraints.items()}
    assert limits["file.write"] == 1 and limits["email.send"] == 1  # independently scoped consequential budgets
    assert limits["web.fetch"] is None


@pytest.mark.parametrize("key,canonical", [("browser.read", "browser.read"), ("file.read", "file.read"),
    ("web_extract", "web.fetch"), ("web.*", None), ("made.up", None)])
def test_only_valid_concrete_grants_carry_limits(settings: Settings, key: str, canonical: str | None) -> None:
    from agentsfence.compiler import IntentDraft, IntentGrant
    request = f"Read {URL} twice."
    output = IntentDraft(interpretation=[], grants=[IntentGrant(id="read", capability=key, mode="request", span=request, max_calls=2)])
    result = PolicyCompiler(settings, RiskClassifier(settings.risk_config), FakeLLM(default=output)).compile(request)
    if canonical is None:
        assert result.policy.tool_constraints == {}
    else:
        assert result.policy.tool_constraints[canonical].max_calls == 2


def test_manual_policy_limits_are_never_rewritten(settings: Settings) -> None:
    """Explicit limits in a manual policy are not compiler output and are enforced as written."""
    policy = TaskPolicy(policy_id="manual", purpose="read", allowed_tools=["web.fetch"],
                        tool_constraints={"web.fetch": ToolConstraint(max_calls=1)})
    evaluator = Evaluator(settings, RiskClassifier(settings.risk_config), Guards(settings.guards, agentsfence_home=settings.home))
    state = ExecutionState(calls_by_key={"web.fetch": 1})
    decision = evaluator.evaluate(policy, "web_extract", {"urls": [URL]}, state)
    assert decision.decision is Verdict.BLOCK and decision.rule_id == "call-limit-exceeded"


def test_an_existing_task_limit_survives_an_amendment(settings: Settings) -> None:
    classifier = RiskClassifier(settings.risk_config)
    existing = PolicyCompiler(settings, classifier, FakeLLM(default=draft(
        purpose="task", allowed_capabilities=["web.fetch"],
        tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": 1}}))
    ).compile(f"Fetch {URL} once.").policy
    assert existing.tool_constraints["web.fetch"].max_calls == 1
    amended = PolicyCompiler(settings, classifier, FakeLLM(default=draft(
        purpose="task", allowed_capabilities=["web.fetch"],
        tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": 5}}))
    ).amend(existing, "Also summarize it in three bullets.").policy
    assert amended.tool_constraints["web.fetch"].max_calls == 1  # the user's earlier "once" still holds


@pytest.mark.parametrize(("request_text", "expected"), [
    # Review round 3 #4: "once" limits the read it is bound to, not every read.
    (f"Fetch {URL} once, then search the web for related news.", {"web.fetch": 1, "web.search": None}),
    (f"Search the web once for news about {URL} and fetch whatever helps.", {"web.fetch": None, "web.search": 1}),
    ("Fetch https://other.example.org/page once and summarize it.", {"web.fetch": None, "web.search": None}),
    (f"Summarize {URL}. Fetch it only once.", {"web.fetch": 1, "web.search": None}),  # a pronoun names no other site
])
def test_once_is_bound_to_the_specific_read_and_site(settings: Settings, request_text: str, expected: dict[str, Any]) -> None:
    result = compile_with(settings, request_text, allowed_capabilities=["web.fetch", "web.search"],
                          tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": expected["web.fetch"]},
                                            "web.search": {"max_calls": expected["web.search"]}})
    limits = {k: c.max_calls for k, c in result.policy.tool_constraints.items()}
    for key, limit in expected.items():
        assert limits.get(key) == limit, (key, limits)


@pytest.mark.parametrize(("request_text", "expected"), [
    # Review round 4 #4: only an explicit restriction on the requested read keeps a limit.
    ("Fetch https://agentsfence-alpha.vercel.app/a more than once and compare the versions.", None),
    ("Fetch https://agentsfence-alpha.vercel.app/a at least once.", None),
    ("Fetch https://agentsfence-alpha.vercel.app/a once again.", None),
    ("Fetch https://agentsfence-alpha.vercel.app/a once a day.", None),
    ("Explain what happens when you fetch https://agentsfence-alpha.vercel.app/a more than once.", None),
    ("Explain what happens when you fetch https://agentsfence-alpha.vercel.app/a once.", None),  # informational
    ("Summarize https://agentsfence-alpha.vercel.app/a, fetching it once.", 1),  # the clause opens with "summarize"
    ("Please fetch https://agentsfence-alpha.vercel.app/a at most once.", 1),
    ("Fetch https://agentsfence-alpha.vercel.app/a only once, then summarize it.", 1),
])
def test_once_must_restrict_the_requested_read(settings: Settings, request_text: str, expected: int | None) -> None:
    result = compile_with(settings, request_text, allowed_capabilities=["web.fetch"],
                          tool_constraints={"web.fetch": {"allowed_domains": ["agentsfence-alpha.vercel.app"], "max_calls": expected}})
    if request_text.startswith("Explain"):
        assert "web.fetch" not in result.policy.allowed_tools
    else:
        assert result.policy.tool_constraints["web.fetch"].max_calls == expected


# --- Write and delete limits count distinct files (early-user report, 0.2.0a5) ------------
# A correction of the model's own authorized summary.md was blocked with
# call-limit-exceeded and left a garbled file. A limit on a path-bound write or
# delete bounds how many files the task touches, not how often it edits one.

SUMMARY = "~/agentsfence-selftest/summary.md"


KIT_DIR = "~/agentsfence-selftest/"


def _write_limited_fence(make_fence: Any, limit: int = 1, paths: list[str] | None = None) -> Any:
    target = (paths or [SUMMARY])[0]
    llm = FakeLLM(default=draft(
        purpose="summarize_and_save", allowed_capabilities=["web.fetch", "file.write"],
        allowed_risk_classes=[RiskClass.READ, RiskClass.LOCAL_WRITE], allow_local_writes=True,
        allowed_paths=paths or [SUMMARY],
        tool_constraints={"file.write": {"allowed_paths": paths or [SUMMARY], "max_calls": limit}},
        evidence=[Evidence(permission="LOCAL_WRITE", quote=f"save the summary to {target}")]))
    fence = make_fence(llm)
    start_task(fence, f"Summarize {URL} and save the summary to {target} .")
    return fence


def test_rewriting_or_patching_the_authorized_file_is_not_a_new_use(make_fence: Any) -> None:
    import os

    fence = _write_limited_fence(make_fence)
    path = os.path.expanduser(SUMMARY)
    assert verdict(tool(fence, "write_file", {"path": path, "content": "draft"}, call_id="w1")) == "ALLOW"
    assert verdict(tool(fence, "write_file", {"path": path, "content": "fixed"}, call_id="w2")) == "ALLOW"
    assert verdict(tool(fence, "patch", {"path": path, "old_string": "fixed", "new_string": "final"}, call_id="w3")) == "ALLOW"
    assert fence.store.get("s1").state.uses("file.write") == 1


def test_a_second_distinct_file_still_exceeds_the_limit(make_fence: Any) -> None:
    import os

    fence = _write_limited_fence(make_fence, paths=[KIT_DIR])
    assert verdict(tool(fence, "write_file", {"path": os.path.expanduser(SUMMARY), "content": "x"}, call_id="w1")) == "ALLOW"
    out = tool(fence, "write_file", {"path": os.path.expanduser("~/agentsfence-selftest/other.md"), "content": "x"}, call_id="w2")
    assert verdict(out) == "BLOCK" and "call-limit-exceeded" in out["message"]


def test_a_denied_write_releases_its_target(make_fence: Any) -> None:
    import os

    fence = _write_limited_fence(make_fence, paths=[KIT_DIR])
    fence.store.get("s1").policy.requires_approval.append("file.write")
    path = os.path.expanduser("~/agentsfence-selftest/other.md")
    assert verdict(tool(fence, "write_file", {"path": path, "content": "x"}, call_id="ask1")) == "ASK_USER"
    assert fence.store.get("s1").state.uses("file.write") == 1  # reserved while the user decides
    fence.on_post_tool_call(session_id="s1", task_id="t1", tool_call_id="ask1", tool_name="write_file", status="blocked")
    assert fence.store.get("s1").state.uses("file.write") == 0


def test_a_patch_whose_files_cannot_be_verified_counts_as_a_call(settings: Settings) -> None:
    evaluator = Evaluator(settings, RiskClassifier(settings.risk_config), Guards(settings.guards, agentsfence_home=settings.home))
    policy = TaskPolicy(policy_id="p", purpose="edit", allowed_risk_classes=[RiskClass.READ, RiskClass.LOCAL_WRITE],
                        allow_local_writes=True, tool_constraints={"file.write": ToolConstraint(max_calls=1)})
    state = ExecutionState(calls_by_key={"file.write": 1})
    decision = evaluator.evaluate(policy, "patch", {"mode": "patch", "patch": "*** Begin Patch\n*** End Patch"}, state)
    assert decision.decision is not Verdict.ALLOW


def test_send_limits_still_count_every_call(make_fence: Any) -> None:
    llm = FakeLLM(default=draft(
        purpose="send_once", allowed_capabilities=["email.send"], allowed_risk_classes=[RiskClass.READ, RiskClass.COMMUNICATION],
        allow_external_writes=True, allowed_recipients=["john@example.com"],
        tool_constraints={"email.send": {"allowed_recipients": ["john@example.com"], "max_calls": 1}},
        evidence=[Evidence(permission="COMMUNICATION", quote="email the summary to john@example.com")]))
    fence = make_fence(llm)
    start_task(fence, "Send one email: email the summary to john@example.com.")
    assert verdict(tool(fence, "mcp_gmail_send_message", {"to": "john@example.com", "body": "a"}, call_id="e1")) == "ALLOW"
    assert verdict(tool(fence, "mcp_gmail_send_message", {"to": "john@example.com", "body": "a"}, call_id="e2")) == "BLOCK"


def test_distinct_target_counts_persist(settings: Settings, tmp_path: Any) -> None:
    from agentsfence.policy_store import PolicyStore, Reservation

    store = PolicyStore(tmp_path / "policies", persist=True)
    rec = store.put("s", TaskPolicy(policy_id="p", purpose="x"))
    store.reserve(rec, "c1", Reservation(tool="write_file", capability="file.write", risk=RiskClass.LOCAL_WRITE,
                                         constraint_keys=["file.write"], counted_targets=["/a/b/c.md"]))
    store.settle(rec, "c1")
    reloaded = PolicyStore(tmp_path / "policies", persist=True).get("s")
    assert reloaded is not None and reloaded.state.new_targets("file.write", ["/a/b/c.md"]) == []
