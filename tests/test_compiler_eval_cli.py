"""Compiler evaluation is offline by choice, routed through Hermes when live."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from agentsfence.cli import _run_test, main
from agentsfence.config import Settings
from agentsfence.diagnostics import compiler_eval_evidence, format_status, snapshot
from agentsfence.host_probe import probe_compiler_eval
from agentsfence.testkit.compiler_eval import first_call_wait_metrics, load_cases, percentile, run_offline


def test_offline_cli_schema_and_no_launcher(home: Path, monkeypatch: pytest.MonkeyPatch,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Recorded evaluation must never launch Hermes")

    monkeypatch.setattr("agentsfence.host_probe.run_probe", forbidden)
    monkeypatch.setattr("agentsfence.cli._upkeep", lambda: None)
    assert main(["test", "--compiler-eval", "--no-live", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == 1 and result["kind"] == "compiler-eval" and result["mode"] == "recorded"
    assert result["cases"] == 80 and len(result["categories"]) == 10
    assert result["totals"] == {"calls": 80, "overgrant": 0, "undergrant": 0, "mismatch": 0}
    assert result["compiles"] == 88 and result["fallback_compiles"] == 0
    assert result["model_calls"] == 88 and result["calls_per_compile"] == 1
    assert 0 <= result["latency_seconds"]["p50"] <= result["latency_seconds"]["p95"]
    waits = result["first_call_wait_seconds"]
    assert set(waits) == {"p50", "p95", "waited_count", "total_first_calls", "waited_fraction"}
    assert waits["total_first_calls"] == 80
    assert 0 <= waits["waited_count"] <= waits["total_first_calls"]
    assert waits["waited_fraction"] == waits["waited_count"] / 80


def test_billable_warning_precedes_live_probe(home: Path, monkeypatch: pytest.MonkeyPatch,
                                              capsys: pytest.CaptureFixture[str]) -> None:
    calls: list[str] = []

    def probe(path: Path, kind: str) -> dict[str, Any]:
        assert path == home and kind == "compiler-eval"
        assert "potentially billable" in capsys.readouterr().err
        calls.append(kind)
        return {"ok": True}

    monkeypatch.setattr("agentsfence.host_probe.run_probe", probe)
    args = argparse.Namespace(compiler_eval=True, scenario=[], all=False, model=None, provider=None,
                              no_live=False, yes=True, json=True)
    assert _run_test(home, args) == 0
    assert calls == ["compiler-eval"]


def test_unaccepted_live_eval_does_not_call_model(home: Path, monkeypatch: pytest.MonkeyPatch,
                                                 capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsfence.cli._interactive", lambda: False)
    monkeypatch.setattr("agentsfence.host_probe.run_probe", lambda *args: pytest.fail("No authorization for model calls"))
    args = argparse.Namespace(compiler_eval=True, scenario=[], all=False, model=None, provider=None,
                              no_live=False, yes=False, json=True)
    assert _run_test(home, args) == 2
    assert "--yes" in capsys.readouterr().err


def test_live_probe_uses_host_client_and_compile_provenance(make_fence: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    fence.evidence = lambda: {"started": 0, "evidence_digest": "same-route", "routing": "task"}
    audit: list[tuple[str, dict[str, Any]]] = []
    fence._audit = lambda event, **kw: audit.append((event, kw))

    def run(settings: Settings, *, client: Any) -> dict[str, Any]:
        assert settings is fence.settings and client is fence.compiler.client
        return {"ok": True, "mode": "live", "timings": [{"model": "hermes:provider:model"}], "fallback_compiles": 0}

    monkeypatch.setattr("agentsfence.testkit.compiler_eval.run", run)
    result = probe_compiler_eval(fence)
    assert result["provenance"]["evidence_digest"] == "same-route"
    assert result["provenance"]["compiler_model"] == "hermes:provider:model"
    assert audit[0][0] == "compiler_eval" and audit[0][1]["details"]["test_run"]


def test_doctor_shows_recorded_score_without_verifying_live_route(home: Path) -> None:
    hermes = home / "hermes"
    result = run_offline(hermes)
    data = snapshot(hermes)
    assert data["last_compiler_eval"]["details"]["totals"] == result["totals"]
    assert data["checks"]["compiler"]["status"] == "not_verified"
    text = format_status(data)
    assert "Last compiler evaluation (recorded): 0 over-grants, 0 under-grants" in text
    assert "p50" in text and "p95" in text and "model calls/compile" in text
    assert "First tool calls that waited:" in text


def test_last_eval_survives_visible_audit_tail(settings: Settings) -> None:
    path = settings.home / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"event": "compiler_eval", "details": {"mode": "recorded", "totals": {"overgrant": 0}}}
    path.write_text(json.dumps(row) + "\n" + (json.dumps({"event": "decision"}) + "\n") * 60)
    assert compiler_eval_evidence(path) == row


def test_percentiles_and_fixture_turn_count() -> None:
    assert percentile([1, 2, 3], 50) == 2
    assert percentile([1, 2, 3], 95) == 2.9
    assert percentile([], 50) is None
    assert sum(len(case["messages"]) for case in load_cases()) == 88


def test_first_call_wait_share_excludes_owner_only_turns() -> None:
    compiles = [{"first_call_wait_seconds": wait} for wait in (None, 0, 1, 3)]
    assert first_call_wait_metrics(compiles) == {"p50": 1, "p95": 2.8, "waited_count": 2,
                                                "total_first_calls": 3, "waited_fraction": 2 / 3}
    assert first_call_wait_metrics([]) == {"p50": None, "p95": None, "waited_count": 0,
                                          "total_first_calls": 0, "waited_fraction": None}


def test_recorded_eval_supports_two_stage_compiler(settings: Settings) -> None:
    from agentsfence.testkit.compiler_eval import run

    configured = settings.model_copy(update={"compiler": settings.compiler.model_copy(update={"stages": 2})})
    result = run(configured, cases=load_cases()[:1], recorded=True)
    assert result["ok"] and result["model_calls"] == 2 and result["calls_per_compile"] == 2


def test_live_corpus_launcher_budget_covers_all_owner_turns(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsfence import host_client

    measured: list[float] = []

    def call(path: Path, action: list[str], *, timeout: float, **kwargs: Any) -> dict[str, Any]:
        measured.append(timeout)
        return {"reachable": True, "outcome": "enforcing", "probe": {"ok": True}}

    monkeypatch.setattr(host_client, "call", call)
    assert host_client.probe(home, "compiler-eval")["ok"]
    assert measured[0] >= 88 * 30
