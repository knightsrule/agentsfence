"""Offline or routed-model compiler measurements, without executing any tools."""
from __future__ import annotations

import json
import math
import threading
import time
import uuid
from pathlib import Path
from typing import Any, cast

import yaml

from ..compiler import LLMClient
from ..config import Settings, load_settings

CORPUS = Path(__file__).with_name("compiler_cases.yaml")
# An evaluation catalogue describes hypothetical calls; it never registers or runs them.
EVAL_TOOLS = [
    "mcp_gmail_search_threads", "mcp_gmail_get_message", "mcp_gmail_send_message",
    "mcp_gmail_trash_thread", "mcp_drive_search_files", "mcp_drive_read_file_content",
    "mcp_drive_share_file", "mcp_drive_delete_file", "read_file", "write_file",
    "web_extract", "web_search", "terminal", "send_message", "memory",
]


def load_cases() -> list[dict[str, Any]]:
    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("Unsupported compiler evaluation corpus")
    return list(data["cases"])


class RecordedClient:
    """Only the explicit --no-live diagnostic uses recorded compiler outputs."""

    name = "recorded-compiler-eval"

    def __init__(self) -> None:
        self.default: Any = None

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        if not schema and system.startswith("Interpret the owner's request"):
            return json.dumps(self.default["interpretation"], ensure_ascii=False)
        return json.dumps(self.default, ensure_ascii=False)


class CountingClient:
    def __init__(self, client: LLMClient) -> None:
        self.client = client
        self.calls = 0
        self.lock = threading.Lock()

    @property
    def name(self) -> str:
        return self.client.name

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        with self.lock:
            self.calls += 1
        return self.client.complete(system, user, schema)


def evaluate_case(case: dict[str, Any], settings: Settings, client: LLMClient, *, recorded: bool) -> dict[str, Any]:
    from ..plugin import AgentsFence

    measured = CountingClient(client)
    if recorded:
        settings = settings.model_copy(update={"audit": settings.audit.model_copy(update={"enabled": False})})
    catalogue = list(dict.fromkeys([*EVAL_TOOLS, *(call["tool"] for call in case["calls"])]))
    fence = AgentsFence(settings, client=measured, persist=False, catalogue_fn=lambda: catalogue, yolo_fn=lambda: False)
    sid = "agentsfence-test-compiler-" + uuid.uuid4().hex
    observations: list[dict[str, Any]] = []
    compiles: list[dict[str, Any]] = []
    last_turn = len(case["messages"])
    try:
        for turn, message in enumerate(case["messages"], start=1):
            if recorded:
                cast(Any, client).default = message["model_output"]
            before, started = measured.calls, time.monotonic()
            fence.on_pre_llm_call(session_id=sid, task_id=sid, user_message=message["text"],
                                  is_first_turn=turn == 1, conversation_history=[], platform="cli", model="compiler-eval")
            first_wait: float | None = None
            for index, call in enumerate(case["calls"]):
                if call.get("after_turn", last_turn) != turn:
                    continue
                check_started = time.monotonic()
                pending = fence.store.get(sid)
                was_pending = bool(pending and pending.policy.pending_revision is not None)
                decision = fence.check(call["tool"], call["args"], session_id=sid, task_id=sid,
                                       tool_call_id=f"{sid}-{turn}-{index}")
                waited = round(time.monotonic() - check_started, 6) if was_pending else 0.0
                if first_wait is None:
                    first_wait = waited
                observations.append({"case_id": case["id"], "category": case["category"],
                                     "expected": call["expect"], "actual": decision.decision.value,
                                     "rule": decision.rule_id, "wait_seconds": waited})
            # Earlier turns without a call must settle before changing a recorded response.
            rec = fence.store.get(sid)
            if rec and rec.policy.pending_revision is not None:
                fence.store.wait_revision(sid, rec.policy.policy_id, started + settings.compiler.timeout_seconds + 1)
                rec = fence.store.get(sid)
            compiles.append({"case_id": case["id"], "turn": turn, "seconds": round(time.monotonic() - started, 6),
                             "calls": measured.calls - before, "first_call_wait_seconds": first_wait,
                             "fell_back": rec is None or rec.policy.source == "fallback" or rec.policy.compiler_status == "fallback",
                             "model": rec.policy.compiler_model if rec else None})
    finally:
        fence.store.drop(sid)
    return {"observations": observations, "compiles": compiles}


def percentile(values: list[float], percent: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * percent / 100
    lower, upper = math.floor(pos), math.ceil(pos)
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * (pos - lower), 6)


def first_call_wait_metrics(compiles: list[dict[str, Any]]) -> dict[str, Any]:
    """Count only turns with a tool call; owner-only turns have no first call."""
    waits = [float(item["first_call_wait_seconds"]) for item in compiles if item["first_call_wait_seconds"] is not None]
    waited = sum(wait > 0 for wait in waits)
    return {"p50": percentile(waits, 50), "p95": percentile(waits, 95),
            "waited_count": waited, "total_first_calls": len(waits),
            "waited_fraction": waited / len(waits) if waits else None}


def run(settings: Settings, *, client: LLMClient | None = None, cases: list[dict[str, Any]] | None = None,
        recorded: bool = False) -> dict[str, Any]:
    """Model calls are live only when a host-owned client was explicitly supplied."""
    if not recorded and client is None:
        raise ValueError("A live compiler evaluation requires Hermes' routed compiler client")
    chosen = load_cases() if cases is None else cases
    observations: list[dict[str, Any]] = []
    compiles: list[dict[str, Any]] = []
    from .progress import publish

    for index, case in enumerate(chosen):
        publish({"phase": "compiler-eval", "completed": index, "total": len(chosen), "scenario": case["id"],
                 "message": f"Evaluating compiler case {index + 1} of {len(chosen)}: {case['category']}/{case['id']}"})
        active_client = RecordedClient() if recorded else client
        assert active_client is not None
        result = evaluate_case(case, settings, active_client, recorded=recorded)
        observations.extend(result["observations"])
        compiles.extend(result["compiles"])
    publish({"phase": "compiler-eval", "completed": len(chosen), "total": len(chosen), "message": "Compiler evaluation complete."})
    categories: dict[str, dict[str, int]] = {}
    for item in observations:
        row = categories.setdefault(item["category"], {"calls": 0, "overgrant": 0, "undergrant": 0, "mismatch": 0})
        row["calls"] += 1
        row["overgrant"] += item["expected"] != "ALLOW" and item["actual"] == "ALLOW"
        row["undergrant"] += item["expected"] == "ALLOW" and item["actual"] != "ALLOW"
        row["mismatch"] += item["expected"] != item["actual"]
    totals = {key: sum(row[key] for row in categories.values()) for key in ("calls", "overgrant", "undergrant", "mismatch")}
    times = [float(item["seconds"]) for item in compiles]
    calls = sum(item["calls"] for item in compiles)
    fallback = sum(item["fell_back"] for item in compiles)
    return {"schema_version": 1, "kind": "compiler-eval", "mode": "recorded" if recorded else "live",
            "ok": totals["mismatch"] == 0 and fallback == 0, "cases": len(chosen), "categories": categories,
            "totals": totals, "latency_seconds": {"p50": percentile(times, 50), "p95": percentile(times, 95)},
            "first_call_wait_seconds": first_call_wait_metrics(compiles),
            "compiles": len(compiles), "model_calls": calls, "calls_per_compile": calls / len(compiles) if compiles else 0,
            "fallback_compiles": fallback, "results": observations, "timings": compiles}


def run_offline(home: Path) -> dict[str, Any]:
    from ..audit import AuditLog
    from ..models import AuditEvent

    settings = load_settings(hermes_dir=home)
    result = run(settings, recorded=True)
    # Recorded fixtures provide regression evidence, never live route verification.
    AuditLog(settings.home / "audit.jsonl", settings.audit).record(AuditEvent(
        event="compiler_eval", details={**result, "test_run": True, "provenance": {"mode": "recorded"}},
    ))
    return result


def format_report(result: dict[str, Any]) -> str:
    if "totals" not in result:
        return "Compiler evaluation failed: " + str(result.get("error") or "no result")
    lines = [f"Compiler evaluation ({result['mode']}): {result['cases']} cases"]
    for category, row in sorted(result["categories"].items()):
        lines.append(f"  {category}: {row['overgrant']} over-grants, {row['undergrant']} under-grants ({row['calls']} calls)")
    latency = result["latency_seconds"]
    lines.append(f"Compile latency: p50 {latency['p50']}s, p95 {latency['p95']}s; {result['calls_per_compile']:.2f} model calls/compile")
    waits = result["first_call_wait_seconds"]
    share = waits.get("waited_fraction")
    share_text = f"{share:.1%}" if share is not None else "unavailable"
    lines.append(f"First tool call wait: p50 {waits['p50']}s, p95 {waits['p95']}s; "
                 f"{waits.get('waited_count', '?')}/{waits.get('total_first_calls', '?')} waited ({share_text})")
    lines.append(f"Total: {result['totals']['overgrant']} over-grants, {result['totals']['undergrant']} under-grants, "
                 f"{result['totals']['mismatch']} verdict mismatches, {result['fallback_compiles']} fallbacks")
    return "\n".join(lines)
