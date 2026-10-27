"""The live model run of `agentsfence test`: a real chat model, the mock workspace, the real fence.

For each scenario, Hermes runs one non-interactive turn in the profile
(``hermes -p NAME -z <request> -m MODEL --provider P -t agentsfence-test``). Only the
mock Gmail/Drive toolset is enabled, so nothing the model does can reach real
tools or accounts; the profile's real compiler and AgentsFence decide every call.
A one-shot turn has no human. Hermes applies its configured unattended approval
mode, and the deterministic run separately exercises approval and denial callbacks.

What the model tried is read back from the profile's audit log, where the plugin
tags every row of the run with ``details.test_run``.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .mock_tools import TOOLSET
from .progress import Progress
from .scenarios import Scenario

TURN_TIMEOUT = 240.0
RUN_ENV = "AGENTSFENCE_TEST_RUN"


def run(home: Path, scenarios: list[Scenario], model: str, provider: str,
        *, progress: Progress | None = None) -> dict[str, list[dict[str, Any]]]:
    """``{scenario key: [{"tool", "decision", "rule_id"}]}`` for each scenario the model ran."""
    from ..diagnostics import audit_rows
    from ..hermes_env import launcher
    from ..profiles import profile_name, root_home

    exe = launcher()
    if not exe:
        raise RuntimeError("No Hermes launcher found (put `hermes` on PATH or set AGENTSFENCE_HERMES).")
    run_id = uuid.uuid4().hex[:8]
    observed: dict[str, list[dict[str, Any]]] = {}
    base = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PYTHONSTARTUP")}
    base.update(HERMES_HOME=str(root_home()), AGENTSFENCE_TEST_TOOLS="1")
    with tempfile.TemporaryDirectory(prefix="agentsfence-test-") as cwd:  # no project files for the model to read
        for index, scenario in enumerate(scenarios):
            if progress:
                progress({"phase": "live", "completed": index, "total": len(scenarios), "scenario": scenario.key,
                          "message": f"Live model scenario {index + 1} of {len(scenarios)}: {scenario.title}"})
            tag = f"{run_id}-{scenario.key}"
            command = [exe, "-p", profile_name(home), "-z", scenario.intent, "-m", model, "-t", TOOLSET]
            if provider and provider != "auto":
                command[5:5] = ["--provider", provider]
            try:
                turn = subprocess.run(command, env={**base, RUN_ENV: tag}, cwd=cwd, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=TURN_TIMEOUT)
            except subprocess.TimeoutExpired:
                observed[scenario.key] = [{"tool": "(turn timed out)", "decision": None, "rule_id": None, "error": True}]
                continue
            if turn.returncode:
                observed[scenario.key] = [{"tool": f"(Hermes turn failed: exit {turn.returncode})", "decision": None,
                                           "rule_id": None, "error": True}]
                continue
            rows = [r for r in audit_rows(home, limit=500)
                    if (r.get("details") or {}).get("test_run") == tag and r.get("event") == "decision"]
            observed[scenario.key] = [{"tool": r.get("tool"), "decision": r.get("decision"), "rule_id": r.get("rule_id")}
                                      for r in rows]
    return observed


def run_test(home: Path, scenarios: list[Scenario], *, live: bool = True, model: str | None = None,
             provider: str | None = None, accept_cost: bool = False, all_probes: bool = False,
             selected: list[str] | None = None, progress: Progress | None = None) -> dict[str, Any]:
    """The whole `agentsfence test` for one profile, shared by the CLI and the Desktop pane.

    Returns the deterministic result with the live run's observations merged in, or
    ``{"needs_confirmation": True, "live": {...}}`` when a paid model would be used
    and ``accept_cost`` is false.
    """
    from ..host_probe import run_probe
    from .models import projected_cost

    live_scenarios = [s for s in scenarios if not s.probe]
    summary: dict[str, Any] = {"skipped": "not requested" if not live else "probes only"}
    observed = None
    if live and live_scenarios:
        if model:
            summary = {"model": model, "provider": provider or "auto", "why": "chosen", "cost": None}
        else:
            if progress:
                progress({"phase": "models", "message": "Checking available live models and their projected cost."})
            picked = run_probe(home, "models")
            choice = picked.get("choice") or {}
            if not picked.get("ok"):
                summary = {"skipped": picked.get("error") or "no model found"}
            else:
                cost = (projected_cost(choice["prompt"], choice["completion"], len(live_scenarios))
                        if choice.get("prompt") is not None and choice.get("completion") is not None
                        else (0.0 if choice.get("free") else None))
                summary = {"model": choice["model"], "provider": choice["provider"], "why": choice["why"], "cost": cost}
        if summary.get("model") and summary.get("cost") != 0.0 and not accept_cost:
            return {"needs_confirmation": True, "live": summary}
        if summary.get("model"):
            observed = run(home, live_scenarios, summary["model"], summary.get("provider") or "auto",
                           **({"progress": progress} if progress is not None else {}))
    if progress:
        progress({"phase": "starting", "completed": 0, "total": len(scenarios),
                  "message": "Starting fresh Hermes scenario checks."})
    result = run_probe(home, "test-all" if all_probes else "test", selected or None,
                       **({"progress": progress} if progress is not None else {}))
    if "scenarios" in result and observed is not None:
        for scenario in result["scenarios"]:
            rows = observed.get(scenario["key"])
            scenario["observed"] = rows
            tried = {r.get("tool") for r in rows or []}
            for step in scenario["steps"]:
                step["attempted_by_model"] = step["tool"] in tried if rows is not None else None
    if observed is not None and any(row.get("error") for rows in observed.values() for row in rows):
        result["ok"] = False
        summary["error"] = "One or more live Hermes turns failed or timed out; see scenario observations."
    result["live"] = summary
    return result
