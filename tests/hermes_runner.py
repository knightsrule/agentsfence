"""Run scenarios through a real Hermes Python: the integration-test harness (not a user command).

Runs *inside a Hermes Python*: loads AgentsFence through Hermes' real plugin
discovery in a throwaway HERMES_HOME and dispatches every tool call through
``model_tools.handle_function_call``: the same ``pre_tool_call`` → approval gate →
tool handler path the agent loop uses. The mock tool records whether it actually
ran. Compiles use the deterministic read-only test compiler (no model calls), set
on the loaded instance, so the harness never changes a user-facing setting.

``tests/test_hermes_integration.py`` drives it with ``spawn_hermes`` against the
Hermes install that ``AGENTSFENCE_HERMES_PYTHON`` names.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from agentsfence.testkit import mock_tools
from agentsfence.testkit.scenarios import SCENARIOS, Scenario, Step, read_only_expectations

_RESULT_STREAM = sys.stdout  # Hermes may redirect sys.stdout when imported under a pipe.

REPO_ROOT = Path(__file__).resolve().parents[1]


def _step_result(step: Step, decision: str, rule_id: str | None, reason: str | None, executed: bool, approval: str | None) -> dict[str, Any]:
    return {
        "tool": step.tool, "args": step.args, "expect": step.expect, "note": step.note,
        "decision": decision, "rule_id": rule_id, "reason": reason, "executed": executed, "approval": approval,
    }


def evaluate_checks(scn: Scenario) -> list[dict[str, Any]]:
    from agentsfence.testkit.harness import _check

    return [_check(c) for c in scn.checks]


def _scenario_result(scn: Scenario, policy_text: str, compiler_name: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "key": scn.key, "title": scn.title, "intent": scn.intent, "story": scn.story,
        "policy": policy_text, "compiler": compiler_name, "steps": steps, "checks": evaluate_checks(scn),
    }


# ---------------------------------------------------------------------------
# in-process run (must run inside a Hermes Python)
# ---------------------------------------------------------------------------


_APPROVER_PLUGIN = """\
def register(ctx):
    # Test-only plugin: approves every tool call. Loaded before AgentsFence to
    # check that its "approve" cannot hide AgentsFence's "block".
    ctx.register_hook("pre_tool_call", lambda **kw: {"action": "approve", "message": "approver says yes"})
"""


def run_in_hermes(
    scenarios: list[Scenario],
    hermes_root: Path | None = None,
    *,
    no_human: bool = False,
    extra_approver: bool = False,
    yolo: bool = False,
    skip_pre_llm: bool = False,
    force_fallback: bool = False,
    preapprove_step: int | None = None,
    cron_approve: bool = False,
    strict_yolo: bool = False,
    gateway: bool = False,
) -> list[dict[str, Any]]:
    """``gateway``: a person answers in the Desktop or a messaging gateway, through Hermes' gateway approval queue."""
    tmp = Path(tempfile.mkdtemp(prefix="agentsfence-hermes-test-"))
    hermes_home = tmp / "hermes"
    (hermes_home / "plugins").mkdir(parents=True)
    # A source checkout loads as a directory plugin; a wheel loads through its
    # hermes_agent.plugins entry point, with no plugin directory.
    directory_install = (REPO_ROOT / "plugin.yaml").is_file()
    if directory_install:
        (hermes_home / "plugins" / "agentsfence").symlink_to(REPO_ROOT, target_is_directory=True)
    enabled = ["agentsfence"]
    if extra_approver:
        ap = hermes_home / "plugins" / "aaa-approver"
        ap.mkdir()
        (ap / "plugin.yaml").write_text("name: aaa-approver\nversion: '0'\nhooks: [pre_tool_call]\n", encoding="utf-8")
        (ap / "__init__.py").write_text(_APPROVER_PLUGIN, encoding="utf-8")
        enabled.insert(0, "aaa-approver")
    config = "plugins:\n  enabled:\n" + "".join(f"    - {n}\n" for n in enabled)
    if cron_approve:
        config += "approvals:\n  cron_mode: approve\n"
        os.environ["HERMES_CRON_SESSION"] = "1"
    else:
        os.environ.pop("HERMES_CRON_SESSION", None)
    (hermes_home / "config.yaml").write_text(config, encoding="utf-8")
    if yolo:
        os.environ["HERMES_YOLO_MODE"] = "1"  # read by tools.approval at import time
    os.environ.update(
        {
            "HERMES_HOME": str(hermes_home),
            "AGENTSFENCE_HOME": str(tmp / "af"),
            "AGENTSFENCE_TEST_TOOLS": "1",
        }
    )
    if strict_yolo:
        os.environ["AGENTSFENCE_STRICT_YOLO"] = "1"
    else:
        os.environ.pop("AGENTSFENCE_STRICT_YOLO", None)
    if no_human or gateway:
        os.environ.pop("HERMES_INTERACTIVE", None)
    else:
        os.environ["HERMES_INTERACTIVE"] = "1"  # a (simulated) human is present to answer approvals
    if gateway:
        os.environ["HERMES_GATEWAY_SESSION"] = "1"  # the Desktop backend and gateways answer through this queue
    else:
        os.environ.pop("HERMES_GATEWAY_SESSION", None)
    if hermes_root is not None:
        sys.path.insert(0, str(hermes_root))
    import model_tools  # noqa: F401  (initialises the tool registry)
    from hermes_cli import plugins as hp
    from tools import terminal_tool

    hp.discover_plugins(force=True)
    info = {p["name"]: p for p in hp.get_plugin_manager().list_plugins()}
    af = info.get("agentsfence")
    if not af or not af["enabled"] or af["error"]:
        raise RuntimeError(f"AgentsFence failed to load in Hermes: {af}")

    # The demo tools must be the plugin's copy of the workspace.
    ws_mod = sys.modules.get("hermes_plugins.agentsfence.agentsfence.testkit.mock_tools")
    workspace = ws_mod.WORKSPACE if ws_mod else mock_tools.WORKSPACE
    fence_mod = sys.modules.get("hermes_plugins.agentsfence.agentsfence.plugin") or importlib.import_module("agentsfence.plugin")
    render_mod = sys.modules.get("hermes_plugins.agentsfence.agentsfence.render") or importlib.import_module("agentsfence.render")
    fence = fence_mod.get_instance()
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    fence._client, fence._compiler = __import__("rules_client").RulesClient(), None  # deterministic, no model calls
    fence.settings.compiler.hermes_task = None  # fixture bypasses only the model route, never evaluation
    hook_order = [getattr(cb, "__qualname__", repr(cb)) for cb in hp.get_plugin_manager()._hooks.get("pre_tool_call", [])]
    load_order = list(getattr(hp.get_plugin_manager(), "_plugins", {}).keys())

    audit_path = tmp / "af" / "audit.jsonl"
    results = []
    try:
        for scn in read_only_expectations(scenarios):
            workspace.reset()
            mock_tools.WORKSPACE = workspace  # checks read the same object
            sid = f"test-{scn.key}-{uuid.uuid4().hex[:6]}"
            if not skip_pre_llm:
                hp.invoke_hook("pre_llm_call", session_id=sid, task_id=sid, turn_id="t0", user_message=scn.intent,
                               conversation_history=[], is_first_turn=True, model="demo", platform="cli", sender_id="")
                pending = fence.store.get(sid)
                if pending is not None:
                    deadline = time.monotonic() + fence.settings.compiler.timeout_seconds + 1
                    assert fence.store.wait_revision(sid, pending.policy.policy_id, deadline) == "ready"
                    while fence._compiling.get(sid):
                        assert time.monotonic() < deadline
                        time.sleep(.001)
            if force_fallback:
                fallback = fence.compiler.fallback(fence_mod.CompileContext(session_id=sid, task_id=sid))
                fence.store.put(sid, fallback, task_id=sid)
            rec = fence.store.get(sid)
            if preapprove_step is not None:
                assert rec is not None
                step = scn.steps[preapprove_step]
                assessed = fence.evaluator.assess(rec.policy, step.tool, step.args, rec.state, yolo=False)
                from tools.approval import approve_permanent

                approve_permanent("plugin_rule:" + fence.rule_key_for(rec.policy, step.tool, assessed.decision))
            policy_text = render_mod.describe_policy(rec.policy) if rec else "(no pre_llm_call: no policy yet)"
            steps = []
            for i, step in enumerate(scn.steps):
                call_id = f"{sid}-{i}"
                answer = step.approve or "deny"
                asked: list[str] = []

                def approval_cb(command: str, description: str, _answer: str = answer, _asked: list[str] = asked, **_: Any) -> str:
                    _asked.append(description)
                    return _answer

                terminal_tool.set_approval_callback(None if no_human or gateway else approval_cb)
                token = None
                if gateway:
                    import threading

                    from tools import approval as host_approval

                    def notify(data: dict[str, Any], _answer: str = answer, _asked: list[str] = asked, _sid: str = sid) -> None:
                        # The Desktop shows the request; the person answers a moment later.
                        _asked.append(str(data.get("description") or data))
                        threading.Timer(0.2, host_approval.resolve_gateway_approval, args=(_sid, _answer)).start()

                    host_approval.register_gateway_notify(sid, notify)
                    token = host_approval.set_current_session_key(sid)
                before = len(workspace.executed)
                try:
                    model_tools.handle_function_call(step.tool, dict(step.args), task_id=sid, tool_call_id=call_id, session_id=sid)
                finally:
                    if gateway:
                        host_approval.unregister_gateway_notify(sid)
                        if token is not None and hasattr(host_approval, "reset_current_session_key"):
                            host_approval.reset_current_session_key(token)
                executed = len(workspace.executed) > before
                ev = _last_decision(audit_path, call_id)
                steps.append(_step_result(step, ev.get("decision", "?"), ev.get("rule_id"), ev.get("reason"), executed, answer if asked else None))
            r = _scenario_result(scn, policy_text, fence.compiler.client.name + " via Hermes", steps)
            r["approvals"] = _approval_events(audit_path, sid)
            r["hook_order_at_load"] = hook_order
            r["plugin_load_order"] = load_order
            results.append(r)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return results


def _approval_events(audit_path: Path, sid: str) -> list[dict[str, Any]]:
    if not audit_path.is_file():
        return []
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    return [{"event": r["event"], "tool_call_id": r.get("tool_call_id"), "choice": (r.get("details") or {}).get("choice")}
            for r in rows if r.get("session_id") == sid and r.get("event") in {"approval_granted", "approval_denied"}]


def _last_decision(audit_path: Path, call_id: str) -> dict[str, Any]:
    if not audit_path.is_file():
        return {}
    for line in reversed(audit_path.read_text(encoding="utf-8").splitlines()):
        row = json.loads(line)
        if row.get("event") == "decision" and row.get("tool_call_id") == call_id:
            return dict(row)
    return {}


def find_hermes() -> tuple[Path, Path] | None:
    """``(python, source)`` for the Hermes install: the interpreter Hermes' own record names
    when its package manager owns the environment, else ``<source>/venv``.
    AGENTSFENCE_HERMES_PYTHON (``<source>/venv/bin/python``) selects a test install."""
    from agentsfence.hermes_env import detect
    from agentsfence.profiles import root_home

    install = detect(root_home(), shutil.which("hermes") or "")
    if install.python is None or install.source is None or not install.python.exists():
        return None
    return install.python, install.source


def find_hermes_python() -> Path | None:
    found = find_hermes()
    return found[0] if found else None


def spawn_hermes(keys: list[str], *, no_human: bool = False, extra_approver: bool = False, yolo: bool = False,
                 skip_pre_llm: bool = False, force_fallback: bool = False, preapprove_step: int | None = None,
                 cron_approve: bool = False, strict_yolo: bool = False, gateway: bool = False) -> list[dict[str, Any]]:
    found = find_hermes()
    if found is None:
        raise SystemExit("Could not find a Hermes installation. Set AGENTSFENCE_HERMES_PYTHON to Hermes' venv python.")
    py, hermes_root = found
    from agentsfence import __version__
    from agentsfence.hermes_env import installed_version

    env = dict(os.environ)
    # The harness must never change Hermes' install (a self-managed Hermes installs extras lazily).
    env["HERMES_DISABLE_LAZY_INSTALLS"] = "1"
    if installed_version(py) != __version__:
        # Hermes' environment lacks this version: run this copy. From a checkout that is the
        # source tree; from another environment its packages must match Hermes' Python.
        env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [str(py), str(REPO_ROOT / "tests" / "hermes_runner.py"), "--hermes-root", str(hermes_root)]
    for k in keys:
        cmd += ["--scenario", k]
    for flag, on in (("--no-human", no_human), ("--extra-approver", extra_approver), ("--yolo", yolo),
                     ("--skip-pre-llm", skip_pre_llm), ("--force-fallback", force_fallback),
                     ("--cron-approve", cron_approve), ("--strict-yolo", strict_yolo), ("--gateway", gateway)):
        if on:
            cmd.append(flag)
    if preapprove_step is not None:
        cmd += ["--preapprove-step", str(preapprove_step)]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=str(hermes_root))
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"Hermes scenario run failed (exit {proc.returncode})")
    payload = proc.stdout[proc.stdout.index("<<<AGENTSFENCE_JSON>>>") + len("<<<AGENTSFENCE_JSON>>>"):]
    return list(json.loads(payload))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tests/hermes_runner.py", description="AgentsFence integration harness")
    ap.add_argument("--scenario", action="append", default=[], help="run only these scenario keys")
    ap.add_argument("--hermes-root", default=None)
    ap.add_argument("--no-human", action="store_true", help="no interactive user: approvals must fail closed")
    ap.add_argument("--extra-approver", action="store_true", help="load a plugin that approves everything before AgentsFence")
    ap.add_argument("--yolo", action="store_true", help="run with HERMES_YOLO_MODE=1")
    ap.add_argument("--skip-pre-llm", action="store_true", help="dispatch tools without a pre_llm_call first")
    ap.add_argument("--force-fallback", action="store_true", help="replace the compiled policy with a fallback")
    ap.add_argument("--preapprove-step", type=int, help="allowlist one exact action before dispatch")
    ap.add_argument("--cron-approve", action="store_true", help="run as an unattended cron job configured to approve")
    ap.add_argument("--strict-yolo", action="store_true", help="block approvals Hermes would grant automatically")
    ap.add_argument("--gateway", action="store_true", help="a person answers through the Desktop/gateway approval queue")
    args = ap.parse_args(argv)
    scns = [s for s in SCENARIOS if not args.scenario or s.key in args.scenario]
    results = run_in_hermes(
        scns, Path(args.hermes_root) if args.hermes_root else None,
        no_human=args.no_human, extra_approver=args.extra_approver, yolo=args.yolo, skip_pre_llm=args.skip_pre_llm,
        force_fallback=args.force_fallback, preapprove_step=args.preapprove_step, cron_approve=args.cron_approve,
        strict_yolo=args.strict_yolo, gateway=args.gateway,
    )
    _RESULT_STREAM.write("<<<AGENTSFENCE_JSON>>>" + json.dumps(results, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
