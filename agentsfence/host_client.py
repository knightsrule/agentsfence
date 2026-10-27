"""Ask Hermes itself, through its own launcher, what a new process loads.

Doctor, probes and Desktop checks run ``hermes -p <profile> agentsfence …`` so the
answer comes from Hermes' real runtime and dependencies, whatever install layout
or Python the launcher uses. The caller's own package never leaks in: the child
gets no PYTHONPATH/PYTHONHOME/VIRTUAL_ENV, and the command answers for its own
process only (see ``failsafe.register_status_command``).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .failsafe import _SECRET, STATUS_MARKER, STATUS_SCHEMA
from .hermes_env import UNVERIFIED
from .profiles import profile_name, root_home
from .testkit.progress import PROGRESS_FILE, Progress

STATUS_TIMEOUT = 90.0
PROBE_TIMEOUT = 150.0
#: Scenario tests and job dry runs compile several requests, each within the compile budget.
LONG_PROBE_TIMEOUT = 900.0
_MAX_OUTPUT = 1_000_000
_ISOLATED = ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "PYTHONSTARTUP")



def launcher() -> str | None:
    """The Hermes launcher to ask: AGENTSFENCE_HERMES, else ``hermes`` on PATH."""
    from .hermes_env import launcher as installation_launcher

    return installation_launcher()


def _redact(text: str, limit: int = 400) -> str:
    lines = [line for line in text.strip().splitlines() if line.strip()][-4:]
    return _SECRET.sub("[redacted]", " | ".join(lines))[:limit]


def call(home: Path, action: list[str], *, timeout: float = STATUS_TIMEOUT,
         progress: Progress | None = None) -> dict[str, Any]:
    """Run ``hermes -p <profile> agentsfence <action> --json`` and return its answer.

    Always returns a dict. ``reachable`` is True only when Hermes answered with a
    well-formed response for the requested profile.
    """
    exe = launcher()
    if not exe:
        return {"reachable": False, "error": "No Hermes launcher found (put `hermes` on PATH or set AGENTSFENCE_HERMES)."}
    work = pending_work(exe)
    if work:
        # Starting Hermes would run that work now, and chats fail until it finishes.
        kind, pending = work
        why = ("cannot confirm that it has none" if kind == UNVERIFIED else "has update work pending")
        return {"reachable": False, "launcher": exe, "pending_update": pending, "pending_kind": kind,
                "error": f"Not checked: {pending}. AgentsFence does not start Hermes while it {why}, "
                         "because the check itself would run that work. Re-run this check afterwards."}
    command = [exe, "-p", profile_name(home), "agentsfence", *action, "--json"]
    env = {k: v for k, v in os.environ.items() if k not in _ISOLATED}
    if action[:2] in (["probe", "test"], ["probe", "test-all"]):
        env["AGENTSFENCE_TEST_TOOLS"] = "1"
        # This is a fresh diagnostic context with its own native test callback,
        # independent of the chat/cron context which launched the command.
        for key in ("HERMES_SINGLE_QUERY_SESSION", "HERMES_CRON_SESSION", "HERMES_GATEWAY_SESSION",
                    "HERMES_SESSION_PLATFORM", "HERMES_SESSION_KEY", "HERMES_EXEC_ASK"):
            env.pop(key, None)
    env["HERMES_HOME"] = str(root_home())  # -p selects the profile beneath it; the sticky default is ignored
    shown = " ".join(command[1:5])
    # Output goes to files, not pipes: if Hermes outlives the timeout (for example
    # while it finishes its own pending update steps), it keeps running undisturbed.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, \
            tempfile.TemporaryDirectory(prefix="agentsfence-progress-") as directory:
        progress_path = Path(directory) / "progress.json"
        env.pop(PROGRESS_FILE, None)
        if progress is not None:
            env[PROGRESS_FILE] = str(progress_path)
        try:
            child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     start_new_session=True)
        except OSError as exc:
            return {"reachable": False, "launcher": exe, "error": f"Could not run {exe}: {exc.strerror or exc}."}
        try:
            if progress is None:
                returncode = child.wait(timeout=timeout)
            else:
                from .testkit.progress import wait

                returncode = wait(child, timeout, progress_path, progress)
        except subprocess.TimeoutExpired:
            return {"reachable": False, "launcher": exe, "still_running": child.pid,
                    "error": (f"Hermes is still starting or updating (PID {child.pid}, `hermes {shown}`); it was left "
                              f"running so its own work completes. Re-run doctor when it finishes.")}
        out.seek(0)
        err.seek(0)
        stdout_text = out.read()[-_MAX_OUTPUT:].decode("utf-8", errors="replace")
        stderr_text = err.read()[-_MAX_OUTPUT:].decode("utf-8", errors="replace")
    proc = subprocess.CompletedProcess(command, returncode, stdout_text, stderr_text)
    stdout = proc.stdout[-_MAX_OUTPUT:]
    for line in reversed(stdout.splitlines()):
        if not line.startswith(STATUS_MARKER):
            continue
        try:
            data = json.loads(line[len(STATUS_MARKER):])
        except ValueError:
            break
        if not isinstance(data, dict) or data.get("schema") != STATUS_SCHEMA:
            return {"reachable": False, "launcher": exe, "error": "Hermes answered with an unsupported AgentsFence status format."}
        answered = Path(str(data.get("hermes_home") or "")).expanduser()
        if answered.resolve() != home.resolve():
            return {"reachable": False, "launcher": exe,
                    "error": f"Hermes answered for {answered} instead of {home}; check the launcher and profile."}
        return {"reachable": True, "launcher": exe, **data}
    output = (proc.stderr or "") + "\n" + stdout
    unknown = "invalid choice" in output and "agentsfence" in output
    detail = _redact(output) or f"exit status {proc.returncode}"
    return {"reachable": False, "launcher": exe, "command_unknown": unknown,
            "error": ("Hermes did not load AgentsFence's command (the plugin may not be loading). " if unknown else
                      f"`hermes {shown}` gave no AgentsFence answer. ") + detail}


def pending_work(exe: str | None = None) -> tuple[str, str] | None:
    """``(kind, reason)`` when starting Hermes could run update work, including when that is unverified."""
    from .hermes_env import detect
    from .hermes_env import pending_work as hermes_pending_work

    root = root_home()
    return hermes_pending_work(detect(root, exe), root)


def pending_update_reason(exe: str | None = None) -> str | None:
    work = pending_work(exe)
    return work[1] if work else None


def status(home: Path) -> dict[str, Any]:
    return call(home, ["status"])


def probe(home: Path, kind: str = "compiler", scenarios: list[str] | None = None,
          *, progress: Progress | None = None) -> dict[str, Any]:
    """A probe run inside a fresh Hermes process; returns the probe result dict."""
    action = ["probe", kind] + [arg for key in scenarios or [] for arg in ("--scenario", key)]
    timeout = PROBE_TIMEOUT if kind in ("compiler", "models") else LONG_PROBE_TIMEOUT
    if kind == "compiler-eval":
        from .config import load_settings
        from .testkit.compiler_eval import load_cases

        turns = sum(len(case["messages"]) for case in load_cases())
        timeout = max(timeout, turns * (load_settings(hermes_dir=home).compiler.timeout_seconds + 1) + STATUS_TIMEOUT)
    answer = call(home, action, timeout=timeout,
                  progress=progress)
    if not answer.get("reachable"):
        return {"ok": False, "error": answer.get("error"), "launcher": answer.get("launcher")}
    result = answer.get("probe")
    if not isinstance(result, dict):
        return {"ok": False, "error": "Hermes returned no probe result.", "launcher": answer.get("launcher")}
    if answer.get("outcome") != "enforcing" and "error" not in result:
        result = {**result, "ok": False, "error": answer.get("error") or "AgentsFence is not enforcing in Hermes."}
    return {**result, "launcher": answer.get("launcher"), "python": answer.get("python")}
