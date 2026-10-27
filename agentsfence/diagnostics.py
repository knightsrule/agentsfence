"""Diagnostics used by CLI and the authenticated Hermes desktop API."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values

from . import __version__, failsafe
from .approvals import effective_approval_mode
from .config import Settings, hermes_home, load_settings, profile_environment, shared_settings_path
from .models import TaskPolicy
from .profiles import (
    compiler_route,
    desired_route,
    is_checkout,
    profile_name,
    read_config,
    read_state,
    root_home,
)
from .render import describe_policy, local_time


def configuration_digest(home: Path) -> str:
    """Digest only what a running AgentsFence reads once, at plugin load.

    Hermes re-reads the compiler route, plugin model trust entries and approval
    mode on every call, so editing those (or unrelated Hermes settings) never
    requires a restart.
    """
    env = profile_environment(home)
    extra = Path(env["AGENTSFENCE_CONFIG"]).expanduser() if env.get("AGENTSFENCE_CONFIG") else load_settings(hermes_dir=home).home / "config.yaml"
    try:
        entry = dict(((read_config(home).get("plugins") or {}).get("entries") or {}).get("agentsfence") or {})
    except ValueError:
        entry = {"unreadable": True}
    entry.pop("llm", None)
    dotenv = {k: v for k, v in dotenv_values(home / ".env", interpolate=False).items() if k.startswith("AGENTSFENCE_")}

    def startup_settings(path: Path) -> Any:
        text = path.read_text(errors="replace") if path.is_file() else ""
        try:
            settings: Any = yaml.safe_load(text)
        except yaml.YAMLError:
            return text
        if isinstance(settings, dict) and isinstance(settings.get("compiler"), dict):
            # Read afresh before each compile (route sync), so changing them needs no restart.
            compiler = {k: v for k, v in settings["compiler"].items() if k not in {"mode", "selected_model", "selected_provider"}}
            settings = {**settings, "compiler": compiler} if compiler else {k: v for k, v in settings.items() if k != "compiler"}
        return settings or {}

    state = {"entry": entry, "env": dotenv, "settings": startup_settings(extra),
             "shared": startup_settings(shared_settings_path(home))}
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()


def _psutil() -> Any:
    """psutil when importable (a Hermes dependency), else None."""
    try:
        import psutil
    except ImportError:
        return None
    return psutil


def _read_process_identity(pid: int) -> str | None:
    """A process's start time, so a reused PID never matches its registration."""
    psutil = _psutil()  # `ps` is absent on Windows and in slim images
    if psutil is not None:
        try:
            # Windows can retain creation metadata for an exited process while
            # another process still holds its handle. Metadata alone is not liveness.
            if not psutil.pid_exists(pid):
                return None
            return f"{psutil.Process(pid).create_time():.2f}"
        except (psutil.Error, OSError):
            return None
    if sys.platform == "win32":
        return None
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True, timeout=2)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


@lru_cache(maxsize=2)
def _current_process_identity(pid: int) -> str | None:
    return _read_process_identity(pid)


def process_identity(pid: int) -> str | None:
    # Our own PID cannot be reused while this interpreter is alive. Other
    # processes still receive a fresh identity check in explicit CLI diagnostics.
    return _current_process_identity(pid) if pid == os.getpid() else _read_process_identity(pid)


def _pid_alive(pid: int) -> bool | None:
    """Whether a PID exists; None when that cannot be determined without side effects."""
    psutil = _psutil()
    if psutil is not None:
        try:
            return bool(psutil.pid_exists(pid))
        except (psutil.Error, OSError):
            return None
    if sys.platform == "win32":
        return None  # os.kill(pid, 0) terminates the process on Windows.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return None  # Permission errors or unavailable process checks do not prove death.
    return True


def _discard_dead_runtime(path: Path, pid: int, original: os.stat_result) -> None:
    """Prune only a confirmed dead process's unchanged registration."""
    if pid <= 0:
        return  # Never probe a process group from a malformed registration.
    if _pid_alive(pid) is not False:
        return  # Alive, or death is unproven.
    try:
        current = path.stat()
    except OSError:
        return
    if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns, current.st_size) == (
        original.st_dev, original.st_ino, original.st_mtime_ns, original.st_ctime_ns, original.st_size
    ):
        path.unlink(missing_ok=True)


def register_runtime(settings: Settings) -> None:
    home = hermes_home()
    directory = settings.home / "runtime"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    surface = "desktop" if "serve" in sys.argv else "gateway" if "gateway" in sys.argv else "cli"
    data = {"pid": os.getpid(), "process_start": process_identity(os.getpid()), "version": __version__,
            "surface": surface, "registered_at": time.time(), "configuration": configuration_digest(home)}
    path = directory / f"{os.getpid()}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream)


def runtime_status(home: Path, settings: Settings, *, current_only: bool = False) -> list[dict[str, Any]]:
    """List valid registrations and remove unchanged records for confirmed dead PIDs."""
    result = []
    digest = configuration_digest(home)
    for path in (settings.home / "runtime").glob("*.json"):
        try:
            with path.open() as stream:
                original = os.fstat(stream.fileno())
                row = json.load(stream)
            pid = int(row["pid"])
            if current_only and pid != os.getpid():
                continue
            identity = process_identity(pid)
            if not identity:
                _discard_dead_runtime(path, pid, original)
                continue
            if not row.get("process_start") or identity != row["process_start"]:
                continue
            row["current"] = row["configuration"] == digest and row["version"] == __version__
            result.append(row)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return result


def unregistered_gateway(home: Path, processes: list[dict[str, Any]]) -> int | None:
    """PID of a live gateway for this profile that never loaded AgentsFence."""
    try:
        from gateway.status import get_running_pid

        pid = get_running_pid(home / "gateway.pid", cleanup_stale=False)
    except Exception:
        return None
    return pid if pid and not any(p["pid"] == pid for p in processes) else None


# Hermes subcommands that never run the agent loop, so never load plugins.
_NON_AGENT_COMMANDS = frozenset({"auth", "backup", "completion", "config", "doctor", "import", "login", "logout",
                                 "model", "plugins", "profile", "setup", "status", "uninstall", "update", "version"})
_BACKEND_COMMANDS = frozenset({"dashboard", "desktop", "gui", "serve"})
_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def hermes_invocation(argv: list[str]) -> tuple[str, str | None] | None:
    """(subcommand, explicit profile) of a Hermes command line; None for anything else."""
    if not argv:
        return None
    program = Path(argv[0]).name
    if program in {"hermes", "hermes.exe"}:
        rest = argv[1:]
    elif program.lower().startswith("python") and len(argv) > 1 and Path(argv[1]).name == "hermes":
        rest = argv[2:]
    elif program.lower().startswith("python") and argv[1:3] == ["-m", "hermes_cli.main"]:
        rest = argv[3:]
    elif program.lower().startswith("python") and argv[1:3] == ["-I", "-c"] and len(argv) > 3:
        # Hermes' managed launchers execute bootstrap code instead of a named
        # script. Inspect syntax only; strings mentioning Hermes are not imports.
        try:
            body = ast.parse(argv[3]).body
        except (SyntaxError, ValueError):
            return None
        bootstrap = any(isinstance(node, ast.Import) and any(alias.name == "hermes_bootstrap" for alias in node.names)
                        for node in body)
        entry = any(isinstance(node, ast.ImportFrom) and node.module == "hermes_cli.main"
                    and any(alias.name == "main" for alias in node.names) for node in body)
        module_entry = any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                           and isinstance(node.value.func, ast.Attribute)
                           and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "runpy"
                           and node.value.func.attr == "run_module" and node.value.args
                           and isinstance(node.value.args[0], ast.Constant)
                           and node.value.args[0].value == "hermes_cli.main" for node in body)
        if not bootstrap or not (entry or module_entry):
            return None
        rest = argv[4:]
        if rest[:1] == ["--run-module"]:
            if rest[1:2] != ["hermes_cli.main"]:
                return None
            rest = rest[2:]
        if rest[:1] == ["--print-runtime-command"]:
            return None
    else:
        return None
    command: str | None = None
    profile: str | None = None
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg in {"-p", "--profile"} and index + 1 < len(rest):
            profile = profile or rest[index + 1]
            index += 2
            continue
        if arg.startswith("--profile="):
            profile = profile or arg.partition("=")[2]
        elif command is None and not arg.startswith("-"):
            command = arg
        index += 1
    return command or "chat", profile if profile and _PROFILE_NAME.match(profile) else None


def hermes_process_home(profile: str | None, environ: dict[str, str]) -> Path:
    """The profile a Hermes process runs, resolved the way Hermes' launcher does."""
    env_home = environ.get("HERMES_HOME", "")
    home = Path(env_home).expanduser() if env_home else Path.home() / ".hermes"
    root = home.parent.parent if home.parent.name == "profiles" else home
    if profile:
        return root if profile == "default" else root / "profiles" / profile
    if env_home and home.parent.name == "profiles":
        return home
    try:  # the sticky default; it may have changed since the process started
        active = (root / "active_profile").read_text().strip()
    except (OSError, UnicodeDecodeError):
        active = ""
    return root / "profiles" / active if active and active != "default" else root


def unregistered_hermes(home: Path, processes: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """Live Hermes processes for this profile that never loaded AgentsFence.

    Hermes keeps no registry of running chats, so this lists the user's own
    processes. Returns None when processes cannot be listed; a missing
    registration alone never proves that nothing needs a restart.
    """
    try:
        import psutil
    except ImportError:
        return None
    registered = {p["pid"] for p in processes}
    target = home.resolve()
    found: list[dict[str, Any]] = []
    try:
        user = psutil.Process().username()
        for proc in psutil.process_iter(["pid", "cmdline", "username"]):
            info = proc.info
            if info["pid"] == os.getpid() or info["pid"] in registered or info.get("username") != user:
                continue
            invocation = hermes_invocation(info.get("cmdline") or [])
            if invocation is None or invocation[0] in _NON_AGENT_COMMANDS:
                continue
            try:
                environ = proc.environ()
            except (psutil.Error, OSError):
                environ = None  # unreadable: assume it may run this profile
            if environ is not None and hermes_process_home(invocation[1], environ).resolve() != target:
                continue
            surface = "gateway" if invocation[0] == "gateway" else "desktop" if invocation[0] in _BACKEND_COMMANDS else "cli"
            found.append({"pid": info["pid"], "surface": surface})
    except (psutil.Error, OSError):  # sandboxes raise a plain PermissionError from sysctl
        return None
    return found


_SURFACES = {"gateway": ("Hermes gateway", "run `hermes gateway restart`"),
             "cli": ("Hermes chat", "exit and reopen it"),
             "desktop": ("Hermes backend", "restart this profile's backend")}


def _restart_guidance(stale: list[dict[str, Any]], unregistered: list[dict[str, Any]]) -> str:
    if not stale and not unregistered:
        return "Restart the profile backend and send a message to verify activation."
    lines = []
    for p, why in [(p, "started before AgentsFence was enabled") for p in unregistered] + [
            (p, "uses " + ("an older AgentsFence version" if p.get("version") != __version__ else "older AgentsFence settings"))
            for p in stale]:
        name, action = _SURFACES.get(p.get("surface", ""), _SURFACES["desktop"])
        lines.append(f"{name} (PID {p['pid']}) {why}: {action}.")
    return " ".join(lines)


_COMPILATION_STATE_LOCK = threading.Lock()


def record_compilation_state(settings: Settings, session: str, active: bool) -> None:
    """Update this process's existing registration; never create a false registration."""
    path = settings.home / "runtime" / f"{os.getpid()}.json"
    # Owner hooks and background workers update one process record. Serialize
    # read/modify/replace so they neither lose sessions nor share a moved temp.
    with _COMPILATION_STATE_LOCK:
        if not path.is_file():
            return
        data = json.loads(path.read_text())
        sessions = set(data.get("compiling_sessions") or [])
        if active:
            sessions.add(session)
        else:
            sessions.discard(session)
        data["compiling_sessions"] = sorted(sessions)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data))
        temporary.chmod(0o600)
        temporary.replace(path)


@dataclass
class _AuditCursor:
    identity: tuple[int, int] | None = None
    signature: tuple[int, int] | None = None
    offset: int = 0
    anchor: bytes = b""
    rows: deque[dict[str, Any]] = field(default_factory=deque)
    latest: dict[str, Any] | None = None
    latest_eval: dict[str, Any] | None = None


_AUDIT_CURSORS: OrderedDict[tuple[Path, str | None, int], _AuditCursor] = OrderedDict()
_AUDIT_LOCK = threading.Lock()


def _audit_view(path: Path, session: str | None, limit: int) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """One initial scan per query, then only appended complete rows. Bounded LRU."""
    if limit <= 0:
        return [], None
    key = (path.resolve(), session, limit)
    with _AUDIT_LOCK:
        if not path.is_file():
            _AUDIT_CURSORS.pop(key, None)
            return [], None
        cursor = _AUDIT_CURSORS.setdefault(key, _AuditCursor(rows=deque(maxlen=limit)))
        _AUDIT_CURSORS.move_to_end(key)
        while len(_AUDIT_CURSORS) > 32:
            _AUDIT_CURSORS.popitem(last=False)
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            identity, signature = (stat.st_dev, stat.st_ino), (stat.st_size, stat.st_mtime_ns)
            if cursor.identity == identity and cursor.signature == signature:
                return list(cursor.rows), cursor.latest
            stream.seek(max(0, cursor.offset - len(cursor.anchor)))
            unchanged_prefix = stream.read(len(cursor.anchor)) == cursor.anchor
            if cursor.identity != identity or stat.st_size < cursor.offset or not unchanged_prefix or (
                cursor.signature is not None and stat.st_size == cursor.signature[0]
            ):
                cursor.offset = 0
                cursor.rows.clear()
                cursor.latest = None
                cursor.latest_eval = None
            stream.seek(cursor.offset)
            for line in stream:
                if not line.endswith(b"\n"):
                    break  # An append in progress will be read on the next poll.
                cursor.offset += len(line)
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict) or (session is not None and row.get("session_id") != session):
                    continue
                cursor.rows.append(row)
                if row.get("event") in {"policy_compiled", "policy_amended", "compiler_probe"}:
                    cursor.latest = row
                if row.get("event") == "compiler_eval":
                    cursor.latest_eval = row
                    if (row.get("details") or {}).get("mode") == "live":
                        cursor.latest = row
            stream.seek(max(0, cursor.offset - 64))
            cursor.anchor = stream.read(min(cursor.offset, 64))
            cursor.identity, cursor.signature = identity, signature
        return list(cursor.rows), cursor.latest


def compiler_eval_evidence(path: Path) -> dict[str, Any] | None:
    """Keep the last corpus result even after newer decisions leave the visible tail."""
    _audit_view(path, None, 50)
    with _AUDIT_LOCK:
        cursor = _AUDIT_CURSORS.get((path.resolve(), None, 50))
        return cursor.latest_eval if cursor else None


def audit_rows(home: Path, *, session: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    rows, _ = _audit_view(load_settings(hermes_dir=home).home / "audit.jsonl", session, limit)
    return rows


def policy_for(settings: Settings, session: str | None) -> TaskPolicy | None:
    if not session:
        return None
    # Compare the embedded session id; never interpolate an untrusted id into a path.
    for path in (settings.home / "policies").glob("*.json"):
        try:
            record = json.loads(path.read_text())
            if record.get("session_id") == session and "policy" in record:
                return TaskPolicy.model_validate(record["policy"])
        except (OSError, ValueError, TypeError):
            continue
    return None


def evidence_digest(home: Path, settings: Settings) -> str:
    """What decides which compiler runs: AgentsFence compiler settings, the Hermes route and its grant.

    Separate from configuration_digest(): that one is the restart digest and
    deliberately excludes the route and grant, which Hermes re-reads per call.
    """
    cfg = read_config(home)
    route = (cfg.get("auxiliary") or {}).get("agentsfence_policy") or {}
    grant = ((((cfg.get("plugins") or {}).get("entries") or {}).get("agentsfence") or {}).get("llm")) or {}
    # Every setting that can change a compile's outcome (model, endpoint, timeout, request
    # size, follow-up mode, concurrency); only display-only and runtime-assigned fields are left out.
    compiler = settings.compiler.model_dump(mode="json", exclude={"hermes_task"})
    state = {"compiler": compiler, "route": route, "grant": grant}
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()[:16]


def installed_loader_version(home: Path) -> int | str | None:
    """The protect-written loader's version; "checkout" for a git or directory install."""
    target = home / "plugins" / "agentsfence"
    if is_checkout(home):
        return "checkout"
    try:
        text = (target / "__init__.py").read_text(errors="replace")
    except OSError:
        return None
    match = re.search(r"^LOADER_VERSION = (\d+)$", text, re.M)
    return int(match.group(1)) if match else 0


def last_recorded_load(settings: Settings, home: Path) -> dict[str, Any] | None:
    """Historical evidence only: the newest load record for this profile, any interpreter."""
    rows = []
    for path in (settings.home / "load_status").glob(f"{profile_name(home)}-*.json"):
        try:
            rows.append(json.loads(path.read_text()))
        except (OSError, ValueError):
            continue
    rows = [r for r in rows if isinstance(r, dict)]
    return max(rows, key=lambda r: float(r.get("time") or 0)) if rows else None


def _check(status: str, message: str) -> dict[str, str]:
    return {"status": status, "message": message}


def agentsfence_command(arguments: str) -> str:
    """``uvx --from 'agentsfence==<this version>' agentsfence <arguments>``: never a stale copy on PATH."""
    return f"uvx --from 'agentsfence=={__version__}' agentsfence {arguments}"


def install_command() -> str:
    """The repair command: reinstall this version through `hermes pm install` for every protected profile.

    Pinned to this version, never whichever `agentsfence` is on PATH: a stale copy
    would write loaders for the wrong version.
    """
    return f"`{agentsfence_command('install')}`"


def onboarding_steps(profile: str) -> list[tuple[str, str]]:
    """The first-run sequence for one profile, in order: ``(command, what it proves)``.

    Setup, CLI hints and the docs all use this sequence (tests keep README in step).
    """
    return [
        (agentsfence_command("install"), "checks that Hermes can run AgentsFence and registers it"),
        (agentsfence_command(f"protect --profile {profile}"),
         "enables AgentsFence in the profile and builds Hermes' environment with it"),
        (agentsfence_command(f"doctor --profile {profile} --probe-compiler"),
         "checks that new Hermes processes enforce, and makes one real (possibly billable) compiler call"),
        (agentsfence_command(f"test --profile {profile}"),
         "runs the six scenarios in the profile: injected actions stopped, requested actions allowed"),
    ]


def load_check(home: Path, enabled: bool, safe_mode: bool, host: dict[str, Any] | None) -> dict[str, str]:
    """Can a new Hermes process for this profile load enforcement? Only current evidence decides."""
    if not enabled:
        if profile_name(home) in read_state()["protected"]:
            return _check("problem", "Protection off: you protected this profile, but AgentsFence is not enabled in it (for "
                                     f"example after `hermes update` disabled it). Run {install_command()}: it re-enables "
                                     "AgentsFence in every profile you protected.")
        return _check("problem", "Protection off: AgentsFence is not enabled in this profile. Protect it with "
                                 f"`{agentsfence_command('protect --profile ' + profile_name(home))}`.")
    if safe_mode:
        return _check("problem", "Protection off: HERMES_SAFE_MODE is on, so Hermes skips all plugins, including AgentsFence.")
    loader = installed_loader_version(home)
    if loader != "checkout" and (not isinstance(loader, int) or loader < failsafe.LOADER_VERSION):
        return _check("problem", "This profile's AgentsFence loader is older than this version. "
                                 f"Run {install_command()}.")
    if host is None:
        return _check("unverified", "Not checked. `agentsfence doctor` asks Hermes what a new process loads.")
    if not host.get("reachable"):
        return _check("unverified", f"Could not confirm with Hermes: {host.get('error') or 'no answer'}")
    python = host.get("python") or "Hermes' Python"
    if host.get("outcome") == "recovery_block":
        return _check("problem", f"Tools blocked: AgentsFence could not start in Hermes ({python}): {host.get('error')}. "
                                 f"Repair: {install_command()} reinstalls AgentsFence {__version__} through `hermes pm install`.")
    if host.get("outcome") == "enforcing":
        if host.get("compatibility_error"):
            return _check("problem", f"Tools blocked: {host['compatibility_error']}")
        version = host.get("agentsfence_version")
        if version != __version__:
            return _check("problem", f"Hermes loads AgentsFence {version} ({python}), but this command is {__version__}. "
                                     f"Install one version: {install_command()}.")
        return _check("ok", f"New Hermes processes load AgentsFence {version} ({python}).")
    return _check("unverified", "Hermes did not report whether AgentsFence is enforcing.")


def compiler_check(settings: Settings, latest: dict[str, Any] | None, digest: str | None,
                   routing: str | None = None, profile: str = "default") -> dict[str, str]:
    """healthy / slow / failed / not_verified, from compile evidence that matches the current configuration.

    Reported next to enforcement, never folded into it: a failed compile falls back
    to read-only, which is still protected.
    """
    hint = f"Run `{onboarding_steps(profile)[2][0]}` to test the policy model."
    if latest is None:
        return _check("not_verified", "No compile recorded yet. " + hint)
    details = latest.get("details") or {}
    provenance = details.get("provenance")
    when = local_time(latest.get("timestamp"))
    if not isinstance(provenance, dict):
        return _check("not_verified", f"The last compile ({when}) was recorded without provenance by an earlier "
                                      "AgentsFence, so it may not reflect the current configuration. " + hint)
    if provenance.get("agentsfence_version") != __version__:
        return _check("not_verified", f"Evidence does not match current configuration (recorded under AgentsFence "
                                      f"{provenance.get('agentsfence_version')}). " + hint)
    if digest is None or provenance.get("evidence_digest") != digest:
        return _check("not_verified", "Evidence does not match current configuration (recorded with a different compiler "
                                      "route or settings). " + hint)
    recorded = provenance.get("routing")
    if not recorded:
        return _check("not_verified", "The last compile was recorded without Hermes' routing mode. " + hint)
    if routing is None:
        return _check("not_verified", f"Could not confirm how Hermes routes the compiler now (recorded: {recorded}). " + hint)
    if recorded != routing:
        return _check("not_verified", f"Evidence does not match current configuration (recorded with {recorded} routing; "
                                      f"Hermes now uses {routing}). " + hint)
    model = provenance.get("compiler_model") or "the policy model"
    if details.get("fell_back"):
        return _check("failed", f"The last compile ({when}, {model}) fell back: {details.get('error') or 'compilation failed'}")
    from .plugin import budget_warning

    duration = (details.get("latency_seconds") or {}).get("p95") if latest.get("event") == "compiler_eval" else provenance.get("seconds")
    warning = budget_warning(duration, provenance, model)
    if warning:
        return _check("slow", f"The last compile ({when}) succeeded with {model}. {warning}")
    return _check("healthy", f"The last compile ({when}) succeeded with {model}.")


def overall_status(checks: dict[str, dict[str, str]]) -> str:
    """Enforcement only: ok when a new process loads it and running processes run it.

    The compiler is reported separately. A slow or failed compile falls back to
    read-only, so it never makes a profile unprotected, and one slow probe never
    flips the verdict.
    """
    core = [checks["load"]["status"], checks["processes"]["status"]]
    if "problem" in core:
        return "problem"
    return "ok" if all(status == "ok" for status in core) else "unverified"


def snapshot(home: Path | None = None, *, session: str | None = None, runtime_verified: bool | None = None,
             host: dict[str, Any] | None = None) -> dict[str, Any]:
    home = home or hermes_home()
    settings = load_settings(hermes_dir=home)
    cfg = read_config(home)
    plugins = cfg.get("plugins") or {}
    enabled = "agentsfence" in (plugins.get("enabled") or []) and "agentsfence" not in (plugins.get("disabled") or [])
    env = profile_environment(home)
    safe_mode = env.get("HERMES_SAFE_MODE", "").lower() in {"1", "true", "yes", "on"}
    processes = runtime_status(home, settings, current_only=runtime_verified is not None)
    stale = [p for p in processes if not p["current"]]
    unregistered: list[dict[str, Any]] = []
    process_check = True
    state = "inactive"
    if enabled and not safe_mode:
        if runtime_verified is not None:  # asked by the running Hermes process itself
            running = runtime_verified and any(p["current"] and p["pid"] == os.getpid() for p in processes)
            state = "ready" if running else "restart_required"
            stale = []
        else:
            # A new Hermes process loads the plugin itself. A live process that
            # never loaded it, or runs older code or startup settings, must restart.
            found = unregistered_hermes(home, processes)
            process_check = found is not None
            unregistered = found or []
            gateway = unregistered_gateway(home, processes)
            if gateway and all(p["pid"] != gateway for p in unregistered):
                unregistered.append({"pid": gateway, "surface": "gateway"})
            state = "restart_required" if stale or unregistered else "ready" if processes else "enabled"
    policy = policy_for(settings, session)
    audit_error = None
    try:
        rows, latest = _audit_view(settings.home / "audit.jsonl", session, 50)
        latest_eval = compiler_eval_evidence(settings.home / "audit.jsonl")
    except OSError as exc:  # e.g. created by Hermes running as another user
        rows, latest = [], None
        latest_eval = None
        audit_error = (f"Cannot read the audit log {settings.home / 'audit.jsonl'} ({exc.strerror or exc}). "
                       "Status omits policy evidence until its owner and permissions match this user.")
    try:
        digest: str | None = evidence_digest(home, settings)
    except (ValueError, OSError):
        digest = None
    routing = str(host["routing"]) if host and host.get("reachable") and host.get("routing") else None
    compiler_state = compiler_check(settings, latest, digest, routing, profile_name(home))
    if state == "ready" and any(p["current"] and (session in (p.get("compiling_sessions") or []) if session else p.get("compiling_sessions")) for p in processes):
        state = "compiling"
    elif state == "ready" and policy:
        state = "expired" if policy.is_expired() else "fallback" if policy.compiler_status == "fallback" or policy.source == "fallback" else "active"
    elif state == "ready" and compiler_state["status"] == "failed":
        # Only evidence recorded under the current version and compiler settings counts;
        # an older or provenance-less fallback is history, not the current state.
        state = "fallback"
    if runtime_verified is not None:
        processes_state = _check("ok", "This Hermes backend runs current enforcement.") if state not in {"inactive", "restart_required"} \
            else _check("problem", "This Hermes backend is not running current enforcement. Restart it.")
    elif not enabled or safe_mode:
        processes_state = _check("problem", "Protection is off for this profile.")
    elif not process_check:
        processes_state = _check("unverified", "Could not list running Hermes processes, so processes started earlier "
                                               "may still run without current enforcement.")
    elif stale or unregistered:
        processes_state = _check("problem", _restart_guidance(stale, unregistered))
    else:
        live = len(processes)
        processes_state = _check("ok", f"{live} running Hermes process{'es' if live != 1 else ''} use current enforcement." if live
                                       else "No Hermes process is running for this profile.")
    checks = {"load": load_check(home, enabled, safe_mode, host), "processes": processes_state,
              "compiler": compiler_state}
    if host and host.get("reachable") and (host.get("compatibility_error") or host.get("outcome") == "recovery_block"):
        state = "blocked"
    approval_mode = effective_approval_mode(home, cfg, session)
    route = compiler_route(cfg)
    want, note = desired_route(cfg, settings)
    compiler = {"provider": settings.compiler.provider, "mode": settings.compiler.mode,
                "verified": checks["compiler"]["status"] in {"healthy", "slow"},
                "budget_seconds": settings.compiler.timeout_seconds,
                "model": str(route.get("model") or "") or "unavailable",
                "routing": ("this profile's default model" if settings.compiler.mode != "selected"
                            else "dedicated compiler model") if route.get("model") else "unavailable; read-only fallback"}
    if note and settings.compiler.mode != "selected":
        compiler["note"] = note
    if enabled and {k: str(v) for k, v in route.items()} != want:
        compiler["note"] = ("The compiler route is out of date; the next AgentsFence command or compile updates it "
                            f"to {want.get('model') or 'an unavailable profile default'}.")
    from .hermes_env import detect
    from .lifecycle import unprotected_profiles
    from .testkit.jobs import scheduled_jobs

    unprotected = unprotected_profiles()
    return {"version": __version__, "profile": profile_name(home), "home": str(home), "state": state,
            "unprotected_profiles": unprotected, "include_new": read_state()["include_new"],
            "hermes_environment": detect(root_home()).describe(),
            "scheduled_jobs": [{k: job[k] for k in ("id", "name", "schedule", "enabled")} for job in scheduled_jobs(home)],
            "cron_mode": str((cfg.get("approvals") or {}).get("cron_mode") or "deny"),
            "pending_update": host.get("pending_update") if host else None,
            "pending_kind": host.get("pending_kind") if host else None,
            "enabled": enabled, "safe_mode": safe_mode, "runtime": processes, "compiler": compiler,
            "approval_mode": approval_mode, "human_approval": approval_mode in {"manual", "ask"},
            "strict_approval": settings.evaluation.strict_yolo, "last_compilation": latest,
            "last_compiler_eval": latest_eval,
            "session_id": session, "policy": policy.model_dump(mode="json") if policy else None,
            "policy_text": describe_policy(policy) if policy else None, "audit": rows,
            "process_check": process_check, "audit_error": audit_error,
            "checks": checks, "overall": overall_status(checks), "last_recorded_load": last_recorded_load(settings, home),
            "guidance": checks["load"]["message"] if state == "blocked" else
                        _restart_guidance(stale, unregistered) if state == "restart_required" else
                        ("No Hermes process is running for this profile, so no restart is needed. AgentsFence loads when Hermes starts; your first message in a new chat creates task permissions."
                         if process_check else
                         "AgentsFence loads when Hermes starts for this profile. Running Hermes processes could not be checked here: restart any Hermes chat, gateway or backend that was already running before setup.") if state == "enabled" else
                        "Task policy compilation is in progress. Tool calls are blocked until it finishes." if state == "compiling" else
                        "Enable AgentsFence for this profile." if state == "inactive" else
                        "Compiler unavailable. Review the fallback details before continuing." if state == "fallback" else
                        "The hook is loaded. Send a message to create a task policy." if state == "ready" else ""}


def unreadable_snapshot(home: Path, exc: Exception) -> dict[str, Any]:
    """Status for a profile whose configuration cannot be read, with every field UIs show."""
    message = str(exc) if isinstance(exc, (ValueError, OSError)) else f"{type(exc).__name__}: {exc}"
    return {"version": __version__, "profile": profile_name(home), "home": str(home), "state": "unknown",
            "enabled": False, "error": message, "guidance": f"AgentsFence cannot read this profile: {message}",
            "compiler": {"provider": "", "model": "Unavailable", "routing": "configuration error", "verified": False},
            "approval_mode": "unknown", "human_approval": False, "process_check": False, "audit": [],
            "policy": None, "policy_text": None, "last_compilation": None, "audit_error": None}


def setup_message(state: str, guidance: str) -> str:
    if state == "restart_required":
        return "Saved. " + guidance
    if state == "inactive":
        return "Saved. HERMES_SAFE_MODE is on, so Hermes skips plugins for this profile."
    if state == "enabled":
        return "Saved. " + guidance
    return "Saved. Running Hermes processes use these settings from their next message; no restart is needed."


_OVERALL = {"ok": "PROTECTED", "problem": "NOT PROTECTED", "unverified": "UNVERIFIED"}


def format_status(data: dict[str, Any]) -> str:
    compiler = data["compiler"]
    lines = [f"AgentsFence {data['version']} — profile {data['profile']}", f"Home: {data['home']}"]
    if data.get("hermes_environment"):
        lines.append(f"Hermes environment: {data['hermes_environment']}")
    if data.get("pending_update"):
        label = "Hermes update state unverified" if data.get("pending_kind") == "unverified" else "Hermes update pending"
        lines.append(f"{label}: {data['pending_update']}")
    checks = data.get("checks")
    if checks:
        lines.append(f"Enforcement: {_OVERALL.get(data.get('overall', ''), 'UNVERIFIED')}")
        for key, label in (("load", "New Hermes processes"), ("processes", "Running processes")):
            check = checks[key]
            lines.append(f"  {label}: {check['status'].replace('_', ' ').upper()} — {check['message']}")
        compiler_state = checks["compiler"]
        lines.append(f"Compiler health: {compiler_state['status'].replace('_', ' ').upper()} — {compiler_state['message']}")
        capability = checks.get("capabilities")
        if capability:
            lines.append(f"Hermes capabilities: {capability['status'].upper()} — {capability['message']}")
    lines.append(f"Compiler: {compiler['model']} ({compiler['routing']}), budget {compiler.get('budget_seconds', 30):g}s")
    evaluation = data.get("last_compiler_eval")
    if evaluation:
        result = evaluation.get("details") or {}
        totals, latency = result.get("totals") or {}, result.get("latency_seconds") or {}
        lines.append(f"Last compiler evaluation ({result.get('mode', 'unknown')}): "
                     f"{totals.get('overgrant', '?')} over-grants, {totals.get('undergrant', '?')} under-grants; "
                     f"p50 {latency.get('p50', '?')}s, p95 {latency.get('p95', '?')}s; "
                     f"{result.get('calls_per_compile', '?')} model calls/compile.")
        waits = result.get("first_call_wait_seconds") or {}
        if waits.get("waited_fraction") is not None:
            lines.append(f"First tool calls that waited: {waits.get('waited_count', '?')}/"
                         f"{waits.get('total_first_calls', '?')} ({waits['waited_fraction']:.1%}).")
    if compiler.get("note"):
        lines.append(compiler["note"])
    lines += [f"Approvals: {data['approval_mode']} — " + ("human prompts" if data["human_approval"] else "ASK_USER may resolve without a human")]
    if data.get("audit_error"):
        lines.append(data["audit_error"])
    record = data.get("last_recorded_load")
    if record:
        when = local_time(float(record.get("time") or 0))
        lines.append(f"Last recorded load (history, not current state): {record.get('outcome')} at {when} in {record.get('python')}"
                     + (f" — {record.get('error')}" if record.get("error") else ""))
    jobs = data.get("scheduled_jobs") or []
    if jobs and data.get("enabled"):
        active = [j["name"] for j in jobs if j.get("enabled")]
        lines.append(f"Scheduled jobs: {len(jobs)} ({len(active)} enabled) run fenced and unattended: each run's prompt "
                     f"becomes its task policy and nobody can approve (approvals.cron_mode: {data.get('cron_mode')}). "
                     "See what each prompt authorizes: `agentsfence doctor --jobs`.")
    if data.get("unprotected_profiles"):
        names = ", ".join(data["unprotected_profiles"])
        lines.append(f"Unprotected profiles: {names}. Protect them with `agentsfence protect --profiles {names.replace(', ', ' ')}`"
                     + (" (protect-new-profiles is on: the next AgentsFence command protects them)." if data.get("include_new") else "."))
    if data.get("policy_text"):
        lines += ["", data["policy_text"]]
    return "\n".join(lines)


_COMPILER_ERRORS = (
    (r"unprocessed owner messages exceed",
     "Too many of your messages are waiting for a permission update to fit in one compile. Earlier consequential permissions stay suspended; start a new task to restore them."),
    (r"capacity exhausted",
     "The policy compiler reached its concurrent request limit before this request could run. Wait for pending requests to finish, or restart the profile if they are stuck, then retry validation."),
    # Checked before the others: "unexpected keyword argument 'timeout'" is not a timeout.
    (r"unexpected keyword argument|positional arguments? but",
     "This Hermes version's plugin model API is not compatible with AgentsFence. Update Hermes (`hermes update`) and AgentsFence, then retry validation."),
    (r"cannot override the (?:provider|model)|allowed_(?:provider|model)s|cannot route through auxiliary task",
     "Hermes did not let AgentsFence use the selected compiler model. Choose another with `agentsfence settings --model MODEL`, or use `agentsfence settings --compiler inherit`."),
    (r"timed? ?out\b|timeout",
     "The policy compiler timed out: it did not answer within its time budget. Use a faster compiler model, or raise the budget with "
     "`agentsfence settings --compile-budget SECONDS`, which raises both AgentsFence's `compiler.timeout_seconds` and "
     "Hermes' `plugins.hook_callback_timeout` (raising one alone changes nothing)."),
    (r"\b40[13]\b|unauthori[sz]ed|authenticat|api[ _-]?key|credential|forbidden",
     "Compiler authentication failed. Check this profile's Hermes credentials."),
    (r"invalid response|\b50[234]\b|service.*overloaded|service unavailable",
     "Hermes received an unavailable or invalid response from the compiler provider. Retry later or use another configured model."),
    (r"json|validation|schema|invalid policy",
     "The compiler returned an invalid policy. Try another configured model."),
)


def public_compiler_error(error: str | None) -> str:
    text = (error or "").lower()
    for pattern, message in _COMPILER_ERRORS:
        if re.search(pattern, text):
            return message
    return "Policy compilation failed. Check Hermes connectivity and model configuration, then retry validation."
