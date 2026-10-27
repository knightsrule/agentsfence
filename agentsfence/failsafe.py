"""Fail-closed plugin loading that works even when AgentsFence itself cannot import.

`agentsfence protect` copies this file into each profile's
``plugins/agentsfence/__init__.py`` (see ``profiles.install_surfaces``), and a git
checkout's root ``__init__.py`` loads it by path. Keep it standard-library only
and free of package-relative imports: it runs precisely when the ``agentsfence``
package is missing or broken in Hermes' environment.

The guarantee is scoped: tools are blocked when Hermes discovers and runs this
loader and honors its veto. A host that skips or disables the plugin never runs
it; ``agentsfence doctor`` detects that case instead.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

LOADER_VERSION = 2
# protect rewrites this line in each profile's copy; a checkout keeps None.
EXPECTED_VERSION: str | None = None
ACCEPTED_VERSIONS: tuple[str, ...] = ()
STATUS_MARKER = "AGENTSFENCE_HOST="
STATUS_SCHEMA = 1
_SECRET = re.compile(r"(?i)(sk-[\w-]{6,}|(?:api[_-]?key|token|secret|password)\s*[=:]\s*\S+|bearer\s+\S+)")


def describe(exc: BaseException) -> str:
    """One redacted, bounded line for status output and block messages."""
    text = _SECRET.sub("[redacted]", f"{type(exc).__name__}: {exc}".splitlines()[0] if str(exc) else type(exc).__name__)
    return text[:300]


def guarded_register(ctx: Any, load: Callable[[], Any]) -> None:
    """Import and run AgentsFence's ``register(ctx)``; on any failure, block every tool call.

    ``load`` returns the ``agentsfence.plugin`` module. Both the import and the
    registration are guarded, so a failure after some hooks were registered still
    ends with a blocking hook in front.
    """
    module = None
    try:
        module = load()
        if EXPECTED_VERSION:
            package = sys.modules.get(getattr(module, "__package__", ""))
            loaded_version = getattr(package, "__version__", None)
            if loaded_version not in (ACCEPTED_VERSIONS or (EXPECTED_VERSION,)):
                raise RuntimeError(f"Loaded AgentsFence {loaded_version}, expected {EXPECTED_VERSION}; repair required")
        home = hermes_home()
        root = home.parent.parent if home.parent.name == "profiles" else home
        journal = root / "agentsfence" / "transaction.json"
        if journal.exists():
            try:
                transaction = json.loads(journal.read_text())
            except (ValueError, OSError) as exc:
                raise RuntimeError("AgentsFence recovery journal is unreadable; run `agentsfence install`") from exc
            if transaction.get("recovery_errors"):
                raise RuntimeError("AgentsFence rollback is incomplete; run `agentsfence install`")
        module.register(ctx)
        outcome = dict(module.registration_outcome())
    except Exception as exc:
        outcome = {"outcome": "recovery_block", "error": describe(exc)}
        if module is not None:
            with contextlib.suppress(Exception):  # its own status command then reports the failure too
                module.mark_recovery(outcome["error"])
    if outcome.get("outcome") == "enforcing" or outcome.get("recovery_installed"):
        return  # enforcing, or register() already blocked, fronted and reported
    install_block(ctx, str(outcome.get("error") or "unknown error"))
    status = recovery_status(str(outcome.get("error") or "unknown error"))
    steps: list[Callable[[], object]] = [lambda: write_load_status(status),
                                         lambda: register_status_command(ctx, lambda args: status, None)]
    for step in steps:
        with contextlib.suppress(Exception):  # best-effort; must never undo the block above
            step()


def install_block(ctx: Any, error: str) -> Callable[..., dict[str, str]]:
    """Register a pre_tool_call veto for every tool. Hermes lets any plugin's block win."""
    message = f"AgentsFence BLOCKED this action: AgentsFence could not start in this Hermes environment ({error}). " + repair_hint()

    def blocked(**_: Any) -> dict[str, str]:
        return {"action": "block", "message": message}

    ctx.register_hook("pre_tool_call", blocked)  # must succeed: never swallow this failure
    return blocked


def managed_environment() -> bool:
    """Hermes' package manager owns this interpreter (``installs/<key>/environments/<generation>/venv``)."""
    return Path(sys.prefix).parent.parent.name == "environments"


def repair_hint() -> str:
    """One pinned command that reinstalls AgentsFence where this Hermes runs it.

    `agentsfence install` declares AgentsFence as the plugin's dependency and runs
    `hermes pm install`; it never installs into Hermes' environment behind the
    package manager. A checkout has no published version to pin.
    """
    if not EXPECTED_VERSION:
        return (f"Repair: `uv pip install --python {sys.executable} -e <your AgentsFence checkout>`, then "
                f"`{sys.executable} -m agentsfence protect --all-profiles`.")
    if not managed_environment():
        return (f"Repair: AgentsFence {EXPECTED_VERSION} needs a Hermes that manages its environment (`hermes pm`). "
                f"Run `hermes update`, then `uvx --from 'agentsfence=={EXPECTED_VERSION}' agentsfence install`.")
    return (f"Repair: run `uvx --from 'agentsfence=={EXPECTED_VERSION}' agentsfence install`; it reinstalls AgentsFence "
            f"{EXPECTED_VERSION} through `hermes pm install` for every protected profile (never another `agentsfence` on PATH).")


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()


def profile_name(home: Path) -> str:
    return home.name if home.parent.name == "profiles" else "default"


def recovery_status(error: str, version: str | None = None) -> dict[str, Any]:
    home = hermes_home()
    return {"schema": STATUS_SCHEMA, "kind": "status", "outcome": "recovery_block", "error": error,
            "agentsfence_version": version, "expected_version": EXPECTED_VERSION, "loader_version": LOADER_VERSION,
            "python": sys.executable, "hermes_home": str(home), "profile": profile_name(home), "time": time.time()}


def load_status_path(agentsfence_home: Path | None = None) -> Path:
    home = hermes_home()
    base = agentsfence_home or Path(os.environ.get("AGENTSFENCE_HOME") or home / "agentsfence").expanduser()
    python = hashlib.sha256(sys.executable.encode()).hexdigest()[:12]
    return base / "load_status" / f"{profile_name(home)}-{python}.json"


def write_load_status(status: dict[str, Any], agentsfence_home: Path | None = None) -> None:
    """Historical evidence of the last load in this profile and interpreter."""
    path = load_status_path(agentsfence_home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(status))
    temporary.chmod(0o600)
    temporary.replace(path)


def register_status_command(ctx: Any, status: Callable[[Any], dict[str, Any]],
                            probe: Callable[[str, list[str]], dict[str, Any]] | None) -> None:
    """``hermes agentsfence status|probe --json``: answers for this process only."""

    def setup(parser: Any) -> None:
        actions = parser.add_subparsers(dest="agentsfence_action")
        report = actions.add_parser("status", help="Report whether AgentsFence enforces in this Hermes process")
        report.add_argument("--json", action="store_true")
        check = actions.add_parser("probe", help="Run a compiler probe, scenario test or model pick in this process")
        check.add_argument("kind", nargs="?", default="compiler", choices=["compiler", "compiler-eval", "test", "test-all", "models", "jobs"])
        check.add_argument("--scenario", action="append", default=[])
        check.add_argument("--json", action="store_true")

    def handle(args: Any) -> int:
        if getattr(args, "agentsfence_action", None) == "probe":
            kind = getattr(args, "kind", "compiler")
            scenarios = list(getattr(args, "scenario", None) or [])
            result = (probe(kind, scenarios) if probe else
                      {"ok": False, "error": "AgentsFence could not start in this Hermes environment."})
            payload = {**status(args), "kind": "probe", "probe": result}
        else:
            payload = status(args)
        print(STATUS_MARKER + json.dumps(payload))
        return 0

    ctx.register_cli_command("agentsfence", "AgentsFence status for this Hermes environment", setup, handle,
                             description="Reports this Hermes process's AgentsFence state; used by `agentsfence doctor`.")
