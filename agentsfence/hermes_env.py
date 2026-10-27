"""Which Python Hermes runs, whether its package manager owns it, and whether starting Hermes would update it.

AgentsFence supports Hermes that manages its own Python environment (``hermes pm``):
Hermes runs from a generation recorded in ``<Hermes home>/installs/<key>/facts.json``,
and a starting Hermes process rebuilds that environment, or finishes an interrupted
update, before it does anything else. Stable Hermes 0.21.5 and earlier run from
``<source>/venv``; ``hermes update`` moves them to the package manager. So:

* never install into Hermes' environment behind the manager's back: declare
  AgentsFence as the plugin's Python dependency and let ``hermes pm install``
  build it;
* never start Hermes to check it while an update is pending: the check itself
  would run the update, and chats fail until it finishes.

Standard library only: install runs this before AgentsFence is in Hermes' environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

#: Hermes' own currency check, run with Hermes' interpreter. Read-only: the same
#: comparisons a starting Hermes makes before deciding to rebuild.
_CURRENCY_CHECK = r"""
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
out = {}
try:
    from hermes_cli.steward import read_install_stamp
    out["self_managed"] = (read_install_stamp(root) or {}).get("updateMechanism") == "self"
except Exception as exc:
    out["error"] = type(exc).__name__
try:
    import pm
    out["current"] = bool(pm.venv_is_current(project_root=root))
except Exception as exc:
    out["error"] = type(exc).__name__
try:
    from hermes_cli.update_lock import read_live_update
    out["update_running"] = read_live_update() is not None
except Exception:
    pass
print("AGENTSFENCE_HERMES_ENV=" + json.dumps(out))
"""
CHECK_TIMEOUT = 30.0


@dataclass(frozen=True)
class HermesInstall:
    """Where Hermes runs from. ``managed``: Hermes' package manager owns ``python``."""

    source: Path | None
    python: Path | None
    managed: bool
    state_dir: Path | None = None
    #: The launcher consulted, when it exists: an install it names that could not be
    #: identified is unverified, never "nothing pending".
    launcher: Path | None = None

    def describe(self) -> str:
        if self.python is None:
            return "Hermes' Python was not found"
        owner = "managed by Hermes (`hermes pm`)" if self.managed else "Hermes' virtual environment"
        return f"{self.python} ({owner})"


def _executable(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def launcher() -> str | None:
    configured = os.environ.get("AGENTSFENCE_HERMES", "").strip()
    exe = configured or shutil.which("hermes")
    if not exe:
        return None
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
    root = home.parent.parent if home.parent.name == "profiles" else home
    source = _managed_launcher_source(root, exe)
    if source is not None:
        # Desktop prepends a generation's console scripts to PATH. Those import
        # that generation's workspace and can run PM for the snapshot instead of
        # the owning installation. Use a source-bound Hermes bootstrap launcher.
        for relative in (".hermes/bin/hermes", ".hermes/bin/hermes.exe", ".hermes/bin/hermes.cmd",
                         "venv/bin/hermes", "venv/Scripts/hermes.exe", "venv/Scripts/hermes.cmd"):
            candidate = source / relative
            if candidate.is_file() and _named_checkout(candidate) == source:
                return str(candidate)
    return exe


#: A checkout's own launchers and interpreters, relative to the checkout: the files Hermes
#: itself recognizes as its launchers (hermes_cli/_launchers.py, _owns_launcher). Installer
#: checkouts run `.hermes/bin/hermes` and have no venv; releases and migrated installs run
#: `venv/bin/hermes`.
_CHECKOUT_FILES = tuple(Path(p).parts for p in (
    ".hermes/bin/hermes", ".hermes/bin/hermes.exe", ".hermes/bin/hermes.cmd", ".hermes/bin/hermes-acp",
    "venv/bin/hermes", ".venv/bin/hermes", "venv/Scripts/hermes.exe", ".venv/Scripts/hermes.exe",
    "venv/bin/python", "venv/bin/python3", "venv/Scripts/python.exe", "hermes", "run_agent.py",
))
#: The bootstrap line of Hermes' store launchers: sys.path.insert(0, '<source>').
_BOOTSTRAP = re.compile(r"""sys\.path\.insert\(0,\s*(?:'([^']+)'|"([^"]+)")\)""")


def _is_checkout(root: Path) -> bool:
    """A Hermes source tree: its pyproject names the hermes-agent project (any repo has a pyproject)."""
    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")[:4000]
    except (OSError, ValueError):
        return False
    return re.search(r"""^name\s*=\s*["']hermes-agent["']""", text, re.MULTILINE) is not None


def _checkout_of(path: Path) -> Path | None:
    """``<source>`` when ``path`` is one of a Hermes checkout's own launchers (not a managed generation)."""
    parts = path.parts
    for suffix in _CHECKOUT_FILES:
        if len(parts) > len(suffix) and tuple(parts[-len(suffix):]) == suffix:
            root = Path(*parts[:-len(suffix)])
            if _is_checkout(root):
                return root
    return None


def _named_checkout(exe: Path, depth: int = 3) -> Path | None:
    """The checkout a launcher runs: its own path, or what its script execs or bootstraps (a few levels)."""
    found = _checkout_of(exe) or _checkout_of(exe.resolve())
    if found or depth == 0:
        return found
    try:
        text = exe.read_text(encoding="utf-8", errors="ignore")[:16000]
    except (OSError, ValueError):
        return None
    try:
        tokens = shlex.split(text, comments=True)
    except ValueError:
        tokens = re.findall(r"[^\s\"']+", text)
    for token in tokens:
        for m in _BOOTSTRAP.finditer(token):
            root = Path(m.group(1) or m.group(2))
            if _is_checkout(root):
                return root
    for token in tokens:
        if not token.startswith(("/", "~")) and not re.match(r"^[A-Za-z]:[\\/]", token):
            continue
        path = Path(token).expanduser()
        found = _checkout_of(path)
        if found:
            return found
        if path.name.startswith("hermes") and path.is_file() and path != exe:
            found = _named_checkout(path, depth - 1)  # a wrapper that execs another launcher
            if found:
                return found
    return None


def source_root(launcher_path: str | None = None) -> Path | None:
    """The Hermes checkout the launcher runs; the default location only when there is no launcher.

    A launcher that names no checkout (a custom wrapper, a packaged runtime) is never
    paired with a guessed install.
    """
    configured = os.environ.get("AGENTSFENCE_HERMES_PYTHON", "").strip()
    if configured:
        # <source>/venv/bin/python, as the test and CI installs lay it out. A managed
        # generation's interpreter names no checkout: find it through the launcher.
        found = _checkout_of(Path(configured))
        if found:
            return found
    exe = launcher_path if launcher_path is not None else launcher()
    if exe:
        return _named_checkout(Path(exe))
    if launcher_path is None and os.environ.get("AGENTSFENCE_HERMES", "").strip():
        return None  # a configured launcher names its own install; never guess another
    default = Path.home() / ".hermes" / "hermes-agent"
    return default if _is_checkout(default) else None


def _existing_launcher(launcher_path: str | None) -> Path | None:
    exe = launcher_path if launcher_path is not None else launcher()
    if not exe:
        return None
    path = Path(exe)
    return path if path.is_file() else None


def state_dir(source: Path, home_root: Path) -> Path:
    """Hermes' per-install state: ``installs/<sha256(source)[:16]>`` (pm.environments.install_key)."""
    key = hashlib.sha256(str(source.resolve()).encode("utf-8")).hexdigest()[:16]
    return home_root / "installs" / key


def _managed_launcher_source(home_root: Path, launcher_path: str | None) -> Path | None:
    """Identify PM's generated console launcher through its source-bound activation stamp."""
    exe = _existing_launcher(launcher_path)
    if exe is None:
        return None
    exe = _unresolved(exe)
    install = _state_of(exe, home_root)
    if install is None:
        return None
    parts = exe.relative_to(install).parts
    if (len(parts) != 5 or parts[0] != "environments" or parts[2] != "venv"
            or parts[3] not in {"bin", "Scripts"} or parts[4] not in {"hermes", "hermes.exe", "hermes.cmd"}):
        return None
    try:
        source = Path((install / "inputs/.project-root").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if not source.is_absolute() or not _is_checkout(source) or state_dir(source, home_root).resolve() != install.resolve():
        return None
    return source


def detect(home_root: Path, launcher_path: str | None = None) -> HermesInstall:
    """Hermes' interpreter from Hermes' own record when a manager owns it, else its venv."""
    configured = os.environ.get("AGENTSFENCE_HERMES_PYTHON", "").strip()
    if configured:
        # The override chooses the interpreter, never who owns it: the managed environment
        # stays the package manager's to build, whichever way its Python was named.
        python = _unresolved(Path(configured))
        source = source_root(launcher_path) or _managed_launcher_source(home_root, launcher_path)
        install = state_dir(source, home_root) if source is not None else _state_of(python, home_root)
        managed = (_state_of(python, home_root) is not None or python == _recorded_python(install)
                   or (source is not None and _self_managed(source)))
        return HermesInstall(source, python, managed=managed, state_dir=install, launcher=_existing_launcher(launcher_path))
    source = source_root(launcher_path) or _managed_launcher_source(home_root, launcher_path)
    if source is None:
        return HermesInstall(None, None, managed=False, launcher=_existing_launcher(launcher_path))
    install = state_dir(source, home_root)
    try:
        facts = json.loads((install / "facts.json").read_text(encoding="utf-8-sig"))
        environment = facts["packages"]["venv"]["environment"]
    except (OSError, ValueError, KeyError, TypeError):
        environment = None
    found = _existing_launcher(launcher_path)
    if isinstance(environment, str) and _executable(Path(environment)).exists():
        return HermesInstall(source, _executable(Path(environment)), managed=True, state_dir=install, launcher=found)
    legacy = _executable(source / "venv")
    # A self-updating install whose manager has not recorded an environment yet (the first
    # start after `hermes update` moved it to `hermes pm`) is still the manager's to build.
    return HermesInstall(source, legacy if legacy.exists() else None, managed=_self_managed(source), state_dir=install,
                         launcher=found)


def _unresolved(python: Path) -> Path:
    """``python`` with its directories resolved but not the interpreter, which a venv symlinks elsewhere."""
    path = python.expanduser().absolute()
    try:
        return path.parent.resolve() / path.name
    except OSError:
        return path


def _state_of(python: Path, home_root: Path) -> Path | None:
    """``<home>/installs/<key>`` when ``python`` lives in a generation Hermes' package manager built."""
    installs = _unresolved(home_root / "installs" / "x").parent
    try:
        key = python.relative_to(installs).parts[0]
    except (ValueError, IndexError):
        return None
    return installs / key


def _recorded_python(install: Path | None) -> Path | None:
    """The interpreter ``installs/<key>/facts.json`` records, if any."""
    if install is None:
        return None
    try:
        facts = json.loads((install / "facts.json").read_text(encoding="utf-8-sig"))
        environment = facts["packages"]["venv"]["environment"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return _unresolved(_executable(Path(environment))) if isinstance(environment, str) else None


def _self_managed(source: Path) -> bool:
    try:
        stamp = json.loads((source / "install-stamp.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    return isinstance(stamp, dict) and stamp.get("updateMechanism") == "self" and (source / "pm").is_dir()


#: Kinds of pending work: "update" (an update is running or owes its last steps; only Hermes
#: may finish it), "rebuild" (the environment is out of date; `hermes pm install` rebuilds it)
#: and "unverified" (a managed install whose state Hermes' own check could not report: it
#: may owe either, so it is treated as pending).
UPDATE, REBUILD, UNVERIFIED = "update", "rebuild", "unverified"


def _unverified(why: str) -> tuple[str, str]:
    return UNVERIFIED, (f"Hermes' update state could not be verified ({why}); a start could run pending update work. "
                        "Check it with `hermes pm status`, finish any update with `hermes update` or `hermes pm install`, "
                        "then re-run this command")


def pending_work(install: HermesInstall, home_root: Path) -> tuple[str, str] | None:
    """``(kind, reason)`` when starting Hermes now would first run its own update work, else None.

    For an install Hermes' package manager owns, a check that cannot run or report is
    UNVERIFIED, never "nothing pending": only a venv install, which owes no start-time
    work, falls back to None. The reason is a sentence that names the remedy.
    """
    if os.environ.get("HERMES_DISABLE_LAZY_INSTALLS", "").strip().lower() in ("1", "true", "yes"):
        return None  # Hermes does no update work at start with lazy installs disabled
    if install.source is None:
        if install.python is not None and not install.managed:
            return None  # an interpreter the user named explicitly as a plain environment
        if install.launcher is not None:
            return UNVERIFIED, (f"AgentsFence cannot tell which Hermes installation {install.launcher} runs, so it cannot "
                                "check whether starting Hermes would run update work first. If that Hermes is not "
                                "self-managed, set AGENTSFENCE_HERMES_PYTHON to the Python it runs; otherwise check it "
                                "with `hermes pm status`, then re-run this command")
        return None
    if install.state_dir is not None and (install.state_dir / "source-completion-pending").is_file():
        return UPDATE, "Hermes still owes the last steps of an update; run `hermes update` to finish it"
    for marker in (".update-incomplete", ".lazy-refresh-incomplete"):
        if (install.source / marker).exists():
            return UPDATE, "a Hermes update is in progress; wait for it to finish"
    if install.python is None:
        return _unverified("Hermes' Python was not found") if install.managed else None
    # Also without a recorded environment: the first start after `hermes update` moves a
    # venv install to Hermes' manager has no record yet, and is exactly when it rebuilds.
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["HERMES_HOME"] = str(home_root)
    try:
        proc = subprocess.run([str(install.python), "-I", "-B", "-c", _CURRENCY_CHECK, str(install.source)],
                              env=env, capture_output=True, text=True, timeout=CHECK_TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return _unverified(f"its check did not finish in {CHECK_TIMEOUT:.0f}s") if install.managed else None
    except OSError as exc:
        return _unverified(f"its check could not run: {exc.strerror or exc}") if install.managed else None
    line = next((x for x in reversed(proc.stdout.splitlines()) if x.startswith("AGENTSFENCE_HERMES_ENV=")), "")
    try:
        state = json.loads(line.partition("=")[2]) if line else None
    except ValueError:
        state = None
    if not isinstance(state, dict):
        return _unverified(f"its check gave no answer, exit status {proc.returncode}") if install.managed else None
    if state.get("update_running"):
        return UPDATE, "a Hermes update is running; wait for it to finish"
    if state.get("self_managed") and state.get("current") is False:
        return REBUILD, ("Hermes' Python environment is out of date (after an update or a plugin dependency change) and "
                         "the next Hermes start rebuilds it; run `hermes pm install` and wait for it to finish")
    if install.managed and (state.get("error") or not isinstance(state.get("current"), bool)):
        return _unverified(f"its check failed: {state.get('error') or 'no currency answer'}")
    return None


def pending_update(install: HermesInstall, home_root: Path) -> str | None:
    work = pending_work(install, home_root)
    return work[1] if work else None


def installed_version(python: Path) -> str | None:
    """The AgentsFence version installed for ``python``, asked of that interpreter."""
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    code = "import importlib.metadata as m\ntry: print(m.version('agentsfence'))\nexcept m.PackageNotFoundError: pass"
    try:
        proc = subprocess.run([str(python), "-I", "-c", code], env=env, capture_output=True, text=True,
                              timeout=CHECK_TIMEOUT, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or None


INSTALLED, SKIPPED, FAILED = "installed", "skipped", "failed"


def progress_stream() -> int:
    """Where Hermes' build output goes: stderr, so `--json` output on stdout stays parseable."""
    try:
        return sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):  # a replaced stderr (tests, embedded) has no descriptor
        return subprocess.DEVNULL


#: Why AgentsFence cannot install into a Hermes that does not manage its environment.
UNMANAGED = ("AgentsFence needs a Hermes that manages its own Python environment (`hermes pm`). This Hermes runs "
             "from {python}. Run `hermes update` (it moves Hermes to its package manager), then re-run this command.")


def unsupported_reason(install: HermesInstall) -> str | None:
    """Why this Hermes cannot run AgentsFence, before anything is written; None when it can."""
    if install.python is None:
        if install.launcher is None:
            return "Hermes was not found. Install Hermes (or put `hermes` on PATH), then re-run this command."
        return (f"AgentsFence cannot tell which Python {install.launcher} runs. If that is a custom wrapper, set "
                "AGENTSFENCE_HERMES to Hermes' own launcher.")
    if not install.managed:
        return UNMANAGED.format(python=install.python)
    if launcher() is None:
        return "No Hermes launcher found (put `hermes` on PATH or set AGENTSFENCE_HERMES)."
    return None


def run_pm_install(install: HermesInstall, home_root: Path) -> tuple[str, str]:
    """``hermes pm install``: build Hermes' environment from every enabled plugin's declared dependencies.

    Streams the tool's output. Returns ``(INSTALLED | FAILED, message)``; the active
    environment is left as it was when the build fails.
    """
    reason = unsupported_reason(install)
    if reason:
        return FAILED, reason
    work = pending_work(install, home_root)
    if work and work[0] in (UPDATE, UNVERIFIED):
        return FAILED, f"Not installed: {work[1]}. Then re-run this command."
    exe = launcher()
    assert exe is not None  # checked by unsupported_reason
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["HERMES_HOME"] = str(home_root)
    print("Building Hermes' Python environment with its package manager (`hermes pm install`). This can take a few "
          "minutes; Hermes chats wait for it.", file=sys.stderr, flush=True)
    code = subprocess.call([exe, "pm", "install"], env=env, stdin=subprocess.DEVNULL, stdout=progress_stream())
    if code != 0:
        return FAILED, f"`hermes pm install` failed (exit {code})."
    return INSTALLED, "Hermes' environment is built."
