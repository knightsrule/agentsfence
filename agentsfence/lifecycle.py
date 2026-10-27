"""Install, protect, unprotect, settings and uninstall as journaled, recoverable transactions.

Every operation that changes files follows the same order:

1. **Preflight** (``preflight.run``): Hermes has ``hermes pm`` and every capability
   AgentsFence relies on, and no update is pending. Nothing changes on failure.
2. **Snapshot** every file AgentsFence may touch (each profile's ``config.yaml``,
   ``.env``, loader directory and overrides; the shared settings; ``state.json``)
   into ``<root>/agentsfence/backups/<id>/`` and record a journal.
3. **Apply** the file changes (each file is written atomically).
4. **Build** Hermes' environment with ``hermes pm install`` when the declared
   enabled dependencies may have changed. With no protected profiles, install
   registers the disabled surfaces without building; the first protect builds.
5. **Verify** that a new Hermes process for a protected profile loads this version
   and enforces.
6. **Commit**: remove the journal and snapshot.

A failure at 3-5 restores the snapshot. If the build had already switched Hermes'
environment, the build runs again from the restored declarations, so profiles that
were protected keep the version that protected them. A crash leaves the journal;
the next AgentsFence command (``recover``) finishes the rollback first. When even
the rollback cannot rebuild, the fail-closed loaders block tools and doctor prints
the repair; a protected profile is never silently left unprotected.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import __version__
from .config import INHERIT, SELECTED, load_settings, shared_settings_path
from .profiles import (
    MAX_COMPILE_BUDGET,
    agentsfence_root,
    available_profiles,
    has_written_loader,
    hook_timeout_for,
    install_surfaces,
    is_checkout,
    is_protected,
    loader_source,
    override_path,
    plugin_dir,
    profile_name,
    protect_profile,
    published_release,
    read_config,
    read_settings_file,
    read_state,
    refresh_installed_surfaces,
    root_home,
    sync_compiler_route,
    unprotect_profile,
    validate_profile,
    write_config,
    write_state,
    write_text_atomic,
)


class LifecycleError(RuntimeError):
    """An operation that changed nothing (or was fully rolled back); the message says what to do."""


class LockBusy(LifecycleError):
    """Another lifecycle operation holds the lock on this Hermes root."""


def journal_path() -> Path:
    return agentsfence_root() / "transaction.json"


def _audit_lifecycle(event: str, **details: Any) -> None:
    """Record a lifecycle event in the shared root audit log (best effort)."""
    try:
        from .audit import AuditLog
        from .models import AuditEvent

        homes = available_profiles()
        names = details.get("profiles") or ([details["profile"]] if details.get("profile") else [])
        paths = {agentsfence_root() / "audit.jsonl": load_settings(hermes_dir=root_home()).audit}
        for name in names:
            if name in homes:
                settings = load_settings(hermes_dir=homes[name])
                paths[settings.home / "audit.jsonl"] = settings.audit
        for path, audit_settings in paths.items():
            AuditLog(path, audit_settings).record(AuditEvent(event=event, details={"agentsfence_version": __version__, **details}))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Lock and snapshot
# ---------------------------------------------------------------------------


@contextmanager
def _lock() -> Iterator[None]:
    """One lifecycle operation at a time on this Hermes root.

    The OS lock alone decides ownership, so a lock file left by a crashed process
    never blocks later commands. The owner's PID is kept in the file for the message.
    """
    path = agentsfence_root() / "lifecycle.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as stream:
        path.chmod(0o600)
        try:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                if not stream.read(1):
                    stream.write("0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            owner = ""
            with contextlib.suppress(OSError, ValueError):
                stream.seek(0)
                owner = stream.read().strip()
            who = f" (PID {owner})" if owner.isdigit() and owner != "0" else ""
            raise LockBusy(f"Another AgentsFence operation{who} is running on this Hermes. "
                                 "Wait for it to finish, then re-run this command.") from exc
        try:
            stream.seek(0)
            stream.truncate()
            stream.write(str(os.getpid()))
            stream.flush()
            yield
        finally:
            stream.seek(0)
            stream.truncate()
            stream.write("0")
            stream.flush()
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _tracked_paths() -> list[Path]:
    """Every file or directory an AgentsFence operation may change, across all profiles."""
    paths: list[Path] = [shared_settings_path(root_home()), agentsfence_root() / "state.json"]
    for home in available_profiles().values():
        paths += [home / "config.yaml", home / ".env", plugin_dir(home)]
        with contextlib.suppress(ValueError, OSError):
            paths.append(override_path(home))
    return list(dict.fromkeys(paths))


def _snapshot(backup: Path) -> list[dict[str, Any]]:
    backup.mkdir(parents=True, mode=0o700, exist_ok=True)
    entries = []
    for index, path in enumerate(_tracked_paths()):
        if path.is_dir() and (is_checkout(path.parent.parent) if path.name == "agentsfence" else False):
            continue  # a checkout is the user's working tree; AgentsFence never rewrites it
        copy = backup / str(index)
        if path.is_symlink():
            copy.symlink_to(os.readlink(path), target_is_directory=path.is_dir())
            kind = "symlink"
        elif path.is_dir():
            shutil.copytree(path, copy, symlinks=True)
            kind = "dir"
        elif path.is_file():
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, copy)
            kind = "file"
        else:
            kind = "absent"
        entries.append({"path": str(path), "kind": kind, "copy": str(copy)})
    return entries


def _restore(entries: list[dict[str, Any]]) -> list[str]:
    problems = []
    for entry in entries:
        path, copy = Path(entry["path"]), Path(entry["copy"])
        try:
            if entry["kind"] == "dir":
                path.mkdir(parents=True, exist_ok=True)
                # Publish each restored file atomically; never remove the active loader first.
                for item in copy.rglob("*"):
                    target = path / item.relative_to(copy)
                    if item.is_symlink():
                        _restore_symlink(item, target)
                    elif item.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif item.is_file():
                        _restore_file(item, target)
                for item in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                    saved = copy / item.relative_to(path)
                    if not saved.exists() and not saved.is_symlink():
                        shutil.rmtree(item) if item.is_dir() else item.unlink()
            elif entry["kind"] == "symlink":
                _restore_symlink(copy, path)
            elif entry["kind"] == "file":
                _restore_file(copy, path)
            elif path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            problems.append(f"{path}: {exc.strerror or exc}")
    return problems


def _restore_symlink(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(".agentsfence-link-" + uuid.uuid4().hex)
    try:
        tmp.symlink_to(os.readlink(source), target_is_directory=source.is_dir())
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def _restore_file(source: Path, target: Path) -> None:
    import tempfile

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".agentsfence-restore-")
    os.close(fd)
    try:
        shutil.copy2(source, tmp)
        os.replace(tmp, target)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _write_journal(journal: dict[str, Any]) -> None:
    from .profiles import write_json

    write_json(journal_path(), journal)


def _clear(journal: dict[str, Any]) -> None:
    journal_path().unlink(missing_ok=True)
    shutil.rmtree(journal.get("backup") or "", ignore_errors=True)


# ---------------------------------------------------------------------------
# Hermes steps (module-level so tests can substitute them)
# ---------------------------------------------------------------------------


def detect_install() -> Any:
    from .hermes_env import detect

    return detect(root_home())


def run_preflight() -> dict[str, Any]:
    from . import preflight

    return preflight.run(detect_install(), root_home())


def build_environment() -> tuple[bool, str]:
    from .hermes_env import INSTALLED, run_pm_install

    result, message = run_pm_install(detect_install(), root_home())
    return result == INSTALLED, message


def verify_loads(home: Path, version: str | None) -> tuple[bool, str]:
    """A new Hermes process for ``home`` enforces AgentsFence ``version`` (any version when None)."""
    from .host_client import status

    answer = status(home)
    if not answer.get("reachable"):
        return False, f"Hermes did not answer for {profile_name(home)}: {answer.get('error')}"
    if answer.get("outcome") != "enforcing":
        return False, f"AgentsFence is not enforcing in {profile_name(home)}: {answer.get('error') or answer.get('outcome')}"
    if answer.get("compatibility_error"):
        return False, f"{profile_name(home)}: {answer['compatibility_error']}"
    loaded = answer.get("agentsfence_version")
    if version and loaded != version:
        return False, f"Hermes loads AgentsFence {loaded} in {profile_name(home)}, not {version}."
    return True, f"{profile_name(home)}: a new Hermes process enforces AgentsFence {loaded}."


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


def _protected_homes() -> list[Path]:
    return [home for home in available_profiles().values() if is_protected(home)]


def _needs_build() -> bool:
    """PM discovers enabled declarations; disabled registration alone needs no build."""
    return published_release() and any(is_protected(home) and has_written_loader(home)
                                       for home in available_profiles().values())


def recover() -> list[str]:
    """Finish rolling back a transaction that a crash interrupted; returns what was reported."""
    path = journal_path()
    if not path.is_file():
        return []
    try:
        journal = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise LifecycleError(f"Cannot read {path}. Recovery is required; keep the journal and backups for repair.") from None
    if (not isinstance(journal, dict) or not isinstance(journal.get("backup"), str)
            or not isinstance(journal.get("entries"), list) or not journal["entries"]
            or any(not isinstance(entry, dict) or entry.get("kind") not in {"dir", "file", "symlink", "absent"}
                   or not isinstance(entry.get("path"), str) or not isinstance(entry.get("copy"), str)
                   for entry in journal["entries"])):
        raise LifecycleError(f"Incomplete transaction journal at {path}. Kept it and the backups for repair.")
    lines = [f"Rolling back an interrupted AgentsFence {journal.get('operation', 'operation')} "
             f"(started {time.strftime('%Y-%m-%d %H:%M %Z', time.localtime(journal.get('started') or 0))})."]
    lines += _rollback(journal)
    return lines


def _rollback(journal: dict[str, Any]) -> list[str]:
    lines = []
    problems = _restore(journal.get("entries") or [])
    if problems:
        lines.append("Could not restore: " + "; ".join(problems))
    if journal.get("built") is not False:
        ok, message = build_environment()
        if not ok:
            problems.append("Hermes environment rebuild failed")
        lines.append("Rebuilt Hermes' environment from the restored settings." if ok else
                     f"Rebuilding Hermes' environment from the restored settings failed: {message} Protected profiles "
                     "block every tool call until `agentsfence install` succeeds.")
    homes = _protected_homes()
    if homes and journal.get("built") is not False and not problems:
        for home in homes:
            ok, message = verify_loads(home, journal.get("previous_version"))
            lines.append(message if ok else f"After rollback: {message}")
            if not ok:
                problems.append(message)
    _audit_lifecycle("rolled_back", operation=journal.get("operation"), problems=problems)
    if problems:
        journal["recovery_errors"] = problems
        _write_journal(journal)
        raise LifecycleError("Rollback incomplete. Kept the journal and backups; protected profiles fail closed. "
                             + " ".join(lines) + " Run `agentsfence install` to retry recovery.")
    _clear(journal)
    return lines


def _previous_version() -> str | None:
    recorded = read_state().get("version")
    if recorded:
        return str(recorded)
    # The pre-0.3 lifecycle did not write state.json. Preserve its loader version
    # through the first migrated environment switch as well.
    from .config import read_yaml

    versions = set()
    for home in _protected_homes():
        manifest = plugin_dir(home) / "plugin.yaml"
        if manifest.is_file():
            version = (read_yaml(manifest) or {}).get("version")
            if isinstance(version, str):
                versions.add(version)
    if len(versions) == 1:
        return versions.pop()
    return None


#: Operations that may run while Hermes has a different AgentsFence version: install
#: moves every protected profile to this version; uninstall removes it everywhere.
_ANY_VERSION = {"install", "uninstall"}


def version_mismatch(installed: str) -> str:
    return (f"Hermes runs AgentsFence {installed}, but this command is AgentsFence {__version__}. To keep {installed}, "
            f"run the command with `uvx --from 'agentsfence=={installed}' agentsfence ...`; to upgrade every protected "
            f"profile first, run `uvx --from 'agentsfence=={__version__}' agentsfence install`. Nothing was changed.")


def transaction(operation: str, apply: Callable[[], dict[str, Any]], *, build: bool | None = None,
                verify: bool = True, preflight: bool = True,
                condition: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Run ``apply`` (file changes) inside a snapshot, then build and verify; roll back on any failure.

    Only install and uninstall run while Hermes has another AgentsFence version: any
    other operation would pin loaders to a version the environment does not have
    (every protected profile would then block), or silently move them to this one.
    """
    with _lock():
        recovered = recover()
        if condition is not None and not condition():
            return {"operation": operation, "recovered": recovered, "profiles": [], "lines": list(recovered)}
        installed = _previous_version()
        if installed and installed != __version__ and operation not in _ANY_VERSION:
            raise LifecycleError(version_mismatch(installed))
        report: dict[str, Any] = {"operation": operation, "recovered": recovered, "lines": list(recovered)}
        if preflight:
            check = run_preflight()
            report["preflight"] = check
            if not check.get("ok"):
                raise LifecycleError(check.get("error") or "The capability check failed. Nothing was changed.")
        journal: dict[str, Any] = {"id": uuid.uuid4().hex[:12], "operation": operation, "started": time.time(),
                                   "previous_version": _previous_version(), "built": False}
        backup = agentsfence_root() / "backups" / journal["id"]
        journal["backup"] = str(backup)
        journal["entries"] = _snapshot(backup)
        _write_journal(journal)
        needs_build_before = _needs_build()
        try:
            report.update(apply())
            # Existing and candidate packages are accepted only while switching environments.
            previous = journal.get("previous_version")
            if previous and previous != __version__:
                for home in _protected_homes():
                    if has_written_loader(home):
                        write_text_atomic(plugin_dir(home) / "__init__.py",
                                          loader_source(accepted_versions=(previous, __version__)))
            if build if build is not None else (_needs_build() or needs_build_before):
                journal["built"] = None  # a build that starts may switch Hermes' environment
                _write_journal(journal)
                ok, message = build_environment()
                if not ok:
                    raise LifecycleError(message)
                journal["built"] = True
                _write_journal(journal)
                report["lines"].append(message)
            homes = _protected_homes()
            verified = False
            if verify and homes and published_release():
                for home in homes:
                    ok, message = verify_loads(home, __version__)
                    if not ok:
                        raise LifecycleError(message)
                    report["lines"].append(message)
                verified = True
            # Accept only this version once Hermes demonstrably runs it. Without a build
            # and verification, loaders keep accepting both, never a version Hermes lacks.
            if previous and previous != __version__ and journal["built"] is True and verified:
                for home in _protected_homes():
                    if has_written_loader(home):
                        write_text_atomic(plugin_dir(home) / "__init__.py", loader_source())
        except BaseException as exc:
            if journal["built"] is None:
                journal["built"] = True  # unknown outcome: rebuild from the restored declarations
            lines = _rollback(journal)
            detail = str(exc) if isinstance(exc, (LifecycleError, ValueError, OSError)) else f"{type(exc).__name__}: {exc}"
            _audit_lifecycle("failed", operation=operation, error=detail)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise LifecycleError(f"{detail} Rolled back: every profile is as it was before this command."
                                 + (" " + " ".join(lines) if lines else "")) from exc
        _clear(journal)
        return report


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _names(names: list[str] | None, all_profiles: bool) -> list[str]:
    profiles = available_profiles()
    chosen = list(profiles) if all_profiles else list(dict.fromkeys(names or []))
    if not chosen:
        raise LifecycleError("Choose profiles: --profile NAME, --profiles NAME ... or --all-profiles.")
    unknown = [n for n in chosen if n not in profiles]
    if unknown:
        raise LifecycleError(f"Unknown Hermes profile(s): {', '.join(unknown)}. Available: {', '.join(profiles)}.")
    for name in chosen:  # every selected profile must be readable before any is written
        try:
            validate_profile(profiles[name])
        except ValueError as exc:
            raise LifecycleError(f"{name}: {exc} Nothing was changed.") from exc
    return chosen


def install(*, build: bool | None = None, preflight: bool = True) -> dict[str, Any]:
    """Register this AgentsFence with Hermes; re-apply it to every protected profile (upgrade)."""

    def apply() -> dict[str, Any]:
        state = read_state()
        profiles = available_profiles()
        # Profiles the user protected stay protected, even if an update disabled the plugin.
        targets = [n for n in state["protected"] if n in profiles] or [n for n, h in profiles.items() if is_protected(h)]
        results = [protect_profile(profiles[n]) for n in targets]
        if not targets:
            install_surfaces(root_home())  # dependency declaration and companion; profile stays disabled
        aligned = refresh_installed_surfaces(skip={profiles[n] for n in targets})
        write_state({**state, "protected": targets, "version": __version__})
        _audit_lifecycle("installed", profiles=targets)
        lines = [f"AgentsFence {__version__} is registered with Hermes."]
        lines += [f"{r['profile']}: protected." + "".join(f" {n}" for n in r["notes"]) for r in results]
        if aligned:
            lines.append("Loaders updated to " + __version__ + ": " + ", ".join(aligned))
        if not targets:
            lines.append("Hermes installs the AgentsFence dependency when you protect the first profile.")
            lines.append("No profile is protected yet. Next: `agentsfence protect --all-profiles` (or --profile NAME).")
        return {"profiles": targets, "lines": lines}

    return transaction("install", apply, build=build, preflight=preflight)


def protect(names: list[str] | None = None, *, all_profiles: bool = False, include_new: bool | None = None,
            build: bool | None = None, preflight: bool = True, automatic: bool = False) -> dict[str, Any]:
    chosen = _names(names, all_profiles)

    def still_requested() -> bool:
        # Recheck under the transaction lock: a user may have disabled include-new
        # or excluded a profile since sweep selected its candidates.
        state = read_state()
        profiles = available_profiles()
        chosen[:] = [name for name in chosen if name in profiles and state["include_new"] and name not in state["excluded"]
                     and (not is_protected(profiles[name]) or not (plugin_dir(profiles[name]) / "__init__.py").is_file())]
        return bool(chosen)

    def apply() -> dict[str, Any]:
        profiles = available_profiles()
        results = [protect_profile(profiles[n]) for n in chosen]
        aligned = refresh_installed_surfaces(skip={profiles[n] for n in chosen})
        state = read_state()
        new_state = {**state, "protected": [*state["protected"], *chosen],
                     "excluded": [n for n in state["excluded"] if n not in chosen], "version": __version__}
        if include_new is not None:
            new_state["include_new"] = include_new
        write_state(new_state)
        for r in results:
            _audit_lifecycle("protected", profile=r["profile"], route=r["route"])
        lines = [f"{r['profile']}: protected; compiler {_route_text(r['route'])}." + "".join(f" {n}" for n in r["notes"])
                 + " " + _running(profiles[r["profile"]]) for r in results]
        if aligned:
            lines.append("Loaders updated to " + __version__ + ": " + ", ".join(aligned))
        if new_state["include_new"]:
            lines.append("New profiles are protected automatically the next time AgentsFence runs.")
        return {"profiles": chosen, "lines": lines}

    return transaction("protect", apply, build=build, preflight=preflight,
                       condition=still_requested if automatic else None)


def unprotect(names: list[str] | None = None, *, all_profiles: bool = False, build: bool | None = None,
              preflight: bool = True) -> dict[str, Any]:
    chosen = _names(names, all_profiles)

    def apply() -> dict[str, Any]:
        profiles = available_profiles()
        results = [unprotect_profile(profiles[n]) for n in chosen]
        state = read_state()
        write_state({**state, "protected": [n for n in state["protected"] if n not in chosen],
                     "excluded": [*state["excluded"], *chosen], "include_new": state["include_new"] and not all_profiles})
        for r in results:
            _audit_lifecycle("unprotected", profile=r["profile"])
        return {"profiles": chosen, "lines": [f"{r['profile']}: AgentsFence disabled and its files removed." for r in results]}

    return transaction("unprotect", apply, build=build, verify=False, preflight=preflight)


def uninstall(*, purge: bool = False, build: bool | None = None, preflight: bool = True) -> dict[str, Any]:
    """Unprotect every profile, remove AgentsFence's entries, then let pm drop the package."""

    def apply() -> dict[str, Any]:
        profiles = available_profiles()
        results = [unprotect_profile(home) for home in profiles.values()]
        shared = shared_settings_path(root_home())
        removed = []
        for path in (shared, agentsfence_root() / "state.json"):
            if path.is_file():
                path.unlink()
                removed.append(str(path))
        _audit_lifecycle("uninstalled", profiles=list(profiles), purge=purge)  # before --purge removes the logs themselves
        lines = [f"Removed AgentsFence from {len(results)} profile(s)."]
        lines.append("Audit logs and policies were removed (--purge)." if purge else
                     "Audit logs and policies were kept (under each profile's agentsfence/ directory); "
                     "`agentsfence uninstall --purge` removes them.")
        return {"removed": removed, "lines": lines}

    report = transaction("uninstall", apply, build=build, verify=False, preflight=preflight)
    if purge:
        for home in available_profiles().values():
            data_dir = load_settings(hermes_dir=home).home
            for item in (data_dir.iterdir() if data_dir.is_dir() else []):
                if item.name in {"backups", "transaction.json", "lifecycle.lock"}:
                    continue  # the running transaction's own files
                shutil.rmtree(item, ignore_errors=True) if item.is_dir() else item.unlink(missing_ok=True)
            report["removed"].append(str(data_dir))
    if report.get("preflight") is not None or build:
        gc = collect_garbage()
        if gc:
            report["lines"].append(gc)
    report["lines"].append("Finally remove the command itself if you installed it: `uv tool uninstall agentsfence`.")
    return report


def collect_garbage() -> str | None:
    """``hermes pm gc``: remove environments and store entries nothing references any more."""
    import subprocess

    from .hermes_env import launcher, progress_stream

    exe = launcher()
    if not exe:
        return None
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["HERMES_HOME"] = str(root_home())
    code = subprocess.call([exe, "pm", "gc"], env=env, stdin=subprocess.DEVNULL, stdout=progress_stream())
    return ("Removed Hermes environments nothing references any more (`hermes pm gc`)." if code == 0 else
            f"`hermes pm gc` failed (exit {code}); old Hermes environments may remain under {root_home() / 'installs'}.")


def _running(home: Path) -> str:
    """What running Hermes processes for this profile must do to pick the change up."""
    from .diagnostics import snapshot

    try:
        data = snapshot(home)
    except (ValueError, OSError):
        return ""
    if data["state"] in {"restart_required", "enabled"}:
        return str(data["guidance"])
    return "Running Hermes processes use it from their next message; no restart is needed."


def _route_text(route: dict[str, Any]) -> str:
    if not route.get("model"):
        return "unavailable; configure a profile default or a dedicated model"
    return f"{route['model']}" + (f" via {route['provider']}" if route.get("provider") not in (None, "", "auto") else "")


def update_settings(*, mode: str | None = None, model: str | None = None, provider: str | None = None,
                    compile_budget: float | None = None, strict_yolo: bool | None = None,
                    retention_days: int | None = None, profile: str | None = None,
                    preflight: bool = True, apply_to_all_profiles: bool = False) -> dict[str, Any]:
    """Change shared settings (or one profile's overrides) and apply them to every protected profile."""
    if mode not in (None, INHERIT, SELECTED):
        raise LifecycleError("Choose --compiler inherit or --model MODEL.")
    if model is not None and not model.strip():
        raise LifecycleError("Name the compiler model, or use --compiler inherit.")
    if compile_budget is not None and not 0 < compile_budget <= MAX_COMPILE_BUDGET:
        raise LifecycleError(f"Choose a compile budget between 1 and {MAX_COMPILE_BUDGET:g} seconds.")
    if retention_days is not None and retention_days < 1:
        raise LifecycleError("Keep audit logs for at least one day.")
    if profile and profile not in available_profiles():
        raise LifecycleError(f"Unknown Hermes profile {profile!r}.")
    if provider is not None and model is None:
        raise LifecycleError("Choose --model MODEL together with --provider PROVIDER.")
    if apply_to_all_profiles and profile:
        raise LifecycleError("Choose one profile or every protected profile, not both.")
    target = override_path(available_profiles()[profile]) if profile else shared_settings_path(root_home())

    def apply() -> dict[str, Any]:
        data = read_settings_file(target)
        compiler = data.setdefault("compiler", {})
        if model is not None:
            compiler.update(mode=SELECTED, selected_model=model.strip(), selected_provider=(provider or "auto").strip())
        elif mode == INHERIT:
            compiler["mode"] = INHERIT
            compiler.pop("selected_model", None)
            compiler.pop("selected_provider", None)
        if compile_budget is not None:
            compiler["timeout_seconds"] = compile_budget
        if strict_yolo is not None:
            data.setdefault("evaluation", {})["strict_yolo"] = strict_yolo
        if retention_days is not None:
            data.setdefault("audit", {})["retention_days"] = retention_days
        if not compiler:
            data.pop("compiler")
        write_config(target, data)
        if apply_to_all_profiles:
            # Desktop explicitly applies these fields to every protected profile.
            # CLI shared defaults keep their documented per-profile precedence.
            fields = {"compiler": (["mode", "selected_model", "selected_provider"] if model is not None or mode is not None else [])
                                   + (["timeout_seconds"] if compile_budget is not None else []),
                      "evaluation": ["strict_yolo"] if strict_yolo is not None else [],
                      "audit": ["retention_days"] if retention_days is not None else []}
            for home in _protected_homes():
                override = override_path(home)
                if override.resolve() == target.resolve():
                    continue
                local = read_settings_file(override)
                override_changed = False
                for section, keys in fields.items():
                    values = local.get(section)
                    if not isinstance(values, dict):
                        continue
                    for key in keys:
                        if key in values:
                            del values[key]
                            override_changed = True
                    if not values:
                        local.pop(section)
                if override_changed:
                    write_config(override, local)
        lines = [f"Saved {target}."]
        for home in _protected_homes():
            if profile and profile_name(home) != profile:
                continue
            settings = load_settings(hermes_dir=home)
            cfg = read_config(home)
            plugins = cfg.setdefault("plugins", {})
            hook = hook_timeout_for(settings.compiler.timeout_seconds)
            if plugins.get("hook_callback_timeout") != hook:
                plugins["hook_callback_timeout"] = hook
                write_config(home / "config.yaml", cfg)
            changed = sync_compiler_route(home, settings)
            route = changed["to"] if changed else (read_config(home).get("auxiliary") or {}).get("agentsfence_policy") or {}
            lines.append(f"{profile_name(home)}: compiler {_route_text(route)}, budget {settings.compiler.timeout_seconds:g}s.")
        _audit_lifecycle("settings_changed", profiles=[profile] if profile else list(available_profiles()), target=str(target), mode=mode, model=model, compile_budget=compile_budget,
                         strict_yolo=strict_yolo, retention_days=retention_days)
        return {"lines": lines}

    report = transaction("settings", apply, build=False, verify=False, preflight=preflight)
    if model is not None or mode is not None or provider is not None:
        from .host_probe import run_probe

        probes = {}
        for home in _protected_homes():
            if profile and profile_name(home) != profile:
                continue
            result = run_probe(home)
            probes[profile_name(home)] = result
            report["lines"].append(f"{profile_name(home)}: compiler probe "
                                   + ("passed." if result.get("ok") else f"failed: {result.get('error') or result.get('status')}"))
        report["probes"] = probes
    return report


# ---------------------------------------------------------------------------
# Sweep: keep protection where the user asked for it
# ---------------------------------------------------------------------------


def unprotected_profiles() -> list[str]:
    return [name for name, home in available_profiles().items()
            if not is_protected(home) or not (plugin_dir(home) / "__init__.py").is_file()]


def set_include_new(value: bool) -> None:
    """Turn "protect new profiles" on or off (under the lifecycle lock, so no transaction reverts it)."""
    with _lock():
        write_state({**read_state(), "include_new": value})
    _audit_lifecycle("settings_changed", include_new=value)


def sweep(*, protect_new: bool = True) -> list[str]:
    """Upkeep run by AgentsFence commands and when the Desktop pane opens (never inside a chat).

    Finishes an interrupted transaction, keeps compiler routes on their models,
    and, when the user turned on "protect new profiles", protects profiles that
    appeared since (a transaction of its own, so a failure changes nothing).
    Profiles the user unprotected are left alone. A command from another
    AgentsFence version than Hermes runs protects nothing: that would move every
    profile to its own version.
    """
    lines = []
    try:
        try:
            with _lock():
                if journal_path().is_file():
                    lines += recover()
                for home in _protected_homes():
                    changed = sync_compiler_route(home)
                    if changed:
                        lines.append(f"{changed['profile']}: the compiler now uses {_route_text(changed['to'])} "
                                     "(the profile's default model changed).")
        except LockBusy:
            return lines  # the running operation does this upkeep itself
        state = read_state()
        new = [n for n in unprotected_profiles() if n not in state["excluded"]] if protect_new and state["include_new"] else []
        if new and state["version"] and state["version"] != __version__:
            lines.append(f"Not protecting new profile(s) {', '.join(new)}: {version_mismatch(str(state['version']))}")
        elif new and state["version"]:
            report = protect(new, automatic=True)
            if report["profiles"]:
                lines += [f"Protected new profile(s) automatically: {', '.join(report['profiles'])}.", *report["lines"]]
    except (LifecycleError, ValueError, OSError) as exc:
        lines.append(f"AgentsFence upkeep did not finish: {exc}")
    return lines
