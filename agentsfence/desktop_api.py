"""Operator UI routes, mounted behind Hermes authentication and profile scoping.

The Desktop pane uses the same operations as the CLI (``lifecycle``): protect,
unprotect and settings are transactions with preflight and rollback, and the
scenario test runs through ``hermes -p NAME agentsfence probe test``.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .config import hermes_home, load_settings
from .diagnostics import snapshot, unreadable_snapshot
from .host_probe import probe_compiler, run_probe
from .lifecycle import LifecycleError
from .plugin import REGISTRATION, get_instance
from .profiles import (
    available_profiles,
    compiler_route,
    model_choices,
    profile_name,
    read_config,
    read_state,
    resolve_profile,
)
from .testkit.progress import Runs

router = APIRouter()
_SWEEP = threading.Lock()
_TEST_RUNS = Runs()


def _hook_verified(home: Path) -> bool | None:
    """This backend's own enforcement state; None for another profile's processes."""
    if home != hermes_home():
        return None
    return bool(get_instance() is not None and REGISTRATION.get("outcome") == "enforcing")


def _this_backend() -> dict[str, Any]:
    """This backend's own registration outcome, in the launcher-status shape (no subprocess)."""
    from .plugin import host_status

    return {**host_status(), "reachable": True}


def _background_sweep() -> None:
    """Pane opened: finish upkeep (and protect new profiles, if turned on) without holding the request."""
    if not _SWEEP.acquire(blocking=False):
        return

    from .profiles import root_home

    requested_root = root_home()

    def work() -> None:
        try:
            if root_home() != requested_root:
                return
            from .lifecycle import sweep

            sweep()
        finally:
            _SWEEP.release()

    threading.Thread(target=work, name="agentsfence-sweep", daemon=True).start()


def _fail(exc: Exception) -> HTTPException:
    return HTTPException(400, str(exc))


@router.get("/status")
def status(session_id: str | None = None) -> dict[str, Any]:
    try:
        data = snapshot(session=session_id, runtime_verified=_hook_verified(hermes_home()), host=_this_backend())
    except (ValueError, OSError) as exc:
        return unreadable_snapshot(hermes_home(), exc)
    if data["checks"]["load"]["status"] == "problem" and _this_backend()["outcome"] == "recovery_block":
        data.update(state="blocked", guidance=data["checks"]["load"]["message"])
    return data


@router.get("/profiles")
def profiles() -> dict[str, Any]:
    _background_sweep()
    rows = []
    for name, home in available_profiles().items():
        try:
            data = snapshot(home, runtime_verified=_hook_verified(home),
                            host=_this_backend() if home == hermes_home() else None)
            settings = load_settings(hermes_dir=home)
            route = compiler_route(read_config(home))
        except Exception as exc:  # one unreadable profile must not hide the others
            bad = unreadable_snapshot(home, exc)
            rows.append({"name": name, "state": bad["state"], "protected": False, "error": bad["error"], "models": [],
                         "compiler": bad["compiler"]})
            continue
        rows.append({"name": name, "state": data["state"], "protected": data["enabled"], "overall": data["overall"],
                     "models": model_choices(home), "compiler": data["compiler"],
                     "settings": {"mode": settings.compiler.mode, "model": route.get("model") or "",
                                  "provider": route.get("provider") or "auto",
                                  "compile_budget": settings.compiler.timeout_seconds,
                                  "strict_yolo": settings.evaluation.strict_yolo,
                                  "retention_days": settings.audit.retention_days}})
    state = read_state()
    return {"profiles": rows, "include_new": state["include_new"], "installed_version": state["version"]}


class ProfilesRequest(BaseModel):
    profiles: list[str] = Field(min_length=1)
    include_new: bool | None = None


@router.post("/protect")
def protect(body: ProfilesRequest) -> dict[str, Any]:
    from .lifecycle import protect as run

    try:
        report = run(body.profiles, include_new=body.include_new)
    except (LifecycleError, ValueError, OSError) as exc:
        raise _fail(exc) from exc
    return {"lines": report["lines"], "profiles": report["profiles"], "restart": _restart_needed(report["profiles"])}


@router.post("/unprotect")
def unprotect(body: ProfilesRequest) -> dict[str, Any]:
    from .lifecycle import unprotect as run

    try:
        report = run(body.profiles)
    except (LifecycleError, ValueError, OSError) as exc:
        raise _fail(exc) from exc
    return {"lines": report["lines"], "profiles": report["profiles"], "restart": _restart_needed(report["profiles"])}


class IncludeNewRequest(BaseModel):
    include_new: bool


@router.post("/include-new")
def include_new(body: IncludeNewRequest) -> dict[str, Any]:
    from .lifecycle import set_include_new

    try:
        set_include_new(body.include_new)
    except LifecycleError as exc:
        raise _fail(exc) from exc
    if body.include_new:
        _background_sweep()
    return {"include_new": body.include_new}


class SettingsRequest(BaseModel):
    apply_to_all_profiles: bool = False
    profile: str | None = None
    mode: str | None = None
    model: str | None = None
    provider: str | None = None
    compile_budget: float | None = None
    strict_yolo: bool | None = None
    retention_days: int | None = None


@router.post("/settings")
def settings(body: SettingsRequest) -> dict[str, Any]:
    from .lifecycle import update_settings

    try:
        report = update_settings(mode=body.mode, model=body.model, provider=body.provider, compile_budget=body.compile_budget,
                                 strict_yolo=body.strict_yolo, retention_days=body.retention_days, profile=body.profile,
                                 apply_to_all_profiles=body.apply_to_all_profiles)
    except (LifecycleError, ValueError, OSError) as exc:
        raise _fail(exc) from exc
    return {"lines": report["lines"], "probes": report.get("probes", {})}


def _restart_needed(names: list[str]) -> list[str]:
    """Profiles whose running Hermes processes started before the change and must restart to pick it up."""
    found = available_profiles()
    out = []
    for name in names:
        try:
            if snapshot(found[name]).get("state") == "restart_required":
                out.append(name)
        except Exception:
            continue
    return out


@router.post("/probe")
def probe() -> dict[str, Any]:
    fence = get_instance()
    return probe_compiler(fence) if fence else run_probe(hermes_home())


class CheckRequest(BaseModel):
    profile: str | None = None


@router.post("/check")
def check_profile(body: CheckRequest) -> dict[str, Any]:
    """One guided check: verify activation before spending a model call."""
    try:
        home = resolve_profile(body.profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    current = home == hermes_home()
    fence = get_instance() if current else None
    try:
        data = snapshot(home, runtime_verified=_hook_verified(home), host=_this_backend() if current else None)
    except (ValueError, OSError) as exc:
        data = unreadable_snapshot(home, exc)
    result: dict[str, Any] = {"profile": profile_name(home), "ok": False, "stage": "activation", "state": data["state"]}
    load = (data.get("checks") or {}).get("load") or {}
    if data.get("error") or load.get("status") == "problem" or data["state"] in {"inactive", "restart_required", "compiling"}:
        result["message"] = load.get("message") if load.get("status") == "problem" else data["guidance"]
        return result
    compiler = probe_compiler(fence) if fence else run_probe(home)
    result.update(ok=bool(compiler.get("ok")), stage="compiler",
                  message=("Plugin loaded and compiler check passed." + (f" {compiler['warning']}" if compiler.get("warning") else ""))
                  if compiler.get("ok") else compiler.get("error") or "The compiler check failed.")
    return result


@router.post("/preflight")
def preflight() -> dict[str, Any]:
    from .lifecycle import run_preflight

    return run_preflight()


@router.get("/models")
def models(profile: str | None = None) -> dict[str, Any]:
    """The chat model the live test would use, and its projected cost."""
    try:
        home = resolve_profile(profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return run_probe(home, "models")


class TestRequest(BaseModel):
    run_id: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    profile: str | None = None
    scenarios: list[str] = Field(default_factory=list)
    include_probes: bool = False
    live: bool = False
    model: str | None = None
    provider: str | None = None
    accept_cost: bool = False


@router.post("/test")
def test(body: TestRequest) -> dict[str, Any]:
    """Run the scenarios in a profile: an optional live model run, then the deterministic run."""
    from .testkit.harness import format_report
    from .testkit.live import run_test
    from .testkit.scenarios import select

    try:
        home = resolve_profile(body.profile)
        chosen = select(body.scenarios or None, include_probes=body.include_probes)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    progress = None
    if body.run_id:
        try:
            progress = _TEST_RUNS.begin(body.run_id, home)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
    try:
        result = run_test(home, chosen, live=body.live, model=body.model, provider=body.provider, accept_cost=body.accept_cost,
                          all_probes=body.include_probes, selected=body.scenarios, progress=progress)
        if not result.get("needs_confirmation"):
            result["report"] = format_report(result)
        if body.run_id:
            _TEST_RUNS.finish(body.run_id, "confirmation" if result.get("needs_confirmation") else "finished")
        return result
    except BaseException:
        if body.run_id:
            _TEST_RUNS.finish(body.run_id, "failed")
        raise


@router.get("/test-progress/{run_id}")
def test_progress(run_id: str, profile: str | None = None) -> dict[str, Any]:
    try:
        home = resolve_profile(profile)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    progress = _TEST_RUNS.read(run_id, home)
    if progress is None:
        raise HTTPException(404, "No test progress for this profile and run.")
    return progress
