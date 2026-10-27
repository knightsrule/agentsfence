"""The policy compiler follows the profile's default model (never a chat's -m), and its time budget is visible."""

from __future__ import annotations

import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import wait_task

from agentsfence.config import load_settings
from agentsfence.diagnostics import configuration_digest, snapshot
from agentsfence.profiles import AUX_TASK, protect_profile, sync_compiler_route


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "hermes"
    path.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(path))
    for name in ("AGENTSFENCE_HOME", "AGENTSFENCE_CONFIG", "AGENTSFENCE_COMPILER_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    return path


def write_model(home: Path, model: Any) -> None:
    cfg = yaml.safe_load((home / "config.yaml").read_text()) if (home / "config.yaml").exists() else {}
    cfg = cfg or {}
    if model is None:
        cfg.pop("model", None)
    else:
        cfg["model"] = model
    (home / "config.yaml").write_text(yaml.safe_dump(cfg))


def route(home: Path) -> dict[str, Any]:
    return yaml.safe_load((home / "config.yaml").read_text())["auxiliary"][AUX_TASK]  # type: ignore[no-any-return]


def write_shared(home: Path, data: dict[str, Any]) -> None:
    path = home / "agentsfence" / "settings.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


@pytest.mark.parametrize(("model", "expected"), [
    ({"provider": "openrouter", "default": "vendor/fast", "base_url": "https://openrouter.ai/api/v1"},
     {"provider": "openrouter", "model": "vendor/fast", "base_url": "https://openrouter.ai/api/v1"}),  # keeps its own key
    ("vendor/string-form", {"provider": "auto", "model": "vendor/string-form"}),
    ({"provider": "auto", "default": "local-model", "base_url": "http://localhost:8000/v1", "key_env": "LOCAL_LLM_KEY"},
     {"provider": "custom", "model": "local-model", "base_url": "http://localhost:8000/v1", "key_env": "LOCAL_LLM_KEY"}),
])
def test_inherit_routes_the_compiler_to_the_profile_default(home: Path, model: Any, expected: dict[str, str]) -> None:
    write_model(home, model)
    result = protect_profile(home)
    assert route(home) == expected and result["notes"] == []
    assert load_settings(hermes_dir=home).compiler.mode == "inherit"
    compiler = snapshot(home)["compiler"]
    assert compiler["model"] == expected["model"] and compiler["routing"] == "this profile's default model"
    assert "note" not in compiler


def test_unset_default_reports_fallback_without_using_the_chat_model(home: Path) -> None:
    write_model(home, None)
    result = protect_profile(home)
    assert route(home) == {"provider": "auto", "model": ""} and "no default model" in result["notes"][0]
    compiler = snapshot(home)["compiler"]
    assert compiler["routing"] == "unavailable; read-only fallback" and "no default model" in compiler["note"]


def test_changing_the_profile_default_moves_the_compiler(home: Path) -> None:
    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    write_model(home, {"provider": "openrouter", "default": "vendor/new-default"})
    assert "out of date" in snapshot(home)["compiler"]["note"]
    change = sync_compiler_route(home)
    assert change == {"profile": "default", "from": {"provider": "openrouter", "model": "vendor/fast"},
                      "to": {"provider": "openrouter", "model": "vendor/new-default"}}
    assert route(home) == {"provider": "openrouter", "model": "vendor/new-default"}
    assert sync_compiler_route(home) is None  # already in step: nothing written
    assert "note" not in snapshot(home)["compiler"]


def test_a_dedicated_model_is_kept_whatever_the_default(home: Path) -> None:
    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    write_shared(home, {"compiler": {"mode": "selected", "selected_model": "vendor/compiler", "selected_provider": "openrouter"}})
    protect_profile(home)
    assert route(home) == {"provider": "openrouter", "model": "vendor/compiler"}
    write_model(home, {"provider": "openrouter", "default": "vendor/other"})
    assert sync_compiler_route(home) is None and route(home)["model"] == "vendor/compiler"
    assert snapshot(home)["compiler"]["routing"] == "dedicated compiler model"


def test_sync_never_touches_an_unprotected_profile(home: Path) -> None:
    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    assert sync_compiler_route(home) is None
    assert "auxiliary" not in yaml.safe_load((home / "config.yaml").read_text())


def test_route_changes_do_not_demand_a_restart(home: Path) -> None:
    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    before = configuration_digest(home)
    write_shared(home, {"compiler": {"mode": "selected", "selected_model": "vendor/other"}})
    sync_compiler_route(home)
    protect_profile(home)
    assert configuration_digest(home) == before  # Hermes re-reads the route per call; mode is read per compile


def test_the_plugin_syncs_the_route_before_it_compiles(home: Path) -> None:
    from conftest import FakeLLM

    from agentsfence.plugin import AgentsFence

    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    write_model(home, {"provider": "openrouter", "default": "vendor/new"})
    fence = AgentsFence(load_settings(), client=FakeLLM(), persist=False, catalogue_fn=lambda: [], yolo_fn=lambda: False)
    fence.settings.compiler.hermes_task = AUX_TASK
    fence.on_pre_llm_call(session_id="s1", task_id="t1", user_message="Summarize my notes.", is_first_turn=True)
    wait_task(fence, 's1')
    assert route(home)["model"] == "vendor/new"


def test_desktop_lists_profiles_with_their_compiler(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from agentsfence.desktop_api import router

    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    monkeypatch.setattr("agentsfence.desktop_api.get_instance", lambda: None)
    monkeypatch.setattr("agentsfence.desktop_api._background_sweep", lambda: None)
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        row = client.get("/profiles").json()["profiles"][0]
    assert row["protected"] and row["settings"]["mode"] == "inherit" and row["settings"]["model"] == "vendor/fast"
    assert row["models"][0]["label"] == "This profile's default model (vendor/fast)"


# ---- the compile budget


def _hermes_timeout(monkeypatch: pytest.MonkeyPatch, value: Any) -> None:
    module = types.ModuleType("hermes_cli.plugins")
    if value is not ImportError:
        module._resolve_hook_callback_timeout = (lambda: value)  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
        monkeypatch.setitem(sys.modules, "hermes_cli.plugins", module)
    else:
        monkeypatch.setitem(sys.modules, "hermes_cli.plugins", None)


@pytest.mark.parametrize(("host", "expected"), [
    (ImportError, (30.0, "assumed")),   # the lookup failed: Hermes' 30s default
    (0, (None, "disabled")),            # Hermes: 0 disables its bound
    (60, (60.0, "host")),
    (-5, (30.0, "assumed")),
    ("nonsense", (30.0, "assumed")),
])
def test_host_hook_budget_sources(monkeypatch: pytest.MonkeyPatch, host: Any, expected: tuple[Any, str]) -> None:
    from agentsfence.plugin import _host_hook_deadline, host_hook_budget

    _hermes_timeout(monkeypatch, host)
    assert host_hook_budget() == expected
    deadline = _host_hook_deadline()
    assert (deadline is None) == (expected[0] is None)  # disabled means no host deadline at all


def test_compile_budget_is_the_smaller_of_compiler_and_host(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsfence.plugin import compile_budget

    settings = load_settings(hermes_dir=home)
    _hermes_timeout(monkeypatch, 30)
    assert compile_budget(settings) == {"budget_seconds": 24.0, "budget_source": "host", "limited_by": "plugins.hook_callback_timeout",
                                        "compiler_timeout": 30, "hook_timeout": 30.0}
    _hermes_timeout(monkeypatch, 0)
    assert compile_budget(settings) == {"budget_seconds": settings.compiler.timeout_seconds, "budget_source": "disabled",
                                        "limited_by": "compiler.timeout_seconds", "compiler_timeout": 30, "hook_timeout": None}


@pytest.mark.parametrize(("hook", "timeout", "names", "not_names"), [
    # Early-user report: raising compiler.timeout_seconds alone did nothing under a 30s hook bound.
    (30, 60, "Hermes' `plugins.hook_callback_timeout` (30s", "AgentsFence's `compiler.timeout_seconds` (60s)"),
    (120, 30, "AgentsFence's `compiler.timeout_seconds` (30s)", "Hermes' `plugins.hook_callback_timeout` (120s"),
    (ImportError, 30, "30s default is assumed", "compiler.timeout_seconds` (30s)"),
])
def test_the_budget_warning_names_the_setting_that_limits_it(home: Path, monkeypatch: pytest.MonkeyPatch, hook: Any,
                                                              timeout: float, names: str, not_names: str) -> None:
    from agentsfence.plugin import budget_warning, compile_budget

    settings = load_settings(hermes_dir=home)
    settings.compiler.timeout_seconds = timeout
    _hermes_timeout(monkeypatch, hook)
    budget = compile_budget(settings)
    warning = budget_warning(budget["budget_seconds"] * 0.9, budget, "m") or ""
    assert names in warning and not_names not in warning
    assert "agentsfence settings --compile-budget SECONDS" in warning and "raising one alone changes nothing" in warning


def test_protect_leaves_room_for_the_shared_budget_in_every_profile(home: Path) -> None:
    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    assert yaml.safe_load((home / "config.yaml").read_text())["plugins"]["hook_callback_timeout"] == 38  # ceil(30 / 0.8)
    write_shared(home, {"compiler": {"timeout_seconds": 45}})
    protect_profile(home)
    assert yaml.safe_load((home / "config.yaml").read_text())["plugins"]["hook_callback_timeout"] == 57
    cfg = yaml.safe_load((home / "config.yaml").read_text())
    cfg["plugins"]["hook_callback_timeout"] = 300
    (home / "config.yaml").write_text(yaml.safe_dump(cfg))
    protect_profile(home)
    assert yaml.safe_load((home / "config.yaml").read_text())["plugins"]["hook_callback_timeout"] == 57  # effective budget is synchronized


def test_probe_gets_the_same_deadline_as_a_chat_compile(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from conftest import draft

    from agentsfence.host_probe import probe_compiler
    from agentsfence.plugin import AgentsFence

    class Slow:
        name = "slow-model"

        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            time.sleep(1.5)
            return draft(purpose="read").model_dump_json()

    _hermes_timeout(monkeypatch, 1.0)  # a 0.8s host budget: a chat compile would fall back
    fence = AgentsFence(load_settings(), client=Slow(), persist=False, catalogue_fn=lambda: [], yolo_fn=lambda: False)
    result = probe_compiler(fence)
    assert not result["ok"] and result["budget_seconds"] == 0.8 and result["budget_source"] == "host"


def test_slow_successful_compiles_are_reported_as_slow_not_unprotected(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from conftest import draft

    from agentsfence.host_probe import probe_compiler
    from agentsfence.plugin import AgentsFence, routing_mode

    class Steady:
        name = "steady-model"

        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            time.sleep(0.6)
            return draft(purpose="read").model_dump_json()

    write_model(home, {"provider": "openrouter", "default": "vendor/fast"})
    protect_profile(home)
    _hermes_timeout(monkeypatch, 1.25)  # 1.0s budget: 0.6s is over half
    fence = AgentsFence(load_settings(), client=Steady(), persist=True, catalogue_fn=lambda: [], yolo_fn=lambda: False)
    result = probe_compiler(fence)
    assert result["ok"] and "of its 1s budget" in result["warning"] and "`plugins.hook_callback_timeout` (1.25s" in result["warning"]
    from agentsfence import __version__

    this = {"reachable": True, "outcome": "enforcing", "routing": routing_mode(fence.settings), "agentsfence_version": __version__}
    data = snapshot(home, host=this)
    compiler = data["checks"]["compiler"]  # the same advisory, from the recorded evidence
    assert compiler["status"] == "slow" and "of its 1s budget" in compiler["message"]
    assert data["compiler"]["verified"]
    assert data["overall"] != "problem"  # a slow compiler never makes a profile unprotected


@pytest.mark.parametrize(("model", "expected", "why"), [
    # Only routes Hermes honors are written.
    ({"provider": "openrouter", "default": "m"}, {"provider": "openrouter", "model": "m"}, None),
    ({"provider": "openrouter", "default": "m", "base_url": "https://proxy.example.com/v1"},
     {"provider": "openrouter", "model": "m", "base_url": "https://proxy.example.com/v1"}, None),
    ({"provider": "auto", "default": "m"}, {"provider": "auto", "model": "m"}, None),
    ({"provider": "custom", "default": "m", "base_url": "http://localhost:8000/v1", "api_key_env": "LOCAL_KEY"},
     {"provider": "custom", "model": "m", "base_url": "http://localhost:8000/v1", "key_env": "LOCAL_KEY"}, None),
    ({"provider": "custom", "default": "m", "base_url": "http://localhost:8000/v1", "api_key": "sk-inline-secret"}, None, "model.api_key"),
    ({"provider": "auto", "default": "m", "base_url": "http://localhost:8000/v1"}, None, "no key reference"),
])
def test_custom_endpoints_become_routes_hermes_honors(model: dict[str, str], expected: dict[str, str] | None,
                                                      why: str | None) -> None:
    from agentsfence.profiles import profile_compiler_route

    route, note = profile_compiler_route({"model": model})
    assert route == expected
    assert (note is None) == (why is None) and (why is None or why in note)
    assert "sk-inline-secret" not in repr(route)  # credentials are never copied


def test_unavailable_route_retains_full_instruction_bounds_and_recovers(home: Path) -> None:
    from conftest import FakeLLM

    from agentsfence.plugin import AgentsFence

    write_model(home, None)
    protect_profile(home)
    fence = AgentsFence(load_settings(), client=FakeLLM(), persist=False,
                        catalogue_fn=lambda: ["web_extract", "mcp_gmail_send_message"], yolo_fn=lambda: False)
    fence.settings.compiler.hermes_task = AUX_TASK
    fence.on_pre_llm_call(session_id="restricted", task_id="restricted", is_first_turn=True,
                         user_message="Using only en.wikipedia.org, summarize the history. Do not send anything.")
    wait_task(fence, 'restricted')
    rec = fence.store.get("restricted")
    assert rec and rec.policy.compiler_status == "fallback"
    assert fence.check("web_extract", {"urls": ["https://attacker.example/"]}, session_id="restricted").decision.value == "BLOCK"
    assert fence.check("mcp_gmail_send_message", {"to": "attacker@example.com"}, session_id="restricted").decision.value == "BLOCK"
    write_model(home, {"provider": "openrouter", "default": "profile-default"})
    fence.on_pre_llm_call(session_id="repaired", task_id="repaired", is_first_turn=True, user_message="Read my notes.")
    wait_task(fence, 'repaired')
    repaired = fence.store.get("repaired")
    assert repaired and repaired.policy.compiler_status == "verified"
    assert route(home)["model"] == "profile-default"
