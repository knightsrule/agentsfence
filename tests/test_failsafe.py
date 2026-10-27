"""Fail-closed loading: a missing or broken AgentsFence must block tools, never run unprotected."""

from __future__ import annotations

import ast
import json
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

from agentsfence import __version__, failsafe
from agentsfence import plugin as plugin_module


class Manager:
    def __init__(self) -> None:
        self._hooks: dict[str, list[Any]] = {}


class Ctx:
    """The PluginContext surface AgentsFence uses, with Hermes' hook-list layout."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self._manager = Manager()
        self.fail = fail or set()
        self.commands: dict[str, tuple[Any, Any]] = {}

    def register_hook(self, name: str, callback: Any) -> None:
        if name in self.fail:
            raise RuntimeError(f"cannot register {name}")
        self._manager._hooks.setdefault(name, []).append(callback)

    def register_cli_command(self, name: str, help: str, setup_fn: Any, handler_fn: Any = None, description: str = "") -> None:
        if "cli" in self.fail:
            raise RuntimeError("no CLI commands")
        self.commands[name] = (setup_fn, handler_fn)

    def register_command(self, *args: Any, **kwargs: Any) -> None:
        if "command" in self.fail:
            raise RuntimeError("no slash commands")

    def register_auxiliary_task(self, *args: Any, **kwargs: Any) -> None:
        if "aux" in self.fail:
            raise RuntimeError("no auxiliary tasks")

    def hooks(self, name: str) -> list[Any]:
        return self._manager._hooks.get(name, [])

    def decide(self, tool: str = "send_message") -> Any:
        """Hermes' resolution: any plugin's block wins over any approve, whatever the order."""
        results = [callback(tool_name=tool, args={}, session_id="s", task_id="s") for callback in self.hooks("pre_tool_call")]
        directives = [r for r in results if isinstance(r, dict) and r.get("action") in {"block", "approve"}]
        return next((r for r in directives if r["action"] == "block" and r.get("message")), directives[0] if directives else None)

    def status(self, *argv: str) -> dict[str, Any]:
        import argparse

        setup, handler = self.commands["agentsfence"]
        parser = argparse.ArgumentParser()
        setup(parser)
        return handler(parser.parse_args(list(argv)))  # type: ignore[no-any-return]


def approver(**_: Any) -> dict[str, str]:
    return {"action": "approve", "message": "approve-all plugin"}


def _answer(ctx: Ctx, capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, Any]:
    ctx.status(*argv)
    line = [x for x in capsys.readouterr().out.splitlines() if x.startswith(failsafe.STATUS_MARKER)][-1]
    return json.loads(line[len(failsafe.STATUS_MARKER):])  # type: ignore[no-any-return]


def test_missing_package_blocks_every_tool_ahead_of_an_earlier_approver(
        home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ctx = Ctx()
    ctx.register_hook("pre_tool_call", approver)  # an approve-all plugin loaded first

    def missing() -> Any:
        raise ModuleNotFoundError("No module named 'agentsfence'")

    failsafe.guarded_register(ctx, missing)
    decision = ctx.decide()
    assert decision["action"] == "block" and sys.executable in decision["message"]
    assert "No module named 'agentsfence'" in decision["message"]
    ctx.hooks("pre_tool_call").insert(0, lambda **_: {"action": "approve", "message": "loaded later"})
    assert ctx.decide()["action"] == "block"  # a block wins wherever it sits
    answer = _answer(ctx, capsys, "status", "--json")
    assert answer["outcome"] == "recovery_block" and answer["python"] == sys.executable
    record = json.loads(next((home / "af" / "load_status").glob("*.json")).read_text())
    assert record["outcome"] == "recovery_block"


def test_failure_after_partial_registration_still_blocks(home: Path) -> None:
    ctx = Ctx()
    marked = []
    fake = types.SimpleNamespace(
        register=lambda c: (c.register_hook("pre_tool_call", lambda **_: None), (_ for _ in ()).throw(RuntimeError("half way"))),
        registration_outcome=lambda: {"outcome": None}, mark_recovery=marked.append)
    failsafe.guarded_register(ctx, lambda: fake)
    assert ctx.decide()["action"] == "block"
    assert marked and "half way" in marked[0]


def test_internal_recovery_is_trusted_not_duplicated(home: Path) -> None:
    ctx = Ctx()
    fake = types.SimpleNamespace(register=lambda c: None,
                                 registration_outcome=lambda: {"outcome": "recovery_block", "recovery_installed": True})
    failsafe.guarded_register(ctx, lambda: fake)
    assert ctx.hooks("pre_tool_call") == []  # register() already installed its own block


def test_register_returning_without_enforcing_is_blocked(home: Path) -> None:
    ctx = Ctx()
    fake = types.SimpleNamespace(register=lambda c: None, registration_outcome=lambda: {"outcome": None})
    failsafe.guarded_register(ctx, lambda: fake)
    assert ctx.decide()["action"] == "block"


def test_diagnostic_failures_never_undo_the_block(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    blocked_path = home / "not-a-directory"
    blocked_path.write_text("x")
    monkeypatch.setenv("AGENTSFENCE_HOME", str(blocked_path))  # load-status writes fail
    ctx = Ctx(fail={"cli"})

    def missing() -> Any:
        raise ImportError("broken")

    failsafe.guarded_register(ctx, missing)
    assert ctx.decide()["action"] == "block"


def test_optional_registration_failures_keep_enforcement(home: Path) -> None:
    ctx = Ctx(fail={"aux", "command", "cli"})
    plugin_module.register(ctx)
    assert plugin_module.registration_outcome()["outcome"] == "enforcing"
    assert [cb.__name__ for cb in ctx.hooks("pre_tool_call")] == ["on_pre_tool_call"]


@pytest.mark.parametrize("hook", ["pre_llm_call", "post_tool_call", "on_session_finalize"])
def test_required_hook_failure_after_enforcement_enters_recovery(home: Path, capsys: pytest.CaptureFixture[str],
                                                                 hook: str) -> None:
    ctx = Ctx(fail={hook})
    ctx.register_hook("pre_tool_call", approver)
    plugin_module.register(ctx)  # returns normally after recovering
    outcome = plugin_module.registration_outcome()
    assert outcome["outcome"] == "recovery_block" and outcome["recovery_installed"]
    assert ctx.decide(tool="read_file")["action"] == "block"
    assert _answer(ctx, capsys, "status", "--json")["outcome"] == "recovery_block"
    assert failsafe.load_status_path().is_file()
    assert json.loads(failsafe.load_status_path().read_text())["outcome"] == "recovery_block"


def test_status_command_answers_for_its_own_process_only(home: Path, monkeypatch: pytest.MonkeyPatch,
                                                         capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsfence.host_client.call", lambda *a, **k: pytest.fail("status must never launch Hermes"))
    monkeypatch.setattr("agentsfence.host_client.status", lambda *a, **k: pytest.fail("status must never launch Hermes"))
    ctx = Ctx()
    plugin_module.register(ctx)
    answer = _answer(ctx, capsys, "status", "--json")
    assert answer["outcome"] == "enforcing" and answer["agentsfence_version"] == __version__
    assert Path(answer["hermes_home"]) == home / "hermes" and answer["schema"] == failsafe.STATUS_SCHEMA
    record = json.loads(failsafe.load_status_path(home / "af").read_text())
    assert record["outcome"] == "enforcing"  # a verified load supersedes an earlier failure record


def test_protect_writes_a_standard_library_fail_closed_loader(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    from agentsfence.profiles import loader_source, protect_profile

    monkeypatch.setattr("agentsfence.profiles.published_release", lambda: True)
    (home / "config.yaml").write_text("model: {provider: p, default: m}\n")
    protect_profile(home)
    loader = (home / "plugins/agentsfence/__init__.py").read_text()
    assert loader == loader_source() and f"EXPECTED_VERSION: str | None = {__version__!r}" in loader
    stdlib = set(sys.stdlib_module_names) | {"__future__", "hermes_cli", "hermes_constants"}
    imported = {alias.name.split(".")[0] for node in ast.walk(ast.parse(loader))
                if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names if isinstance(node, ast.Import)}
    imported |= {node.module.split(".")[0] for node in ast.walk(ast.parse(loader))
                 if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= stdlib, imported - stdlib  # works when the package is missing
    manifest = yaml.safe_load((home / "plugins/agentsfence/plugin.yaml").read_text())
    assert manifest["python_dependencies"] == [f"agentsfence=={__version__}"]


def test_an_unpublished_build_declares_no_dependency_hermes_cannot_resolve(home: Path) -> None:
    """Hermes' update disables a plugin whose declared pin no longer resolves, in every profile.
    This test environment is an editable install, so its version may not exist on any index."""
    import yaml

    from agentsfence.profiles import protect_profile, published_release

    assert not published_release()
    (home / "config.yaml").write_text("model: {provider: p, default: m}\n")
    protect_profile(home)
    assert "python_dependencies" not in yaml.safe_load((home / "plugins/agentsfence/plugin.yaml").read_text())


def test_status_broadcast_can_never_hold_a_turn_as_compiling(settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from conftest import start_task

    release = threading.Event()
    events = types.ModuleType("hermes_cli.plugin_events")
    events.broadcast_plugin_event = lambda *a, **k: release.wait(10)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.plugin_events", events)
    fence = plugin_module.AgentsFence(settings, persist=False, catalogue_fn=lambda: [], yolo_fn=lambda: False)
    started = time.monotonic()
    start_task(fence, "Read the report.")
    assert time.monotonic() - started < 5 and not fence._compiling
    release.set()


def test_block_message_repairs_with_this_interpreter_not_path(home: Path) -> None:
    """Review round 3 #1: a stale `agentsfence` on PATH would pin the loader to the wrong version."""
    ctx = Ctx()

    def missing() -> Any:
        raise ModuleNotFoundError("No module named 'agentsfence'")

    failsafe.guarded_register(ctx, missing)
    message = ctx.decide()["message"]
    assert f"`{sys.executable} -m agentsfence protect --all-profiles`" in message  # a checkout pins no version
    assert "then `agentsfence setup`" not in message


@pytest.mark.parametrize("managed", [False, True])
def test_loader_repairs_with_the_pinned_version_through_the_package_manager(
        home: Path, monkeypatch: pytest.MonkeyPatch, managed: bool) -> None:
    """Never `uv pip install` into Hermes' environment; a venv Hermes is told to update first."""
    monkeypatch.setattr(failsafe, "EXPECTED_VERSION", "9.9.9")
    prefix = "/h/installs/abc/environments/gen1/venv" if managed else "/h/hermes-agent/venv"
    monkeypatch.setattr(sys, "prefix", prefix)
    ctx = Ctx()

    def missing() -> Any:
        raise ModuleNotFoundError("No module named 'agentsfence'")

    failsafe.guarded_register(ctx, missing)
    message = ctx.decide()["message"]
    assert "`uvx --from 'agentsfence==9.9.9' agentsfence install`" in message
    assert ("hermes pm install" in message) is managed
    assert ("Run `hermes update`" in message) is not managed
    assert "uv pip install" not in message
