"""Regressions for the ten findings in the alpha.4 review."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLLM, start_task, tool, wait_task
from intent_fixtures import PolicyDraft
from rules_client import RulesClient

from agentsfence import diagnostics
from agentsfence.compiler import CompileContext, HermesLLMClient, PolicyCompiler
from agentsfence.compiler.interpret import IntentDraft, Prohibition
from agentsfence.config import Settings
from agentsfence.plugin import AgentsFence
from agentsfence.profiles import install_surfaces, protect_profile


def test_concurrent_compilation_status_keeps_every_active_session(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = settings.home / "runtime"
    directory.mkdir(parents=True)
    path = directory / f"{os.getpid()}.json"
    path.write_text(json.dumps({"version": "test-version", "compiling_sessions": []}))
    read = Path.read_text
    def delayed_read(self: Path, *args: Any, **kwargs: Any) -> str:
        value = read(self, *args, **kwargs)
        if self == path:
            time.sleep(.003)  # expose lost read/modify/write updates without serialization
        return value
    monkeypatch.setattr(Path, "read_text", delayed_read)
    sessions = [f"session-{i}" for i in range(24)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda sid: diagnostics.record_compilation_state(settings, sid, True), sessions))
    assert set(json.loads(path.read_text())["compiling_sessions"]) == set(sessions)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda sid: diagnostics.record_compilation_state(settings, sid, False), sessions[::2]))
    data = json.loads(path.read_text())
    assert set(data["compiling_sessions"]) == set(sessions[1::2]) and data["version"] == "test-version"
    path.unlink()
    diagnostics.record_compilation_state(settings, "absent", True)
    assert not path.exists()


def test_independent_chats_share_a_concurrent_compiler(settings: Settings) -> None:
    entered = threading.Barrier(3)
    release = threading.Event()

    class Together(RulesClient):
        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            entered.wait(5)
            assert release.wait(5)
            return super().complete(system, user, schema)

    fence = AgentsFence(settings, client=Together(), persist=False, yolo_fn=lambda: False)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fence.on_pre_llm_call, session_id=sid, task_id=sid,
                               user_message="Read the report. Do not write anything.") for sid in ("one", "two")]
        try:
            entered.wait(5)  # Both provider calls must start before either returns.
            assert set(fence._compiling) == {"one", "two"}
        finally:
            release.set()
        for future in futures:
            assert future.result(5)
    for sid in ("one", "two"):
        wait_task(fence, sid)
        record = fence.store.get(sid)
        assert record and record.policy.compiler_status == "verified"
        assert "LOCAL_WRITE" in record.policy.user_prohibitions


def test_hung_provider_keeps_one_slot_and_other_chats_work(settings: Settings) -> None:
    entered, release, done = threading.Event(), threading.Event(), threading.Event()
    calls: list[str] = []

    class OneHung(RulesClient):
        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            calls.append(user)
            if "hung" in user:
                entered.set()
                try:
                    assert release.wait(5)
                finally:
                    done.set()
            return super().complete(system, user, schema)

    settings.compiler.max_concurrent_requests = 2
    compiler = PolicyCompiler(settings, AgentsFence(settings, persist=False).classifier, OneHung())
    try:
        timed = compiler.compile("Read the hung report.", CompileContext(deadline=time.monotonic() + 0.05))
        assert entered.is_set() and timed.fell_back and not done.is_set()
        successful = compiler.compile("Read a different report.")
        assert not successful.fell_back and len(calls) == 2
    finally:
        release.set()
        assert done.wait(5)
    assert timed.policy.source == "fallback"


def test_same_chat_amendments_supersede_and_keep_both_prohibitions(settings: Settings) -> None:
    entered, queued, release = threading.Event(), threading.Event(), threading.Event()

    class FirstSlow(RulesClient):
        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            if "first report" in user:
                entered.set()
                assert release.wait(5)
            return super().complete(system, user, schema)

    fence = AgentsFence(settings, client=FirstSlow(), persist=False, yolo_fn=lambda: False)

    def observe(sid: str, active: bool) -> None:
        if fence._compiling.get(sid) == 2:
            queued.set()

    fence._record_compilation_state = observe  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(start_task, fence, "Read the first report. Do not send anything.")
        try:
            assert entered.wait(5)
            second = pool.submit(start_task, fence, "Read another report. Do not write anything.")
            assert queued.wait(5)
            decision = fence.check("read_file", {}, session_id="s1", deadline=time.monotonic() + .02)
            current = fence.store.get("s1")
            assert current
            assert decision.rule_id == "policy-compiling" or current.policy.pending_revision is None
        finally:
            release.set()
        assert first.result(5) and second.result(5)
    record = fence.store.get("s1")
    assert record and record.turns_seen == 2
    assert record.policy.prohibition_origins["COMMUNICATION"] == 1
    assert record.policy.prohibition_origins["LOCAL_WRITE"] == 2
    assert not fence._compiling and not fence._turn_locks


def test_full_compiler_pool_waits_without_spawning_workers(settings: Settings) -> None:
    entered, release = threading.Event(), threading.Event()
    calls = []

    class Busy(RulesClient):
        def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
            calls.append(user)
            entered.set()
            assert release.wait(5)
            return super().complete(system, user, schema)

    settings.compiler.max_concurrent_requests = 1
    compiler = PolicyCompiler(settings, AgentsFence(settings, persist=False).classifier, Busy())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(compiler.compile, "Read the first report.")
        try:
            assert entered.wait(5)
            exhausted = compiler.compile("Read a waiting report.", CompileContext(deadline=time.monotonic() + 0.05))
            assert exhausted.fell_back and "capacity exhausted" in str(exhausted.error)
            assert len(calls) == 1
            queued = pool.submit(compiler.compile, "Read the next report.")
        finally:
            release.set()
        assert not first.result(5).fell_back
        assert not queued.result(5).fell_back


def test_model_names_are_bound_to_concurrent_results(settings: Settings) -> None:
    barrier = threading.Barrier(2)

    class Host:  # Hermes 0.19.0 signature
        def complete(self, messages: Any, *, provider: str | None = None, model: str | None = None,
                     temperature: float | None = None, max_tokens: int | None = None, timeout: float | None = None,
                     agent_id: str | None = None, profile: str | None = None, purpose: str | None = None) -> Any:
            model = "alpha" if "Alpha" in messages[-1]["content"] else "beta"
            barrier.wait(5)
            return types.SimpleNamespace(text=PolicyDraft(purpose=model).model_dump_json(), provider="configured", model=model)

    compiler = PolicyCompiler(settings, AgentsFence(settings, persist=False).classifier, HermesLLMClient(Host(), 30))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(compiler.compile, text) for text in ("Read Alpha.", "Read Beta.")]
        assert [r.result(5).policy.compiler_model for r in results] == ["hermes:configured:alpha", "hermes:configured:beta"]


def test_later_model_prohibitions_keep_their_real_origin(settings: Settings) -> None:
    response = IntentDraft(interpretation=[], grants=[], prohibitions=[Prohibition(capability="email.read", span="Don't read my inbox.")])
    fence = AgentsFence(settings, client=FakeLLM(responses={"Don't read": response}),
                        persist=False, yolo_fn=lambda: False, gateway_fn=lambda: False)
    start_task(fence, "Read my inbox.")
    start_task(fence, "Don't read my inbox. Do not send anything.")
    blocked = tool(fence, "mcp_gmail_get_message", {"id": "example"})
    assert blocked and "turn 2" in blocked["message"] and "earlier turn 1" not in blocked["message"]
    assert "email.read (turn 2)" in fence.slash_command()
    start_task(fence, "Don't read my inbox. Do not send anything.")
    record = fence.store.get("s1")
    assert record and record.policy.prohibition_origins["email.read"] == 2


@pytest.mark.parametrize("failure", [RuntimeError("changed API"), "invalid", float("nan"), float("inf")])
def test_timeout_adapter_failures_still_install_policy(settings: Settings, monkeypatch: pytest.MonkeyPatch, failure: Any) -> None:
    host = types.ModuleType("hermes_cli.plugins")

    def timeout() -> Any:
        if isinstance(failure, Exception):
            raise failure
        return failure

    host._resolve_hook_callback_timeout = timeout  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", host)
    fence = AgentsFence(settings, client=RulesClient(), persist=False, yolo_fn=lambda: False)
    start_task(fence, "Read the report. Do not write anything.")
    record = fence.store.get("s1")
    assert record and record.policy.compiler_status == "verified" and "LOCAL_WRITE" in record.policy.user_prohibitions


def test_nested_children_are_audited_under_the_parent_session(settings: Settings, tmp_path: Path) -> None:
    fence = AgentsFence(settings, client=RulesClient(), persist=True, yolo_fn=lambda: False)
    start_task(fence, "Read the report. Do not write anything.", session="parent")
    fence.on_subagent_start(child_session_id="child", parent_session_id="parent")
    fence.on_subagent_start(child_session_id="grandchild", parent_session_id="child")
    fence._compiling["parent"] = 1
    blocked = tool(fence, "write_file", {"path": str(tmp_path / "kit/canary-1-write.txt"), "content": "x"}, session="grandchild")
    assert blocked and blocked["action"] == "block"
    rows = [json.loads(line) for line in (settings.home / "audit.jsonl").read_text().splitlines()]
    assert rows[-1]["session_id"] == "parent" and rows[-1]["details"]["source_session_id"] == "grandchild"
    assert diagnostics.audit_rows(Path(os.environ["HERMES_HOME"]), session="parent")


def test_protect_preserves_checkout_files(settings: Settings, tmp_path: Path) -> None:
    home = tmp_path / "profile"
    home.mkdir()
    (home / "config.yaml").write_text("model: {default: configured}\n")
    target = home / "plugins/agentsfence"
    (target / "agentsfence").mkdir(parents=True)
    (target / ".git").write_text("gitdir: /some/worktree\n")
    files = {"plugin.yaml":"name: agentsfence\nauthor: Keep me\n", "__init__.py":"# own shim\n",
             "desktop/plugin.js":"// own UI\n", "dashboard/plugin_api.py":"# own API\n"}
    for name, contents in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    protect_profile(home)
    assert all((target / name).read_text() == contents for name, contents in files.items())
    assert not (target / ".agentsfence-install.json").exists()


@pytest.mark.parametrize("yolo,default,expected", [(True,"manual","off"), (False,"smart","smart"), (False,None,"unknown")])
def test_status_reports_hermes_effective_approval_mode(settings: Settings, monkeypatch: pytest.MonkeyPatch,
                                                      yolo: bool, default: str | None, expected: str) -> None:
    config = types.ModuleType("hermes_cli.config")
    config.load_config = lambda: {}  # type: ignore[attr-defined]
    config.DEFAULT_CONFIG = {"approvals": {"mode": default}}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
    monkeypatch.delitem(sys.modules, "tools.approval", raising=False)
    monkeypatch.setenv("HERMES_YOLO_MODE", "1" if yolo else "0")
    status = diagnostics.snapshot()
    assert status["approval_mode"] == expected and status["human_approval"] is (expected in {"manual", "ask"})


def test_directory_code_and_api_ignore_installed_package(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    fake = tmp_path / "installed/agentsfence"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("__version__ = 'old-installed'\n")
    (fake / "plugin.py").write_text("def register(ctx): raise RuntimeError('old package')\n")
    code = """
import importlib.util, sys, agentsfence
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('checkout_plugin', root / '__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
class Ctx:
    def register_hook(self, name, callback): pass
module.register(Ctx())  # the fail-closed wrapper runs the checkout's implementation
implementation = sys.modules[spec.name + '.agentsfence.plugin']
assert Path(implementation.__file__).resolve() == root / 'agentsfence/plugin.py'
assert implementation.registration_outcome()['outcome'] == 'enforcing'
assert agentsfence.__version__ == 'old-installed'
api_spec = importlib.util.spec_from_file_location('checkout_dashboard', root / 'dashboard/plugin_api.py')
api = importlib.util.module_from_spec(api_spec)
sys.modules[api_spec.name] = api
api_spec.loader.exec_module(api)
own_api = sys.modules[implementation.__package__ + '.desktop_api']
assert api.router is own_api.router
print('checkout code and API share their own package')
"""
    result = subprocess.run([sys.executable, "-c", code, str(root)], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(fake.parent), "HERMES_HOME": str(tmp_path / "hermes"),
                                 "AGENTSFENCE_HOME": str(tmp_path / "af")}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_incremental_status_index_handles_append_rotation_and_partial_lines(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    audit = settings.home / "audit.jsonl"
    audit.parent.mkdir(parents=True)
    initial = {"event":"policy_compiled", "session_id":"one", "details":{"fell_back":False}}
    audit.write_text(json.dumps(initial) + "\n")
    assert diagnostics.snapshot(session="one")["last_compilation"] == initial
    with monkeypatch.context() as context:
        context.setattr(diagnostics.json, "loads", lambda value: pytest.fail("Unchanged audit must not be reparsed"))
        assert diagnostics.snapshot(session="one")["audit"] == [initial]
    new = {"event":"policy_amended", "session_id":"one", "details":{"fell_back":True}}
    with audit.open("a") as stream:
        stream.write(json.dumps(new))
    assert diagnostics.snapshot(session="one")["last_compilation"] == initial
    with audit.open("a") as stream:
        stream.write("\n")
    assert diagnostics.snapshot(session="one")["last_compilation"] == new
    audit.rename(audit.with_suffix(".old"))
    audit.write_text(json.dumps(initial) + "\n")
    assert diagnostics.snapshot(session="one")["audit"] == [initial]
    audit.write_text('{}\n')
    assert diagnostics.snapshot(session="one")["last_compilation"] is None


def test_desktop_status_does_not_probe_foreign_processes_each_poll(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    home = Path(os.environ["HERMES_HOME"])
    home.mkdir()
    (home / "config.yaml").write_text("plugins: {enabled: [agentsfence]}\n")
    runtime = settings.home / "runtime"
    runtime.mkdir(parents=True)
    digest = diagnostics.configuration_digest(home)
    from agentsfence import __version__

    for pid in (os.getpid(), 999999):
        (runtime / f"{pid}.json").write_text(json.dumps({"pid":pid, "process_start":"same", "configuration":digest, "version":__version__}))
    calls = []
    monkeypatch.setattr(diagnostics, "_read_process_identity", lambda pid: calls.append(pid) or "same")
    diagnostics._current_process_identity.cache_clear()
    for _ in range(2):
        assert diagnostics.snapshot(runtime_verified=True)["state"] == "ready"
    assert calls == [os.getpid()]
    diagnostics.runtime_status(home, settings)
    assert calls == [os.getpid(), 999999]
    diagnostics._current_process_identity.cache_clear()


def test_wheel_style_install_materializes_canonical_assets(settings: Settings, tmp_path: Path) -> None:
    install_surfaces(tmp_path)
    root = Path(__file__).resolve().parents[1]
    for name in ("desktop/plugin.js", "dashboard/plugin_api.py", "dashboard/manifest.json"):
        assert (tmp_path / "plugins/agentsfence" / name).read_bytes() == (root / name).read_bytes()
