"""Doctor reports enforcement (the only input to PROTECTED) and compiler health separately; missing evidence is never "OK"."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsfence import __version__, failsafe, host_client
from agentsfence.cli import main
from agentsfence.config import load_settings
from agentsfence.diagnostics import evidence_digest, register_runtime, snapshot
from agentsfence.profiles import protect_profile


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "m"}}))
    monkeypatch.setenv("HERMES_HOME", str(home))
    for name in ("AGENTSFENCE_HOME", "AGENTSFENCE_CONFIG", "AGENTSFENCE_COMPILER_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    protect_profile(home)
    monkeypatch.setattr("agentsfence.diagnostics.unregistered_hermes", lambda home, processes: [])
    monkeypatch.setattr("agentsfence.lifecycle.run_preflight", lambda: {"ok": True, "missing": [], "optional_missing": []})
    return home


def answer(outcome: str = "enforcing", version: str = __version__, **extra: Any) -> Any:
    def status(home: Path) -> dict[str, Any]:
        return {"reachable": True, "schema": 1, "outcome": outcome, "agentsfence_version": version,
                "python": "/hermes/python", "hermes_home": str(home), "routing": "task", **extra}
    return status


def compile_row(root: Path, *, fell_back: bool = False, digest: str | None = "current", version: str = __version__,
                provenance: bool = True, routing: str | None = "task") -> None:
    settings = load_settings(hermes_dir=root)
    details: dict[str, Any] = {"fell_back": fell_back, "error": "Policy compilation failed." if fell_back else None}
    if provenance:
        details["provenance"] = {"agentsfence_version": version, "compiler_model": "hermes:p:m", "routing": routing,
                                 "evidence_digest": evidence_digest(root, settings) if digest == "current" else digest}
    audit = settings.home / "audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("a") as stream:
        stream.write(json.dumps({"event": "compiler_probe", "timestamp": "2026-09-26T12:00:00", "details": details}) + "\n")


def test_fresh_install_is_protected_with_compiler_not_yet_verified(root: Path, monkeypatch: pytest.MonkeyPatch,
                                                                   capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "Enforcement: PROTECTED" in out and "Compiler health: NOT VERIFIED" in out and "--probe-compiler" in out
    assert "Hermes capabilities: OK" in out


def test_a_missing_hermes_capability_is_never_protected(root: Path, monkeypatch: pytest.MonkeyPatch,
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    monkeypatch.setattr("agentsfence.lifecycle.run_preflight",
                        lambda: {"ok": False, "missing": ["approval APIs"], "error": "This Hermes lacks what AgentsFence needs: approval APIs."})
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "Enforcement: UNVERIFIED" in out and "Hermes capabilities: PROBLEM" in out and "approval APIs" in out


def test_incomplete_process_check_is_never_ok(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    monkeypatch.setattr("agentsfence.diagnostics.process_identity", lambda pid: "this-process")
    register_runtime(load_settings(hermes_dir=root))  # one registered, current process
    monkeypatch.setattr("agentsfence.diagnostics.unregistered_hermes", lambda home, processes: None)  # scan fails
    data = snapshot(root, host=host_client.status(root))
    assert data["state"] == "ready" and data["checks"]["load"]["status"] == "ok"
    assert data["checks"]["processes"]["status"] == "unverified" and data["overall"] == "unverified"
    assert main(["doctor"]) == 1


def test_healthy_fresh_process_alongside_a_stale_running_chat(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    monkeypatch.setattr("agentsfence.diagnostics.unregistered_hermes", lambda home, processes: [{"pid": 4242, "surface": "cli"}])
    data = snapshot(root, host=host_client.status(root))
    assert data["checks"]["load"]["status"] == "ok" and data["checks"]["processes"]["status"] == "problem"
    assert "PID 4242" in data["checks"]["processes"]["message"] and main(["doctor"]) == 1


def test_recovery_loader_answer_means_tools_blocked(root: Path, monkeypatch: pytest.MonkeyPatch,
                                                   capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer("recovery_block", error="ModuleNotFoundError: agentsfence"))
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "Enforcement: NOT PROTECTED" in out and "Tools blocked" in out and "Repair:" in out
    assert "unprotected" not in out.lower()


def test_unreachable_hermes_is_unverified_even_with_an_old_failure_record(root: Path) -> None:
    settings = load_settings(hermes_dir=root)
    failsafe.write_load_status({"outcome": "recovery_block", "error": "old failure", "time": time.time() - 3600,
                                "python": "/old/python"}, settings.home)
    data = snapshot(root, host=host_client.status(root))  # the test launcher does not exist
    assert data["checks"]["load"]["status"] == "unverified"  # history never establishes current absence
    assert data["last_recorded_load"]["outcome"] == "recovery_block" and data["overall"] == "unverified"
    failsafe.write_load_status({"outcome": "enforcing", "time": time.time(), "python": "/old/python"}, settings.home)
    assert snapshot(root)["last_recorded_load"]["outcome"] == "enforcing"  # a verified load supersedes it


def test_disabled_plugin_and_version_mismatch_are_problems(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer(version="0.0.1"))
    data = snapshot(root, host=host_client.status(root))
    assert data["checks"]["load"]["status"] == "problem" and "0.0.1" in data["checks"]["load"]["message"]
    cfg = yaml.safe_load((root / "config.yaml").read_text())
    cfg["plugins"]["disabled"] = ["agentsfence"]
    (root / "config.yaml").write_text(yaml.safe_dump(cfg))
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]
    assert load["status"] == "problem" and "agentsfence protect --profile default" in load["message"]
    (root / "agentsfence").mkdir(exist_ok=True)
    (root / "agentsfence" / "state.json").write_text(json.dumps({"protected": ["default"]}))
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]  # the user protected it: Hermes disabled it
    assert load["status"] == "problem" and "you protected this profile" in load["message"]
    assert f"agentsfence=={__version__}' agentsfence install" in load["message"]


def test_old_loader_requires_a_reinstall(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    (root / "plugins/agentsfence/__init__.py").write_text("from agentsfence.plugin import register\n")
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]
    assert load["status"] == "problem" and "agentsfence install" in load["message"]


def test_compiler_evidence_states(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsfence.host_client.status", answer())

    def compiler() -> dict[str, str]:
        return snapshot(root, host=host_client.status(root))["checks"]["compiler"]  # type: ignore[no-any-return]

    compile_row(root, provenance=False)
    assert compiler()["status"] == "not_verified" and "without provenance" in compiler()["message"]
    compile_row(root)
    assert compiler()["status"] == "healthy" and "hermes:p:m" in compiler()["message"]
    (root / "agentsfence").mkdir(exist_ok=True)
    (root / "agentsfence" / "settings.yaml").write_text(yaml.safe_dump(
        {"compiler": {"mode": "selected", "selected_model": "another-compiler", "selected_provider": "p"}}))
    protect_profile(root)  # switch compilers
    assert compiler()["status"] == "not_verified" and "does not match current configuration" in compiler()["message"]
    compile_row(root, version="0.0.1")
    assert "recorded under AgentsFence 0.0.1" in compiler()["message"]
    compile_row(root, fell_back=True)
    assert compiler()["status"] == "failed"
    assert snapshot(root, host=host_client.status(root))["overall"] == "ok"  # a fallback is read-only, still protected


def test_compile_audit_records_provenance_captured_before_the_call(home: Path) -> None:
    from conftest import FakeLLM, start_task

    from agentsfence.plugin import AgentsFence

    fence = AgentsFence(load_settings(), client=FakeLLM(), persist=True, catalogue_fn=lambda: [],
                        yolo_fn=lambda: False)
    start_task(fence, "Read the report.")
    rows = [json.loads(line) for line in (fence.settings.home / "audit.jsonl").read_text().splitlines()]
    provenance = next(r for r in rows if r["event"] == "policy_compiled")["details"]["provenance"]
    assert provenance["agentsfence_version"] == __version__ and provenance["evidence_digest"]
    assert provenance["compiler_model"] and provenance["route"] == {"provider": "auto", "model": ""}


# The launcher client, against stand-in launchers (never a real Hermes).

def launcher(tmp_path: Path, body: str) -> str:
    """A stand-in `hermes` where a venv release keeps it (<source>/venv/bin/hermes), so doctor can identify the install."""
    source = tmp_path / "hermes-agent"
    source.mkdir(exist_ok=True)
    (source / "pyproject.toml").write_text("[project]\nname='hermes-agent'\n")
    path = source / "venv" / "bin" / "hermes"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\nimport json, os, sys, time\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


pytestmark_posix = pytest.mark.skipif(os.name == "nt", reason="stand-in launchers are POSIX scripts")


@pytestmark_posix
def test_launcher_client_is_isolated_and_checks_identity(root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = ("print('banner noise')\n"
            "home = os.environ['HERMES_HOME'] if sys.argv[2] == 'default' else sys.argv[2]\n"
            "print('AGENTSFENCE_HOST=' + json.dumps({'schema': 1, 'outcome': 'enforcing', 'hermes_home': home,"
            " 'pythonpath': os.environ.get('PYTHONPATH'), 'argv': sys.argv[1:]}))")
    monkeypatch.setenv("AGENTSFENCE_HERMES", launcher(tmp_path, body))
    monkeypatch.setenv("PYTHONPATH", "/stale/agentsfence")
    result = host_client.status(root)
    assert result["reachable"] and result["pythonpath"] is None  # the caller's package is never injected
    assert result["argv"] == ["-p", "default", "agentsfence", "status", "--json"]
    other = root / "profiles" / "work"
    other.mkdir(parents=True)
    mismatch = host_client.status(other)  # the stand-in answers for a different home
    assert not mismatch["reachable"] and "instead of" in mismatch["error"]


@pytestmark_posix
def test_unknown_command_and_bad_answers_are_unverified(root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES", launcher(tmp_path, (
        "sys.stderr.write(\"hermes: error: argument command: invalid choice: 'agentsfence' api_key=sk-secret123456\\n\")\n"
        "sys.exit(2)")))
    result = host_client.status(root)
    assert not result["reachable"] and result["command_unknown"] and "sk-secret" not in result["error"]
    assert snapshot(root, host=result)["checks"]["load"]["status"] == "unverified"


@pytestmark_posix
def test_timeout_leaves_hermes_running(root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "finished"
    monkeypatch.setenv("AGENTSFENCE_HERMES", launcher(tmp_path, f"time.sleep(1.5)\nopen({str(marker)!r}, 'w').write('done')"))
    result = host_client.call(root, ["status"], timeout=0.3)
    assert not result["reachable"] and "left running" in result["error"] and result["still_running"]
    for _ in range(50):
        if marker.exists():
            break
        time.sleep(0.1)
    assert marker.read_text() == "done"  # Hermes' own work completed after doctor stopped waiting


def test_one_status_subprocess_per_doctor_request(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    real_popen = subprocess.Popen

    def counting(command: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(command, list) and "agentsfence" in command:
            calls.append(command)
        return real_popen(command, *args, **kwargs)

    monkeypatch.setattr("agentsfence.host_client.subprocess.Popen", counting)
    exe = launcher(root.parent, "pass")  # a venv release's hermes that exits fast and answers nothing
    monkeypatch.setattr("agentsfence.host_client.launcher", lambda: exe)
    main(["doctor"])
    assert len(calls) == 1 and calls[0][-2:] == ["status", "--json"]


def test_desktop_shows_a_recovering_backend_as_blocked(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from agentsfence import plugin
    from agentsfence.desktop_api import router

    monkeypatch.setitem(plugin.REGISTRATION, "outcome", "recovery_block")
    monkeypatch.setitem(plugin.REGISTRATION, "error", "ModuleNotFoundError: pydantic")
    monkeypatch.setattr("agentsfence.desktop_api.get_instance", lambda: None)
    monkeypatch.setattr("agentsfence.desktop_api.run_probe", lambda home: pytest.fail("a blocked backend must not probe"))
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        status = client.get("/status").json()
        assert status["state"] == "blocked" and "Tools blocked" in status["guidance"]
        check = client.post("/check", json={}).json()
        assert not check["ok"] and check["stage"] == "activation" and "Repair:" in check["message"]


def test_repair_instructions_pin_this_version(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One pinned install command reinstalls through Hermes' package manager, never whichever
    `agentsfence` is on PATH and never `uv pip install` into an environment Hermes manages."""
    command = f"`uvx --from 'agentsfence=={__version__}' agentsfence install`"
    monkeypatch.setattr("agentsfence.host_client.status", answer("recovery_block", error="ModuleNotFoundError: agentsfence"))
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]
    assert command in load["message"] and "uv pip install" not in load["message"]
    monkeypatch.setattr("agentsfence.host_client.status", answer(version="0.0.1"))
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]
    assert command in load["message"]
    (root / "plugins/agentsfence/__init__.py").write_text("from agentsfence.plugin import register\n")
    load = snapshot(root, host=host_client.status(root))["checks"]["load"]
    assert command in load["message"]


def test_evidence_covers_every_setting_that_changes_a_compile(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 3 #5: a success under a 60s timeout says nothing about a 10s one."""
    monkeypatch.setattr("agentsfence.host_client.status", answer())
    compile_row(root)
    assert snapshot(root, host=host_client.status(root))["checks"]["compiler"]["status"] == "healthy"
    af = load_settings(hermes_dir=root).home / "config.yaml"
    af.parent.mkdir(parents=True, exist_ok=True)
    af.touch()
    for key, value in (("timeout_seconds", 10), ("max_request_chars", 2000), ("followup", "ignore"), ("max_concurrent_requests", 1)):
        settings = yaml.safe_load(af.read_text()) or {}
        original = dict(settings.get("compiler") or {})
        settings.setdefault("compiler", {})[key] = value
        af.write_text(yaml.safe_dump(settings))
        check = snapshot(root, host=host_client.status(root))["checks"]["compiler"]
        assert check["status"] == "not_verified" and "does not match" in check["message"], key
        settings["compiler"] = original
        af.write_text(yaml.safe_dump(settings))
    assert snapshot(root, host=host_client.status(root))["checks"]["compiler"]["status"] == "healthy"


def test_desktop_fallback_state_uses_only_current_evidence(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review round 3 #6: an old fallback row is history, not a current Fallback state."""
    monkeypatch.setattr("agentsfence.diagnostics.process_identity", lambda pid: "this-process")
    register_runtime(load_settings(hermes_dir=root))
    this = {"reachable": True, "outcome": "enforcing", "agentsfence_version": __version__, "hermes_home": str(root),
            "routing": "task"}
    compile_row(root, fell_back=True, provenance=False)  # e.g. recorded by 0.2.0a4
    data = snapshot(root, runtime_verified=True, host=this)
    assert data["state"] == "ready" and data["checks"]["compiler"]["status"] == "not_verified"
    compile_row(root, fell_back=True, version="0.0.1")
    assert snapshot(root, runtime_verified=True, host=this)["state"] == "ready"
    compile_row(root, fell_back=True)  # current version and settings
    assert snapshot(root, runtime_verified=True, host=this)["state"] == "fallback"


def test_evidence_records_hermes_routing_mode(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Evidence from Hermes' own model (the compiler slot failed to register) is not current once the slot routes."""
    def compiler(routing: str | None) -> dict[str, str]:
        monkeypatch.setattr("agentsfence.host_client.status", answer(routing=routing))
        return snapshot(root, host=host_client.status(root))["checks"]["compiler"]  # type: ignore[no-any-return]

    compile_row(root, routing="host-model")
    assert compiler("host-model")["status"] == "healthy"
    upgraded = compiler("task")
    assert upgraded["status"] == "not_verified" and "host-model routing" in upgraded["message"]
    assert compiler(None)["status"] == "not_verified"  # can't confirm the current mode
    compile_row(root, routing=None)
    assert "without Hermes' routing mode" in compiler("task")["message"]


def test_process_scan_dependency_is_declared_for_installs_outside_hermes() -> None:
    """`uvx --from agentsfence==X agentsfence doctor` runs outside Hermes' environment, which provides psutil.

    Without a declared dependency, the scan returned None there and every doctor run was UNVERIFIED.
    """
    import importlib.metadata

    requirements = [r.split(";")[0].replace(" ", "").lower() for r in importlib.metadata.requires("agentsfence") or []
                    if "extra ==" not in r]
    assert any(r.startswith("psutil") for r in requirements), requirements


def test_the_process_scan_runs_in_this_environment(root: Path) -> None:
    from agentsfence.diagnostics import unregistered_hermes

    assert unregistered_hermes(root, []) is not None  # a list (possibly empty), never "could not list"
