"""Runtime cleanup must prove process death and preserve fresh registrations."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from agentsfence import __version__, diagnostics
from agentsfence.config import Settings


@pytest.fixture
def registration(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(diagnostics, "configuration_digest", lambda home: "configuration")
    path = settings.home / "runtime" / "999999.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"pid": 999999, "process_start": "original start",
                                "configuration": "configuration", "version": __version__}))
    return path


def test_dead_registration_is_removed_and_never_probed_again(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes = []
    monkeypatch.setattr(diagnostics, "process_identity", lambda pid: probes.append(pid))
    monkeypatch.setattr(diagnostics, "_pid_alive", lambda pid: pid != 999999)
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings) == []
    assert not registration.exists()
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings) == []
    assert probes == [999999]


@pytest.mark.parametrize("alive", [True, None])
def test_failed_identity_check_preserves_unconfirmed_registration(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch, alive: bool | None,
) -> None:
    monkeypatch.setattr(diagnostics, "process_identity", lambda pid: None)
    monkeypatch.setattr(diagnostics, "_pid_alive", lambda pid: alive)
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings) == []
    assert registration.exists()


@pytest.mark.parametrize("identity", ["original start", "reused PID start"])
def test_running_process_registration_is_preserved(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch, identity: str,
) -> None:
    monkeypatch.setattr(diagnostics, "process_identity", lambda pid: identity)
    monkeypatch.setattr(diagnostics, "_pid_alive", lambda pid: pytest.fail("No death probe for a running process"))
    rows = diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings)
    assert len(rows) == (1 if identity == "original start" else 0)
    assert registration.exists()


@pytest.mark.parametrize("replace", [False, True])
def test_registration_changed_during_probe_is_preserved(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch, replace: bool,
) -> None:
    fresh = '{"pid": 999999, "process_start": "fresh registration"}'

    def changed(pid: int) -> None:
        if replace:
            temporary = registration.with_suffix(".tmp")
            temporary.write_text(fresh)
            temporary.replace(registration)
        else:
            registration.write_text(fresh)

    monkeypatch.setattr(diagnostics, "process_identity", changed)
    monkeypatch.setattr(diagnostics, "_pid_alive", lambda pid: False)
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings) == []
    assert registration.read_text() == fresh


def test_desktop_current_only_check_leaves_foreign_records_alone(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(diagnostics, "process_identity", lambda pid: pytest.fail("Must skip foreign PIDs"))
    monkeypatch.setattr(diagnostics, "_pid_alive", lambda pid: pytest.fail("Must skip foreign PIDs"))
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings, current_only=True) == []
    assert registration.exists()


def test_ps_timeout_alone_cannot_delete_a_registration(
    registration: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("ps", 2)

    monkeypatch.setattr(diagnostics, "_psutil", lambda: None)  # the `ps` fallback
    monkeypatch.setattr(diagnostics.sys, "platform", "linux")
    monkeypatch.setattr(diagnostics.subprocess, "run", timeout)
    monkeypatch.setattr(diagnostics.os, "kill", lambda pid, signal: None)
    assert diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings) == []
    assert registration.exists()


@pytest.fixture
def live_child() -> Any:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    yield child
    child.kill()
    child.wait()


@pytest.mark.parametrize("psutil_available", [True, False])
def test_cleanup_never_terminates_a_live_process(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, live_child: Any, psutil_available: bool,
) -> None:
    """os.kill(pid, 0) terminates a process on Windows; liveness checks must not signal it."""
    if not psutil_available:
        monkeypatch.setattr(diagnostics, "_psutil", lambda: None)
    monkeypatch.setattr(diagnostics, "process_identity", lambda pid: None)  # forces the death check
    path = settings.home / "runtime" / f"{live_child.pid}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"pid": live_child.pid, "process_start": "start", "configuration": "c", "version": __version__}))
    diagnostics.runtime_status(Path(os.environ["HERMES_HOME"]), settings)
    time.sleep(0.2)
    assert live_child.poll() is None and path.exists()


def test_windows_without_psutil_never_signals_or_shells_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostics, "_psutil", lambda: None)
    monkeypatch.setattr(diagnostics.sys, "platform", "win32")
    monkeypatch.setattr(diagnostics.os, "kill", lambda *args: pytest.fail("os.kill terminates processes on Windows"))
    monkeypatch.setattr(diagnostics.subprocess, "run", lambda *args, **kwargs: pytest.fail("Windows has no ps"))
    assert diagnostics._pid_alive(12345) is None
    assert diagnostics._read_process_identity(12345) is None


def test_process_identity_does_not_need_ps(monkeypatch: pytest.MonkeyPatch, live_child: Any) -> None:
    monkeypatch.setattr(diagnostics.subprocess, "run", lambda *args, **kwargs: pytest.fail("psutil needs no ps"))
    first = diagnostics._read_process_identity(live_child.pid)
    assert first is not None and first == diagnostics._read_process_identity(live_child.pid)
    assert diagnostics._pid_alive(live_child.pid) is True
    live_child.kill()
    live_child.wait()
    assert diagnostics._read_process_identity(live_child.pid) is None and diagnostics._pid_alive(live_child.pid) is False


def test_dead_process_metadata_is_not_a_live_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exited Windows process can still have readable metadata through an open handle."""
    from types import SimpleNamespace

    psutil = SimpleNamespace(pid_exists=lambda pid: False,
                             Process=lambda pid: pytest.fail("Do not read retained metadata for a dead PID"),
                             Error=RuntimeError)
    monkeypatch.setattr(diagnostics, "_psutil", lambda: psutil)
    assert diagnostics._read_process_identity(12345) is None
