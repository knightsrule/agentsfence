"""Progress observes real boundaries without running Hermes or a model."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentsfence import desktop_api
from agentsfence.testkit.progress import PROGRESS_FILE, Runs, wait


def test_child_progress_arrives_before_exit_without_consuming_stdout(tmp_path: Path) -> None:
    snapshot = tmp_path / "progress.json"
    release = tmp_path / "release"
    events = []
    script = """
import time
from pathlib import Path
from agentsfence.testkit.progress import publish
publish({'phase': 'policy', 'completed': 0, 'total': 6, 'message': 'Compiling policy 1 of 6'})
while not Path(__import__('sys').argv[1]).exists():
    time.sleep(.01)
print('final result', flush=True)
"""
    with (tmp_path / "stdout").open("w+b") as output:
        child = subprocess.Popen([sys.executable, "-c", script, str(release)], stdout=output,
                                 env={**os.environ, PROGRESS_FILE: str(snapshot)})

        def update(event: dict[str, Any]) -> None:
            assert child.poll() is None  # The request is still underway when observed.
            events.append(event)
            release.touch()

        try:
            assert wait(child, 10, snapshot, update) == 0
            output.seek(0)
            assert output.read() == b"final result\n"
            assert events[0]["phase"] == "policy" and events[0]["completed"] == 0
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


def test_updates_do_not_extend_the_original_deadline(tmp_path: Path) -> None:
    snapshot = tmp_path / "progress.json"
    snapshot.write_text('{"phase":"policy"}')

    class Child:
        args = ["stand-in"]

        def wait(self, timeout: float) -> int:
            from time import sleep
            sleep(timeout)
            raise subprocess.TimeoutExpired(self.args, timeout)

    events: list[dict[str, Any]] = []
    with pytest.raises(subprocess.TimeoutExpired) as failure:
        wait(Child(), .05, snapshot, events.append)  # type: ignore[arg-type]
    assert failure.value.timeout == .05 and events == [{"phase": "policy"}]


def test_registry_scopes_profiles_and_bounds_completed_runs(tmp_path: Path) -> None:
    registry = Runs()
    update = registry.begin("run", tmp_path)
    update({"phase": "policy", "message": "Compiling", "secret": "not exposed"})
    assert registry.read("run", tmp_path / "other") is None
    state = registry.read("run", tmp_path)
    assert state and state["phase"] == "policy" and "secret" not in state
    with pytest.raises(ValueError, match="already exists"):
        registry.begin("run", tmp_path)
    registry.finish("run", "finished")
    state = registry.read("run", tmp_path)
    assert state and state["status"] == "finished"
    for index in range(32):
        registry.begin(str(index), tmp_path)
    assert registry.read("run", tmp_path) is None  # Finished entry was evicted.
    with pytest.raises(ValueError, match="Too many"):
        registry.begin("overflow", tmp_path)


def test_desktop_can_poll_while_post_is_running(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(desktop_api, "_TEST_RUNS", Runs())
    monkeypatch.setattr(desktop_api, "resolve_profile", lambda name: tmp_path / (name or "default"))

    def run_test(*args: Any, progress: Any, **kwargs: Any) -> dict[str, Any]:
        progress({"phase": "policy", "message": "Compiling policy 2 of 6", "completed": 1, "total": 6})
        started.set()
        assert release.wait(10)
        return {"error": "stand-in result", "ok": False}

    monkeypatch.setattr("agentsfence.testkit.live.run_test", run_test)
    app = FastAPI()
    app.include_router(desktop_api.router)
    with TestClient(app) as client, ThreadPoolExecutor() as executor:
        pending = executor.submit(client.post, "/test", json={"profile": "default", "run_id": "run"})
        try:
            assert started.wait(10)
            state = client.get("/test-progress/run?profile=default").json()
            assert not pending.done() and state["status"] == "running"
            assert state["message"] == "Compiling policy 2 of 6" and state["completed"] == 1
            assert state["elapsed_seconds"] >= 0
            assert client.get("/test-progress/run?profile=work").status_code == 404
            assert client.post("/test", json={"run_id": "run"}).status_code == 409
        finally:
            release.set()
        assert pending.result().status_code == 200
        assert client.get("/test-progress/run").json()["status"] == "finished"
