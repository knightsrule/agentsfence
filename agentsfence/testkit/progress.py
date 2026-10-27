"""Observed test progress; a private file bridges fresh Hermes processes."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

Progress = Callable[[dict[str, Any]], None]
PROGRESS_FILE = "AGENTSFENCE_TEST_PROGRESS_FILE"


def publish(event: dict[str, Any]) -> None:
    """Called by the scenario runner only when it reaches an actual boundary."""
    filename = os.environ.get(PROGRESS_FILE)
    if not filename:
        return
    path = Path(filename)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(event), encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        pass  # Losing the observer must never change a test's outcome.


def wait(child: subprocess.Popen[Any], timeout: float, path: Path, progress: Progress) -> int:
    """Read atomic snapshots without touching the child's stdout file offset."""
    deadline = time.monotonic() + timeout
    previous = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(child.args, timeout)
        try:
            code = child.wait(timeout=min(0.25, remaining))
        except subprocess.TimeoutExpired:
            code = None
        try:
            text = path.read_text(encoding="utf-8")
            if text != previous:
                event = json.loads(text)
                if isinstance(event, dict):
                    progress(event)
                previous = text
        except (OSError, ValueError):
            pass
        if code is not None:
            return code


class Runs:
    """Bounded backend-local observations, scoped to the requested profile."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, dict[str, Any]] = {}

    def begin(self, run_id: str, home: Path) -> Progress:
        with self._lock:
            now = time.monotonic()
            self._runs = {key: row for key, row in self._runs.items()
                          if row.get("finished") is None or now - row["finished"] < 3600}
            if run_id in self._runs:
                raise ValueError("This test run already exists.")
            if len(self._runs) >= 32:
                finished = next((key for key, row in self._runs.items() if row.get("finished") is not None), None)
                if finished is None:
                    raise ValueError("Too many tests are running. Wait for a test to finish.")
                del self._runs[finished]
            self._runs[run_id] = {"home": home.resolve(), "started": now, "status": "running",
                                  "phase": "preparing", "message": "Preparing this profile's test."}

        def update(event: dict[str, Any]) -> None:
            with self._lock:
                self._runs[run_id].update({key: event[key] for key in
                    ("phase", "message", "completed", "total", "scenario") if key in event})

        return update

    def finish(self, run_id: str, status: str) -> None:
        with self._lock:
            self._runs[run_id].update(status=status, finished=time.monotonic())

    def read(self, run_id: str, home: Path) -> dict[str, Any] | None:
        with self._lock:
            row = self._runs.get(run_id)
            if row is None or row["home"] != home.resolve():
                return None
            end = row.get("finished") or time.monotonic()
            return {**{key: value for key, value in row.items() if key not in ("home", "started", "finished")},
                    "elapsed_seconds": round(end - row["started"], 1)}
