"""Always print authorization errors, including under pytest's default capture."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .harness import Observation, summarize

OBSERVATIONS: list[Observation] = []


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if not OBSERVATIONS:
        return
    terminalreporter.section("compiler eval: recorded outputs, end-to-end")
    terminalreporter.write_line(f"{'category':<23} {'calls':>5} {'over-grant':>10} {'under-grant':>11} {'mismatch':>8}")
    for category, row in sorted(summarize(OBSERVATIONS).items()):
        terminalreporter.write_line(
            f"{category:<23} {row['calls']:>5} {row['overgrant']:>10} {row['undergrant']:>11} {row['mismatch']:>8}"
        )
    if path := os.environ.get("AGENTSFENCE_COMPILER_EVAL_RESULTS"):
        Path(path).write_text(json.dumps([o.__dict__ for o in OBSERVATIONS], indent=2) + "\n", encoding="utf-8")
