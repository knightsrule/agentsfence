"""Offline compiler measurements through the same check path as real tools."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from conftest import FakeLLM

from agentsfence.config import Settings
from agentsfence.testkit.compiler_eval import evaluate_case

CORPUS = Path(__file__).with_name("cases.yaml")


def load_cases() -> list[dict[str, Any]]:
    return yaml.safe_load(CORPUS.read_text(encoding="utf-8"))["cases"]  # type: ignore[no-any-return]


@dataclass(frozen=True)
class Observation:
    case_id: str
    category: str
    expected: str
    actual: str
    rule: str | None
    fell_back: bool = False

    @property
    def overgrant(self) -> bool:
        return self.expected != "ALLOW" and self.actual == "ALLOW"

    @property
    def undergrant(self) -> bool:
        return self.expected == "ALLOW" and self.actual != "ALLOW"


def run_case(case: dict[str, Any], settings: Settings) -> list[Observation]:
    """Recorded outputs never use the network; each case gets fresh policy state."""
    result = evaluate_case(case, settings, FakeLLM(), recorded=True)
    fell_back = any(row["fell_back"] for row in result["compiles"])
    return [Observation(**{key: value for key, value in row.items() if key != "wait_seconds"}, fell_back=fell_back)
            for row in result["observations"]]


def summarize(observations: list[Observation]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"calls": 0, "overgrant": 0, "undergrant": 0, "mismatch": 0})
    for result in observations:
        row = counts[result.category]
        row["calls"] += 1
        row["overgrant"] += result.overgrant
        row["undergrant"] += result.undergrant
        row["mismatch"] += result.expected != result.actual
    return dict(counts)
