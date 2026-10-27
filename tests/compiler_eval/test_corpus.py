"""A semantic corpus, not a replay of the compiler's implementation rules."""
from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

from agentsfence.compiler import IntentDraft
from agentsfence.config import Settings
from agentsfence.testkit.compiler_eval import load_cases as load_packaged_cases

from .conftest import OBSERVATIONS
from .harness import load_cases, run_case

CASES = load_cases()


def parameters() -> list[Any]:
    return [pytest.param(
        case, id=f"{case['category']}/{case['id']}",
        marks=pytest.mark.xfail(strict=True, reason=case["xfail"]) if case.get("xfail") else (),
    ) for case in CASES]


def test_corpus_has_all_categories_and_unique_ids() -> None:
    counts = Counter(case["category"] for case in CASES)
    assert set(counts) == {
        "paraphrase", "negation", "conditional", "informational", "multilingual",
        "source_destination", "followup", "unseen_tool", "quoted_material", "positive_authorized",
    }
    assert all(count >= 8 for count in counts.values())
    assert len({case["id"] for case in CASES}) == len(CASES)
    assert all(case["messages"] and case["calls"] for case in CASES)
    assert load_packaged_cases() == CASES, "Installed CLI and pytest must evaluate the identical corpus"
    for case in CASES:
        for message in case["messages"]:
            IntentDraft.model_validate(message["model_output"])


@pytest.mark.parametrize("case", parameters())
def test_recorded_compiler_authority(case: dict[str, Any], settings: Settings) -> None:
    results = run_case(case, settings)
    OBSERVATIONS.extend(results)
    assert results, "Every case must reach AgentsFence.check"
    assert not any(result.fell_back for result in results), "Valid recorded intents must never silently fall back"
    assert [(r.expected, r.actual) for r in results] == [(r.expected, r.expected) for r in results], "; ".join(
        f"{r.expected} -> {r.actual} ({r.rule})" for r in results if r.actual != r.expected
    )
