"""Docs must not cite tests that don't exist: SECURITY.md's guarantee table is only as good as its evidence."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _defined_tests() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "tests").glob("test_*.py"):
        names.update(re.findall(r"^\s*def (test_\w+)", path.read_text(encoding="utf-8"), re.MULTILINE))
    return names


def test_security_md_cites_only_existing_tests() -> None:
    cited = set(re.findall(r"`(test_\w+)`", (ROOT / "SECURITY.md").read_text(encoding="utf-8")))
    assert cited, "SECURITY.md should cite regression tests"
    assert cited <= _defined_tests(), sorted(cited - _defined_tests())


def test_install_instructions_pin_this_release() -> None:
    """Docs must not advertise behavior while pinning an older release (review round 3 #2)."""
    from agentsfence import __version__

    pins = set(re.findall(r"agentsfence==([0-9][\w.]*)", (ROOT / "README.md").read_text(encoding="utf-8")))
    assert pins == {__version__}, pins


def _gate_revisions() -> dict[str, str]:
    """``{version or "managed": ref}`` from BETA_GATE.md's required-environments table."""
    text = (ROOT / "BETA_GATE.md").read_text(encoding="utf-8")
    table = text.split("## Required environments", 1)[1].split("\n## ", 1)[0]
    rows = {label: ref for ref, label in re.findall(
        r"\|\s*Managed install at `([0-9a-f]{40})`\s*\(([\w.-]+)\)\s*\|", table)}
    return rows


def test_beta_environments_agree_across_gate_ci_and_docs() -> None:
    import yaml

    gate = _gate_revisions()
    assert len(gate) == 2 and "main" in gate and "rc" in gate, gate
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    matrix = {row["ref"] for row in ci["jobs"]["hermes"]["strategy"]["matrix"]["include"]}
    assert matrix == set(gate.values()), (matrix, gate)
    api = (ROOT / "HERMES_API.md").read_text(encoding="utf-8").split("## Supported Hermes versions", 1)[1].split("\n## ", 1)[0]
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for ref in gate.values():
        assert ref in api and ref in agents
    assert "two managed environments" in api and "two managed environments" in agents
