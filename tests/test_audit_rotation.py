"""Retained audit evidence must not be overwritten or left beyond its configured lifetime."""

import json
import os
import time
from pathlib import Path

from agentsfence.audit import AuditLog
from agentsfence.config import AuditSettings
from agentsfence.models import AuditEvent


def test_repeated_rotations_in_one_second_preserve_every_record(tmp_path: Path) -> None:
    settings = AuditSettings()
    settings.max_bytes = 1
    log = AuditLog(tmp_path / "audit.jsonl", settings)
    for index in range(4):
        log.record(AuditEvent(event="decision", details={"index": index}))
    rows = [json.loads(line) for path in tmp_path.glob("*.jsonl") for line in path.read_text().splitlines()]
    assert sorted(row["details"]["index"] for row in rows) == [0, 1, 2, 3]
    assert len(list(tmp_path.glob("audit-*.jsonl"))) == 3


def test_retention_expires_old_evidence_without_waiting_for_next_rotation(tmp_path: Path) -> None:
    old = tmp_path / "audit-old.jsonl"
    old.write_text("old evidence")
    expired = time.time() - 2 * 86400
    os.utime(old, (expired, expired))
    log = AuditLog(tmp_path / "audit.jsonl", AuditSettings(retention_days=1))
    log.record(AuditEvent(event="installed"))
    assert not old.exists() and log.tail()[0]["event"] == "installed"
