"""Audit log and structured logging.

Every consequential decision is appended as one JSON object per line to
``$AGENTSFENCE_HOME/audit.jsonl`` (mode 0600). Argument *values* are redacted
by default: only keys that identify *where* an action goes (recipients, URLs,
paths, actions) are kept, truncated. Message bodies, file contents and other
free-text arguments are replaced by their length and a short hash. Compile and
amend events retain interpretation statements and selected instruction quotes
for review; these may contain sensitive text, including an entire short request.

Each event is also logged through the ``agentsfence`` logger as one line with its
session id, so it appears in Hermes' ``agent.log`` (``hermes logs --session ID``).
When ``audit.jsonl`` grows past ``audit.max_bytes`` it is renamed to
``audit-<UTC time>.jsonl``; rotated files older than ``audit.retention_days`` are removed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .config import AuditSettings
from .models import AuditEvent

logger = logging.getLogger("agentsfence")


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter for the ``agentsfence`` logger."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "agentsfence", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str | None = None) -> None:
    """Opt-in JSON logs on stderr (``AGENTSFENCE_LOG=debug|info|warning``)."""
    lvl = (level or os.environ.get("AGENTSFENCE_LOG") or "").upper()
    if not lvl:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("agentsfence")
    if not any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        root.addHandler(handler)
    root.setLevel(getattr(logging, lvl, logging.INFO))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def redact(value: Any, keep_keys: set[str], max_chars: int, *, key: str | None = None, keep: bool = False) -> Any:
    """Redact free text. Only *leaf* strings directly under a kept key (or a list
    of them) survive; a dict nested under a kept key is redacted like any other,
    so ``{"to": {"body": "..."}}`` cannot smuggle content into the log."""
    keep = keep or (key is not None and key.lower() in keep_keys)
    if isinstance(value, dict):
        return {k: redact(v, keep_keys, max_chars, key=str(k), keep=False) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, keep_keys, max_chars, key=None, keep=keep and not isinstance(v, (dict, list, tuple))) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    text = str(value)
    if keep:
        return text if len(text) <= max_chars else text[:max_chars] + f"…(+{len(text) - max_chars})"
    return {"redacted": True, "len": len(text), "sha256": _digest(text)}


def log_line(event: AuditEvent) -> str:
    """One readable log line: the event, its session, and the timings an operator needs.

    Hermes' log formatter drops ``extra``, so everything needed to reconstruct a
    compile or approval timeline without the audit file goes into the message.
    """
    details = event.details or {}
    recorded = details.get("provenance")
    provenance: dict[str, Any] = recorded if isinstance(recorded, dict) else {}
    fields = [("session", event.session_id), ("tool", event.tool), ("decision", event.decision), ("rule", event.rule_id),
              ("model", provenance.get("compiler_model")), ("seconds", provenance.get("seconds")),
              ("fell_back", details.get("fell_back")), ("wait_seconds", details.get("wait_seconds")),
              ("choice", details.get("choice"))]
    return " ".join([event.event, *(f"{k}={v}" for k, v in fields if v is not None and v != "")])


class AuditLog:
    def __init__(self, path: Path | None, settings: AuditSettings):
        self.path = path
        self.settings = settings
        self._lock = threading.Lock()
        self._keep = {k.lower() for k in settings.keep_keys}
        if path is not None and settings.enabled:
            path.parent.mkdir(parents=True, exist_ok=True)

    def redact_args(self, args: dict[str, Any] | None) -> dict[str, Any]:
        return redact(args or {}, self._keep, self.settings.max_value_chars)  # type: ignore[no-any-return]

    def record(self, event: AuditEvent) -> None:
        line = event.model_dump_json(exclude_none=True)
        logger.info("%s", log_line(event), extra={"agentsfence": json.loads(line)})
        if not self.settings.enabled or self.path is None:
            return
        try:
            with self._lock:
                self._rotate()
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:
            logger.error("audit write failed: %s", exc)

    def _rotate(self) -> None:
        """Rename a full log aside and drop rotated logs past retention. Another process may race; both outcomes are fine."""
        assert self.path is not None
        cutoff = time.time() - self.settings.retention_days * 86400
        for old in self.path.parent.glob(f"{self.path.stem}-*{self.path.suffix}"):
            try:
                if old.stat().st_mtime < cutoff:
                    old.unlink()
            except OSError:
                continue
        try:
            if self.path.stat().st_size < self.settings.max_bytes:
                return
        except FileNotFoundError:
            return
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        try:
            os.replace(self.path, self.path.with_name(f"{self.path.stem}-{stamp}-{uuid.uuid4().hex}{self.path.suffix}"))
        except FileNotFoundError:
            return

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if self.path is None or not self.path.is_file():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return out
