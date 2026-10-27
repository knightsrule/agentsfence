"""Shared operator view of Hermes' effective approval mode."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .config import hermes_home, profile_environment


def effective_approval_mode(home: Path, config: dict[str, Any], session: str | None = None) -> str:
    mode = (config.get("approvals") or {}).get("mode")
    if not mode:
        try:
            from hermes_cli.config import DEFAULT_CONFIG

            mode = (DEFAULT_CONFIG.get("approvals") or {}).get("mode")
        except ImportError:
            pass
    env = profile_environment(home)
    if env.get("HERMES_YOLO_MODE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return "off"
    # A running host may have frozen process YOLO or a chat-specific /yolo
    # toggle. Do not import the tool runtime into standalone diagnostics or
    # consult the current profile's context for a different profile.
    host = sys.modules.get("tools.approval") if home == hermes_home() else None
    if host:
        try:
            if _host_bypass(host, session or ""):
                return "off"
        except Exception:
            return "unknown"
    return str(mode or "unknown")


def _host_bypass(host: Any, session: str) -> bool:
    """Hermes' approval bypass for exactly this session; "" checks process and config only.

    Never use is_approval_bypass_active(): it reads whichever session is current
    in the calling thread or environment, not the one being reported.
    """
    return bool(host.is_approval_bypass_active_for_session(session))
