"""Timings and sessions an operator can read without rebuilding them (early-user report, 0.2.0a6).

Testers reconstructed compile and approval timings by hand: Hermes' log line for
``policy_compiled`` carried no session ID, and approvals recorded no wait time.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

import pytest
from conftest import start_task, tool

from agentsfence.plugin import AgentsFence


def test_the_compile_log_line_names_session_model_and_time(make_fence: Callable[..., AgentsFence],
                                                           caplog: pytest.LogCaptureFixture) -> None:
    fence = make_fence()
    with caplog.at_level(logging.INFO, logger="agentsfence"):
        start_task(fence, "Summarize the report.", session="sess-42")
    line = next(r.getMessage() for r in caplog.records if r.getMessage().startswith("policy_compiled"))
    assert "session=sess-42" in line and "model=fake-llm" in line and "seconds=" in line and "fell_back=False" in line


def test_approvals_record_how_long_the_user_took(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence(persist=True)
    start_task(fence, "Summarize the report.")
    out = tool(fence, "write_file", {"path": "/tmp/agentsfence-visibility.md", "content": "x"}, call_id="w1")
    assert out and out["action"] == "approve"
    fence.on_post_approval_response(pattern_key="plugin_rule:" + out["rule_key"], choice="deny", tool_call_id="w1")
    rows = [json.loads(line) for line in (fence.settings.home / "audit.jsonl").read_text().splitlines()]
    denied = next(r for r in rows if r["event"] == "approval_denied")
    assert isinstance(denied["details"]["wait_seconds"], float) and denied["details"]["wait_seconds"] >= 0
