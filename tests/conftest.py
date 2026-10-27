from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from intent_fixtures import PolicyDraft
from pydantic import BaseModel

from agentsfence.config import Settings, load_settings
from agentsfence.plugin import AgentsFence

# Tool names mirror what Hermes actually exposes: built-ins plus MCP tools
# registered as mcp_<server>_<tool>.
DEMO_TOOLS = [
    "mcp_gmail_search_threads",
    "mcp_gmail_get_message",
    "mcp_gmail_send_message",
    "mcp_gmail_trash_thread",
    "mcp_drive_search_files",
    "mcp_drive_read_file_content",
    "mcp_drive_share_file",
    "mcp_drive_delete_file",
    "read_file",
    "write_file",
    "web_extract",
    "web_search",
    "terminal",
    "send_message",
    "memory",
]


class FakeLLM:
    """Deterministic stand-in for the compiler model.

    ``responses`` maps a substring of the user request to either a PolicyDraft,
    a dict, a raw string, or an Exception to raise.
    """

    name = "fake-llm"

    def __init__(self, responses: dict[str, Any] | None = None, default: Any = None):
        self.responses = responses or {}
        self.default = default
        self.calls: list[str] = []
        self.systems: list[str] = []

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append(user)
        self.systems.append(system)
        request = user.split("<<<REQUEST>>>", 1)[-1].split("<<<END>>>", 1)[0]
        value = self.default
        for key, resp in self.responses.items():
            if key.lower() in request.lower():
                value = resp
                break
        if value is None:
            value = PolicyDraft(purpose="read_task", summary="read only")
        if isinstance(value, Exception):
            raise value
        if isinstance(value, PolicyDraft):
            return value.intents(request.strip()).model_dump_json()
        if isinstance(value, BaseModel):
            return value.model_dump_json()
        if isinstance(value, dict):
            return json.dumps(value)
        return str(value)


def draft(**kw: Any) -> PolicyDraft:
    kw.setdefault("purpose", "task")
    return PolicyDraft(**kw)


@pytest.fixture(autouse=True)
def _never_launch_real_hermes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must never start the developer's real Hermes.

    `agentsfence doctor` asks Hermes through its launcher, and starting a real
    Hermes can run its own pending update steps against the user's install.
    Tests that need a launcher set AGENTSFENCE_HERMES to a throwaway one.
    """
    monkeypatch.setenv("AGENTSFENCE_HERMES", "/nonexistent/agentsfence-test-hermes")


@pytest.fixture
def hermes_enforcing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes answers doctor's launcher check: a new process loads this AgentsFence."""
    import sys

    from agentsfence import __version__

    def status(home: Path) -> dict[str, Any]:
        return {"reachable": True, "schema": 1, "outcome": "enforcing", "agentsfence_version": __version__,
                "python": sys.executable, "hermes_home": str(home), "profile": "test"}

    monkeypatch.setattr("agentsfence.host_client.status", status)


@pytest.fixture
def capable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermes passes the capability preflight (no Hermes is started)."""
    monkeypatch.setattr("agentsfence.lifecycle.run_preflight", lambda: {"ok": True, "missing": [], "optional_missing": []})


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AGENTSFENCE_HOME", str(tmp_path / "af"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    for var in ("AGENTSFENCE_COMPILER_PROVIDER", "AGENTSFENCE_STRICT_YOLO", "AGENTSFENCE_MISSING_POLICY", "AGENTSFENCE_FOLLOWUP"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


@pytest.fixture
def settings(home: Path) -> Settings:
    return load_settings()


@pytest.fixture
def make_fence(settings: Settings) -> Callable[..., AgentsFence]:
    def _make(llm: Any = None, *, persist: bool = False, yolo: bool = False, settings_: Settings | None = None) -> AgentsFence:
        return AgentsFence(
            settings_ or settings,
            client=llm or FakeLLM(),
            persist=persist,
            catalogue_fn=lambda: list(DEMO_TOOLS),
            yolo_fn=lambda: yolo,
        )

    return _make


def start_task(fence: AgentsFence, message: str, session: str = "s1") -> dict[str, str] | None:
    result = fence.on_pre_llm_call(session_id=session, task_id="t1", user_message=message, is_first_turn=True, conversation_history=[], platform="cli", model="m")
    wait_task(fence, session)
    return result


def wait_task(fence: AgentsFence, session: str = "s1") -> None:
    """Recorded fixtures wait for background audits as well as installation."""
    deadline = time.monotonic() + fence.settings.compiler.timeout_seconds + 1
    record = fence.store.get(session)
    if record and record.policy.pending_revision is not None:
        assert fence.store.wait_revision(record.session_id, record.policy.policy_id, deadline) == "ready"
    while fence._compiling.get(session):
        assert time.monotonic() < deadline, "background policy update did not finish"
        time.sleep(.001)


def tool(fence: AgentsFence, name: str, args: dict[str, Any] | None = None, *, session: str = "s1", call_id: str = "") -> dict[str, str] | None:
    return fence.on_pre_tool_call(tool_name=name, args=args or {}, session_id=session, task_id="t1", tool_call_id=call_id or f"c-{name}-{id(args)}")


def verdict(result: dict[str, str] | None) -> str:
    if result is None:
        return "ALLOW"
    return {"block": "BLOCK", "approve": "ASK_USER"}[result["action"]]
