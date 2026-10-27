"""Owner permission updates suspend old grants and wait outside the store lock."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLLM, start_task, wait_task

from agentsfence.compiler import CompileResult
from agentsfence.compiler.interpret import Change, IntentDraft
from agentsfence.compiler.merge import merge_intents
from agentsfence.models import Grant, RiskClass, TaskPolicy, ToolConstraint, Verdict, utcnow
from agentsfence.plugin import AgentsFence
from agentsfence.policy_store import PolicyStore

SEND = "mcp_gmail_send_message"
ARGS = {"to": "alice@example.com", "body": "report"}


def test_unresolved_queue_persists_through_failure_and_restart_until_success(tmp_path: Path) -> None:
    directory = tmp_path / "policies"
    store = PolicyStore(directory)
    record = store.put("owner", TaskPolicy(policy_id="p", purpose="task"))
    instruction = "Leave everything untouched from now on"
    revision = store.begin_revision(record, instruction)
    path = directory / "owner.json"
    assert json.loads(path.read_text())["unresolved"] == [{"revision": revision, "instruction": instruction}]
    assert store.install_revision("owner", revision, record.policy.model_copy(deep=True), resolved=False)
    restarted = PolicyStore(directory)
    loaded = restarted.get("owner")
    assert loaded and [u.instruction for u in loaded.unresolved] == [instruction]
    revision = restarted.begin_revision(loaded, "thanks")
    assert restarted.install_revision("owner", revision, loaded.policy.model_copy(deep=True))
    assert json.loads(path.read_text())["unresolved"] == []
    loaded = restarted.get("owner")
    assert loaded
    restarted.begin_revision(loaded, instruction)
    restarted.drop("owner")
    assert not path.exists()


def authorized(fence: AgentsFence) -> TaskPolicy:
    policy = TaskPolicy(policy_id="pol-revision", purpose="send_report", allowed_tools=["email.send"],
                        allow_external_writes=True, allowed_recipients=["alice@example.com"])
    fence.store.put("s1", policy)
    return policy


@pytest.mark.parametrize("yolo,expected", [(False, Verdict.ASK_USER), (True, Verdict.BLOCK)])
def test_failed_owner_amend_suspends_consequences_but_reads_flow(make_fence: Callable[..., AgentsFence], yolo: bool, expected: Verdict) -> None:
    fence = make_fence(FakeLLM(default=RuntimeError("provider unavailable")), yolo=yolo)
    authorized(fence)
    start_task(fence, "Keep the report brief from now on")
    record = fence.store.get("s1")
    assert record and record.policy.suspended_since is not None
    assert fence.check(SEND, ARGS, session_id="s1").decision is expected
    assert fence.check("read_file", {"path": "/tmp/report"}, session_id="s1").decision is Verdict.ALLOW


def test_untouched_restriction_applies_when_model_omits_revocation(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence(FakeLLM(default={"interpretation": [], "grants": [], "changes": [], "summary": "No new actions"}))
    authorized(fence)
    start_task(fence, "Leave everything untouched from now on")
    record = fence.store.get("s1")
    assert record and record.policy.compiler_status != "fallback"
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "user-prohibition"
    assert fence.check("read_file", {"path": "/tmp/report"}, session_id="s1").decision is Verdict.ALLOW


def test_every_owner_turn_reaches_amend_and_later_success_clears_suspension(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    authorized(fence)
    messages: list[str] = []

    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        messages.append(message)
        changed = existing.model_copy(deep=True)
        changed.allowed_tools = []
        changed.allow_external_writes = False
        changed.suspended_since = None
        return CompileResult(policy=changed)

    monkeypatch.setattr(fence.compiler, "amend", amend)
    start_task(fence, "Leave everything untouched from now on")
    record = fence.store.get("s1")
    assert messages == ["Leave everything untouched from now on"]
    assert record and record.policy.suspended_since is None
    assert fence.check(SEND, ARGS, session_id="s1").decision is not Verdict.ALLOW


def test_runtime_grant_cannot_bypass_suspension_or_prohibition(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = authorized(fence)
    record = fence.store.get("s1")
    assert record
    assessed = fence.evaluator.assess(policy, SEND, ARGS, record.state)
    policy.grants.append(Grant(grant_id="runtime", tool=SEND, capability="email.send", risk=RiskClass.COMMUNICATION,
                               fingerprint=assessed.fingerprint, approved_via="session", constraint=ToolConstraint()))
    policy.suspended_since = 2
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "policy-suspended"
    policy.user_prohibitions = ["COMMUNICATION"]
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "user-prohibition"


def test_pending_revocation_waits_and_worker_can_install_outside_wait_lock(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    old = authorized(fence)
    record = fence.store.get("s1")
    assert record
    revision = fence.store.begin_revision(record)
    with ThreadPoolExecutor(max_workers=1) as pool:
        call = pool.submit(fence.check, SEND, ARGS, session_id="s1", deadline=time.monotonic() + 2)
        time.sleep(.03)
        assert not call.done()
        changed = old.model_copy(update={"allowed_tools": [], "allow_external_writes": False, "suspended_since": None})
        assert fence.store.install_revision("s1", revision, changed)
        assert call.result(1).decision is not Verdict.ALLOW


def test_pending_reads_wait_and_timeout_requires_confirmation(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    authorized(fence)
    record = fence.store.get("s1")
    assert record
    fence.store.begin_revision(record)
    before = time.monotonic()
    result = fence.check("read_file", {"path": "/tmp/x"}, session_id="s1", deadline=before + .04)
    assert time.monotonic() - before >= .03
    assert result.decision is Verdict.ASK_USER and result.rule_id == "policy-compiling"


@pytest.mark.parametrize("expired", [False, True])
def test_drop_or_expiry_cancels_wait_and_rejects_worker(make_fence: Callable[..., AgentsFence], expired: bool) -> None:
    fence = make_fence()
    policy = authorized(fence)
    record = fence.store.get("s1")
    assert record
    if expired:
        policy.expires_at = utcnow() + timedelta(seconds=.06)
    revision = fence.store.begin_revision(record)
    with ThreadPoolExecutor(max_workers=1) as pool:
        call = pool.submit(fence.check, SEND, ARGS, session_id="s1", deadline=time.monotonic() + 2)
        if not expired:
            time.sleep(.03)
            fence.store.drop("s1")
        assert call.result(1).decision is Verdict.BLOCK
    assert fence.store.install_revision("s1", revision, policy) is None


def test_stale_result_cannot_restore_authority_and_counters_survive(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = authorized(fence)
    record = fence.store.get("s1")
    assert record
    record.state.calls_by_capability["email.send"] = 3
    older = fence.store.begin_revision(record)
    newer = fence.store.begin_revision(record)
    assert fence.store.install_revision("s1", older, policy.model_copy()) is None
    changed = policy.model_copy(update={"allowed_tools": [], "allow_external_writes": False, "suspended_since": None})
    installed = fence.store.install_revision("s1", newer, changed)
    assert installed and installed.state.calls_by_capability["email.send"] == 3
    assert installed.policy.pending_revision is None


def test_pending_runtime_grant_never_allows_even_after_timeout(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = authorized(fence)
    record = fence.store.get("s1")
    assert record
    assessed = fence.evaluator.assess(policy, SEND, ARGS, record.state)
    policy.grants.append(Grant(grant_id="runtime", tool=SEND, capability="email.send", risk=RiskClass.COMMUNICATION,
                               fingerprint=assessed.fingerprint, approved_via="session", constraint=ToolConstraint()))
    fence.store.begin_revision(record)
    result = fence.check(SEND, ARGS, session_id="s1", deadline=time.monotonic() + .01)
    assert result.decision is Verdict.ASK_USER


def test_intent_alternatives_keep_target_dimensions_together(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    choices = [ToolConstraint(allowed_recipients=["alice@example.com"], allowed_paths=["/tmp/alice"], max_calls=1),
               ToolConstraint(allowed_recipients=["bob@example.com"], allowed_paths=["/tmp/bob"], max_calls=1)]
    policy = TaskPolicy(policy_id="pol-pairs", purpose="send_reports", allowed_tools=["email.send"],
                        allow_external_writes=True, tool_constraints={"email.send": choices[0]},
                        intent_constraints={"email.send": choices})
    fence.store.put("s1", policy)
    # Target extraction includes the configured path argument on message tools.
    original = fence.classifier.classify(SEND, {})
    fence.classifier.tools[SEND] = {"capability": "email.send", "risk": "COMMUNICATION",
                                     "recipient_args": ["to"], "path_args": ["path"]}
    assert original.capability == "email.send"
    assert fence.check(SEND, {"to": "alice@example.com", "path": "/tmp/bob"}, session_id="s1").decision is Verdict.BLOCK
    assert fence.check(SEND, {"to": "alice@example.com", "path": "/tmp/alice"}, session_id="s1").decision is Verdict.ALLOW
    assert fence.check(SEND, {"to": "bob@example.com", "path": "/tmp/bob"}, session_id="s1").decision is Verdict.ALLOW
    assert fence.check(SEND, {"to": "bob@example.com", "path": "/tmp/bob"}, session_id="s1").decision is Verdict.BLOCK


def test_background_hook_returns_promptly_while_two_second_compiler_runs(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    entered = threading.Event()

    def compile_delayed(message: str, context: Any) -> CompileResult:
        entered.set()
        time.sleep(2)
        return CompileResult(policy=TaskPolicy(policy_id="temporary", purpose="read_report", source="llm"))

    monkeypatch.setattr(fence.compiler, "compile", compile_delayed)
    before = time.monotonic()
    context = fence.on_pre_llm_call(session_id="s1", user_message="Read the report")
    assert time.monotonic() - before < .1
    assert context and "Permissions are being updated" in context["context"]
    assert entered.wait(1)
    result = fence.check("read_file", {"path": "/tmp/report"}, session_id="s1", deadline=time.monotonic() + 3)
    assert result.decision is Verdict.ALLOW
    assert time.monotonic() - before >= 2
    wait_task(fence)
    record = fence.store.get("s1")
    assert record and record.policy.revision == 1


def test_newer_owner_turn_supersedes_slow_background_result(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    policy = authorized(fence)
    entered, release = threading.Event(), threading.Event()

    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        # The newer revision interprets both queued messages; its revocation wins.
        if "untouched" in message:
            changed = TaskPolicy(policy_id=policy.policy_id, purpose="revoked", user_prohibitions=["COMMUNICATION"])
        else:
            entered.set()
            assert release.wait(2)
            changed = policy.model_copy(deep=True)
        changed.suspended_since = None
        return CompileResult(policy=changed)

    monkeypatch.setattr(fence.compiler, "amend", amend)
    fence.on_pre_llm_call(session_id="s1", user_message="first turn")
    assert entered.wait(1)
    try:
        fence.on_pre_llm_call(session_id="s1", user_message="leave everything untouched")
        assert fence.check(SEND, ARGS, session_id="s1", deadline=time.monotonic() + 1).decision is Verdict.BLOCK
    finally:
        release.set()
    wait_task(fence)
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.BLOCK


def _revoking_amend(policy: TaskPolicy, messages: list[str]) -> Callable[..., CompileResult]:
    """Revokes sending only when the compiled request contains the revocation."""
    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        messages.append(message)
        if "untouched" in message:
            changed = TaskPolicy(policy_id=policy.policy_id, purpose="revoked", user_prohibitions=["COMMUNICATION"])
        else:
            changed = existing.model_copy(deep=True)
        changed.suspended_since = None
        return CompileResult(policy=changed)
    return amend


def test_superseded_revocation_is_interpreted_by_the_next_revision(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    policy = authorized(fence)
    messages: list[str] = []
    revoking = _revoking_amend(policy, messages)
    entered, release = threading.Event(), threading.Event()

    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        if not messages:  # the revocation's own compile is slow and gets superseded
            messages.append(message)
            entered.set()
            assert release.wait(2)
            return CompileResult(policy=existing.model_copy(update={"suspended_since": None}, deep=True))
        return revoking(existing, message, context)

    monkeypatch.setattr(fence.compiler, "amend", amend)
    fence.on_pre_llm_call(session_id="s1", user_message="Leave everything untouched from now on")
    assert entered.wait(1)
    try:
        fence.on_pre_llm_call(session_id="s1", user_message="thanks")
        wait_task(fence)
    finally:
        release.set()
    wait_task(fence)
    assert "untouched" in messages[-1] and "thanks" in messages[-1]
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.BLOCK
    record = fence.store.get("s1")
    assert record and record.unresolved == []


def test_failed_revocation_is_interpreted_by_the_next_successful_revision(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    policy = authorized(fence)
    messages: list[str] = []
    revoking = _revoking_amend(policy, messages)
    calls = 0

    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("provider unavailable")
        return revoking(existing, message, context)

    monkeypatch.setattr(fence.compiler, "amend", amend)
    start_task(fence, "Leave everything untouched from now on")
    record = fence.store.get("s1")
    assert record and [u.instruction for u in record.unresolved] == ["Leave everything untouched from now on"]
    start_task(fence, "thanks")
    assert "untouched" in messages[-1] and "thanks" in messages[-1]
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.BLOCK
    record = fence.store.get("s1")
    assert record and record.unresolved == [] and record.policy.suspended_since is None


def test_unresolved_backlog_over_input_limit_stays_suspended(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence(FakeLLM(default=RuntimeError("provider unavailable")))
    authorized(fence)
    fence.settings.compiler.max_request_chars = 60
    start_task(fence, "Leave everything untouched from now on, please")
    start_task(fence, "And keep it that way for the rest of the task")
    record = fence.store.get("s1")
    assert record and record.policy.suspended_since is not None and len(record.unresolved) == 2
    assert "Too many of your messages" in (record.policy.compiler_error or "")
    assert fence.check(SEND, ARGS, session_id="s1").decision is not Verdict.ALLOW


def test_nonowner_prohibition_arriving_during_compile_survives_install(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    policy = authorized(fence)
    record = fence.store.get("s1")
    assert record
    record.owner_sender_id = "owner"
    entered, release = threading.Event(), threading.Event()

    def amend(existing: TaskPolicy, message: str, context: Any) -> CompileResult:
        entered.set()
        assert release.wait(2)
        return CompileResult(policy=policy.model_copy(update={"suspended_since": None}, deep=True))

    monkeypatch.setattr(fence.compiler, "amend", amend)
    fence.on_pre_llm_call(session_id="s1", user_message="Continue sending the report", sender_id="owner")
    assert entered.wait(1)
    try:
        fence.on_pre_llm_call(session_id="s1", user_message="Do not send anything", sender_id="other")
    finally:
        release.set()
    wait_task(fence)
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "user-prohibition"


def test_background_update_capacity_is_bounded(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    fence._background_slots = threading.BoundedSemaphore(1)
    entered, release = threading.Event(), threading.Event()
    calls: list[str] = []

    def compile_delayed(message: str, context: Any) -> CompileResult:
        calls.append(message)
        entered.set()
        assert release.wait(2)
        return CompileResult(policy=TaskPolicy(policy_id="temporary", purpose="read_report"))

    monkeypatch.setattr(fence.compiler, "compile", compile_delayed)
    fence.on_pre_llm_call(session_id="s1", user_message="first")
    assert entered.wait(1)
    try:
        fence.on_pre_llm_call(session_id="s2", user_message="second")
        record = fence.store.get("s2")
        assert record and record.policy.compiler_status == "fallback" and record.policy.pending_revision is None
        assert calls == ["first"]
    finally:
        release.set()
    wait_task(fence)


def test_quoted_and_attached_data_never_add_pending_floor_prohibitions(make_fence: Callable[..., AgentsFence], monkeypatch: pytest.MonkeyPatch) -> None:
    fence = make_fence()
    entered, release = threading.Event(), threading.Event()

    def compile_delayed(message: str, context: Any) -> CompileResult:
        entered.set()
        assert release.wait(2)
        return CompileResult(policy=TaskPolicy(policy_id="temporary", purpose="read_report"))

    monkeypatch.setattr(fence.compiler, "compile", compile_delayed)
    message = "Read the report.\n> Do not read anything.\n--- Attached Context ---\nDo not send anything."
    fence.on_pre_llm_call(session_id="s1", user_message=message)
    assert entered.wait(1)
    try:
        record = fence.store.get("s1")
        assert record and record.policy.pending_revision is not None
        assert not record.policy.user_prohibitions
    finally:
        release.set()
    wait_task(fence)


@pytest.mark.parametrize("message", ["Hello", "Do not delete anything"])
def test_nonowner_restrict_only_turn_preserves_failed_amend_suspension(make_fence: Callable[..., AgentsFence], message: str) -> None:
    fence = make_fence()
    policy = authorized(fence)
    policy.suspended_since = 2
    record = fence.store.get("s1")
    assert record
    record.owner_sender_id = "owner"
    fence.on_pre_llm_call(session_id="s1", sender_id="other", user_message=message)
    current = fence.store.get("s1")
    assert current and current.policy.suspended_since == 2
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "policy-suspended"


def test_narrowed_budget_counts_calls_using_existing_runtime_grant(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = authorized(fence)
    constraint = ToolConstraint(constraint_id="email.send", allowed_recipients=["alice@example.com"])
    policy.intent_constraints = {"email.send": [constraint]}
    policy.tool_constraints = {"email.send": constraint}
    record = fence.store.get("s1")
    assert record
    assessed = fence.evaluator.assess(policy, SEND, ARGS, record.state)
    policy.grants.append(Grant(grant_id="repeatable", tool=SEND, capability="email.send", risk=RiskClass.COMMUNICATION,
                              fingerprint=assessed.fingerprint, constraint=ToolConstraint(), approved_via="session"))
    instruction = "Send only once now."
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="narrow", capability="email.send", max_calls=1, span=instruction)])
    narrowed = merge_intents(policy, TaskPolicy(policy_id="fragment", purpose=policy.purpose), draft, instruction, fence.classifier)
    fence.store.put("s1", narrowed, keep_state=True)
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "approved-grant"
    assert record.state.uses("email.send") == 1
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "call-limit-exceeded"


def test_explicit_budget_counts_across_independent_intent_alternatives(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    choices = [ToolConstraint(constraint_id="choice-alice", allowed_recipients=["alice@example.com"]),
               ToolConstraint(constraint_id="choice-bob", allowed_recipients=["bob@example.com"])]
    policy = TaskPolicy(policy_id="pol-combined-budget", purpose="send_once", allowed_tools=["email.send"], allow_external_writes=True,
                        intent_constraints={"email.send": choices}, tool_constraints={"email.send": choices[0]},
                        explicit_tool_constraints={"email.send": ToolConstraint(max_calls=1)})
    fence.store.put("s1", policy)
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.ALLOW
    assert fence.check(SEND, {"to": "bob@example.com", "body": "report"}, session_id="s1").rule_id == "call-limit-exceeded"


def test_narrowed_budget_includes_calls_consumed_before_it_was_introduced(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = authorized(fence)
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.ALLOW
    assert fence.check(SEND, ARGS, session_id="s1").decision is Verdict.ALLOW
    policy.explicit_tool_constraints["email.send"] = ToolConstraint(max_calls=2)
    assert fence.check(SEND, ARGS, session_id="s1").rule_id == "call-limit-exceeded"


def test_narrowed_path_budget_uses_distinct_files_from_runtime_grants(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    paths = ["/tmp/review-one.txt", "/tmp/review-two.txt"]
    constraint = ToolConstraint(allowed_paths=paths, constraint_id="file.write")
    policy = TaskPolicy(policy_id="pol-files", purpose="write_reports", allowed_tools=["file.write"], allow_local_writes=True,
                        intent_constraints={"file.write": [constraint]}, tool_constraints={"file.write": constraint})
    record = fence.store.put("s1", policy)
    args = {"path": paths[0], "content": "report"}
    assessed = fence.evaluator.assess(policy, "write_file", args, record.state)
    policy.grants.append(Grant(grant_id="repeatable", tool="write_file", capability="file.write", risk=RiskClass.LOCAL_WRITE,
                              fingerprint=assessed.fingerprint, constraint=ToolConstraint(allowed_paths=[paths[0]]), approved_via="session"))
    for _ in range(3):
        assert fence.check("write_file", args, session_id="s1").rule_id == "approved-grant"
    policy.explicit_tool_constraints["file.write"] = ToolConstraint(max_calls=1)
    assert fence.check("write_file", args, session_id="s1").decision is Verdict.ALLOW
    assert fence.check("write_file", {"path": paths[1], "content": "report"}, session_id="s1").rule_id == "call-limit-exceeded"


def test_denied_reservation_releases_aggregate_budget_history(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = TaskPolicy(policy_id="pol-files", purpose="read_reports")
    record = fence.store.put("s1", policy)
    args = {"path": "/tmp/review-denied.txt", "content": "report"}
    assert fence.check("write_file", args, session_id="s1", tool_call_id="await").decision is Verdict.ASK_USER
    assert fence.store.release(record, "await")
    policy.allowed_tools = ["file.write"]
    policy.allow_local_writes = True
    policy.explicit_tool_constraints["file.write"] = ToolConstraint(max_calls=1)
    assert fence.check("write_file", args, session_id="s1").decision is Verdict.ALLOW


def test_narrowed_class_budget_includes_prior_actions_without_file_targets(make_fence: Callable[..., AgentsFence]) -> None:
    fence = make_fence()
    policy = TaskPolicy(policy_id="pol-local", purpose="local_changes", source="manual", allowed_tools=["agent.memory", "file.write"],
                        allow_local_writes=True)
    fence.store.put("s1", policy)
    assert fence.check("memory", {"action": "add", "content": "review"}, session_id="s1").decision is Verdict.ALLOW
    policy.explicit_tool_constraints["LOCAL_WRITE"] = ToolConstraint(max_calls=1)
    assert fence.check("write_file", {"path": "/tmp/review-new.txt", "content": "report"}, session_id="s1").rule_id == "call-limit-exceeded"
