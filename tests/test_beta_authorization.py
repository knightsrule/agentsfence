"""Beta scope checks: retry never bypasses capability or target hardening."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest
from conftest import FakeLLM, draft, start_task, tool, verdict
from intent_fixtures import Evidence, PolicyDraft
from rules_client import RulesClient

from agentsfence.compiler import CompileContext, CompilerError, CompileResult, PolicyCompiler
from agentsfence.config import Settings
from agentsfence.evaluator import Evaluator
from agentsfence.guards import Guards
from agentsfence.models import ExecutionState, RiskClass, Verdict
from agentsfence.plugin import AgentsFence
from agentsfence.risk import RiskClassifier

SOURCE = "~/review/input.md"
OUTPUT = "~/review/output.md"
OTHER = "~/review/unrequested.md"


def write_draft(request: str, **fields: Any) -> PolicyDraft:
    values: dict[str, Any] = {
        "purpose": "save", "allowed_capabilities": ["file.write"], "allow_local_writes": True,
        "evidence": [Evidence(permission="LOCAL_WRITE", quote=request)],
    }
    values.update(fields)
    return draft(**values)


class SequenceLLM(FakeLLM):
    def __init__(self, outputs: list[PolicyDraft | str]) -> None:
        super().__init__()
        self.outputs = outputs

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append(user)
        output = self.outputs[min(len(self.calls) - 1, len(self.outputs) - 1)]
        return output.model_dump_json() if isinstance(output, PolicyDraft) else output


def decide(settings: Settings, result: CompileResult, name: str, args: dict[str, Any]) -> Verdict:
    classifier = RiskClassifier(settings.risk_config)
    evaluator = Evaluator(settings, classifier, Guards(settings.guards, agentsfence_home=settings.home))
    return evaluator.evaluate(result.policy, name, args, ExecutionState()).decision


def compile_with(settings: Settings, request: str, llm: Any) -> CompileResult:
    return PolicyCompiler(settings, RiskClassifier(settings.risk_config), llm).compile(request)


def test_omitted_save_is_not_retried_and_requires_approval(settings: Settings) -> None:
    llm = FakeLLM(default=draft(purpose="read", allowed_paths=[OUTPUT]))
    result = compile_with(settings, f"Save a summary to {OUTPUT}.", llm)
    assert len(llm.calls) == result.attempts == 1
    assert not result.fell_back
    assert not result.policy.allow_local_writes and "file.write" not in result.policy.allowed_tools
    assert decide(settings, result, "write_file", {"path": os.path.expanduser(OUTPUT), "content": "summary"}) is Verdict.ASK_USER


def test_retry_can_supply_a_valid_grant_without_restoration(settings: Settings) -> None:
    request = f"Save a copy of {SOURCE} to {OUTPUT}."
    llm = SequenceLLM(["malformed response", write_draft(request, allowed_paths=[SOURCE, OUTPUT])])
    result = compile_with(settings, request, llm)
    assert len(llm.calls) == result.attempts == 2 and not result.approval_required
    assert decide(settings, result, "write_file", {"path": os.path.expanduser(OUTPUT), "content": "summary"}) is Verdict.ALLOW
    assert decide(settings, result, "write_file", {"path": os.path.expanduser(SOURCE), "content": "overwrite"}) is Verdict.BLOCK
    assert decide(settings, result, "patch", {"path": os.path.expanduser(OTHER), "old_string": "a", "new_string": "b"}) is Verdict.BLOCK


def test_retry_malicious_source_and_persistent_grants_are_hardened(settings: Settings) -> None:
    request = f"Save a copy of {SOURCE} to {OUTPUT}."
    llm = SequenceLLM(["malformed response", write_draft(
        request, allowed_paths=[SOURCE], allowed_risk_classes=[RiskClass.READ, RiskClass.LOCAL_WRITE],
        allowed_capabilities=["file.write", "agent.memory", "skill.write", "LOCAL_WRITE"])])
    result = compile_with(settings, request, llm)
    assert result.attempts == 2 and not result.fell_back
    assert RiskClass.LOCAL_WRITE not in result.policy.allowed_risk_classes
    for name, args in [("write_file", {"path": os.path.expanduser(SOURCE), "content": "bad"}),
                       ("memory", {"action": "add", "content": "persist"}),
                       ("skill_manage", {"action": "create", "name": "persist"})]:
        assert decide(settings, result, name, args) is not Verdict.ALLOW


def test_local_file_save_does_not_authorize_remote_writes(settings: Settings) -> None:
    settings.raw["tools"]["crm_update"] = {"capability": "crm.update", "risk": "EXTERNAL_WRITE"}
    request = f"Save a summary to {OUTPUT}."
    result = compile_with(settings, request, FakeLLM(default=write_draft(
        request, allowed_capabilities=["file.write", "crm.update"], allow_external_writes=True,
        allowed_risk_classes=[RiskClass.READ, RiskClass.EXTERNAL_WRITE],
        evidence=[Evidence(permission="LOCAL_WRITE", quote=request), Evidence(permission="EXTERNAL_WRITE", quote="Save")])))
    assert not result.policy.allow_external_writes and RiskClass.EXTERNAL_WRITE not in result.policy.allowed_risk_classes
    assert decide(settings, result, "crm_update", {"record": "new"}) is Verdict.ASK_USER


@pytest.mark.parametrize("instruction", [
    f"Save a copy of {SOURCE} to {OUTPUT}.",
    f"Export {SOURCE} as {OUTPUT}.",
    f"Write the notes from {SOURCE} into {OUTPUT}.",
    f"Save {OUTPUT} using the notes in {SOURCE}.",
])
@pytest.mark.parametrize("grant", ["file.write", "write_file", "patch", "mcp_filesystem_write_file", "mcp_notes_save"])
def test_destination_bound_covers_capability_and_configured_aliases(settings: Settings, instruction: str, grant: str) -> None:
    settings.raw["tools"]["mcp_filesystem_write_file"] = {
        "capability": "file.write", "risk": "LOCAL_WRITE", "path_args": ["path"],
    }
    settings.raw["patterns"].insert(0, {
        "match": "mcp_notes_*", "capability": "file.write", "risk": "LOCAL_WRITE", "path_args": ["path"],
    })
    result = compile_with(settings, instruction, FakeLLM(default=write_draft(
        instruction, allowed_capabilities=[grant], allowed_paths=[SOURCE, OUTPUT])))
    for name in ["write_file", "patch", "mcp_filesystem_write_file", "mcp_notes_save"]:
        args = {"path": os.path.expanduser(SOURCE), "content": "overwrite", "old_string": "a", "new_string": "b"}
        assert decide(settings, result, name, args) is not Verdict.ALLOW
        if grant in ("file.write", name):
            args["path"] = os.path.expanduser(OUTPUT)
            assert decide(settings, result, name, args) is Verdict.ALLOW


@pytest.mark.parametrize("family", ["memory", "skill"])
def test_file_output_about_persistent_state_does_not_grant_that_state(settings: Settings, family: str) -> None:
    request = f"Save a summary of {family} changes to {OUTPUT}."
    result = compile_with(settings, request, FakeLLM(default=write_draft(
        request, allowed_risk_classes=[RiskClass.READ, RiskClass.LOCAL_WRITE],
        allowed_capabilities=["LOCAL_WRITE", "file.write", "agent.memory", "skill.write"])))
    assert decide(settings, result, "memory", {"action": "add", "content": "persist"}) is not Verdict.ALLOW
    assert decide(settings, result, "skill_manage", {"action": "create", "name": "persist"}) is not Verdict.ALLOW


@pytest.mark.parametrize("instruction", ["Create a summary of project status.", "Generate a project summary."])
def test_output_without_verified_destination_cannot_grant_broad_file_writes(settings: Settings, instruction: str) -> None:
    result = compile_with(settings, instruction, FakeLLM(default=write_draft(instruction)))
    assert decide(settings, result, "write_file", {"path": os.path.expanduser(OTHER), "content": "x"}) is Verdict.ASK_USER


@pytest.mark.parametrize("instruction,capability,tool_name,args", [
    ("Remember my favorite color is blue.", "agent.memory", "memory", {"action": "add", "content": "blue"}),
    ("Create a skill for formatting release notes.", "skill.write", "skill_manage", {"action": "create", "name": "release_notes"}),
])
def test_explicit_persistent_request_can_keep_its_own_capability(settings: Settings, instruction: str,
                                                              capability: str, tool_name: str, args: dict[str, Any]) -> None:
    result = compile_with(settings, instruction, FakeLLM(default=write_draft(instruction, allowed_capabilities=[capability])))
    assert decide(settings, result, tool_name, args) is Verdict.ALLOW


def test_multiplexed_read_alias_cannot_inherit_save_authority(settings: Settings) -> None:
    settings.raw["tools"]["notes"] = {
        "capability": "file.read", "risk": "READ", "arg_risk": {"action": {"write": "LOCAL_WRITE"}}, "path_args": ["path"],
    }
    request = f"Save a copy of {SOURCE} to {OUTPUT}."
    result = compile_with(settings, request, FakeLLM(default=write_draft(request, allowed_capabilities=["notes"])))
    assert decide(settings, result, "notes", {"action": "write", "path": os.path.expanduser(SOURCE), "content": "x"}) is not Verdict.ALLOW


def test_offline_does_not_grant_literal_save_or_send(settings: Settings) -> None:
    result = compile_with(settings, f"Save a summary to {OUTPUT} and email it to bob@example.com.", RulesClient())
    assert result.attempts == 1 and not result.policy.allowed_tools
    assert result.policy.allowed_risk_classes == [RiskClass.READ]
    assert decide(settings, result, "write_file", {"path": os.path.expanduser(OUTPUT), "content": "x"}) is Verdict.ASK_USER
    assert decide(settings, result, "mcp_gmail_send_message", {"to": "bob@example.com", "body": "x"}) is Verdict.ASK_USER


def test_retry_shares_original_deadline_and_keeps_hardened_result_on_timeout(settings: Settings,
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    moment = [100.0]
    monkeypatch.setattr("agentsfence.compiler.time.monotonic", lambda: moment[0])
    seen: list[float | None] = []
    compiler = PolicyCompiler(settings, RiskClassifier(settings.risk_config), FakeLLM())

    def complete(system: str, user: str, schema: dict[str, Any], deadline: float | None) -> tuple[str, str]:
        seen.append(deadline)
        if len(seen) == 1:
            moment[0] = 106.0
            return "malformed response", "fixture"
        raise CompilerError("compiler timed out before the host hook deadline")

    monkeypatch.setattr(compiler, "_complete", complete)
    result = compiler.compile(f"Save a summary to {OUTPUT}.", CompileContext(deadline=107.0))
    assert seen == [107.0, 107.0]
    assert result.fell_back and not result.policy.allow_local_writes


@pytest.mark.parametrize("client", [RulesClient(), FakeLLM(default=RuntimeError("offline"))])
def test_full_text_domain_restriction_survives_truncation_and_fallback(settings: Settings, client: Any) -> None:
    settings.compiler.max_request_chars = 30
    result = compile_with(settings, "Summarize this page. " + "Additional context. " * 10 + "Only use example.com.", client)
    assert result.policy.restricted_external_domains == ["example.com"]
    assert decide(settings, result, "web_extract", {"urls": ["https://other.example.org/"]}) is Verdict.BLOCK


@pytest.mark.parametrize("client", [RulesClient(), FakeLLM(default=draft(purpose="read"))])
def test_repeated_only_domain_clauses_cannot_union_their_bounds(settings: Settings, client: Any) -> None:
    result = compile_with(settings, "Only use example.com. Only use docs.example.com.", client)
    assert result.policy.restricted_external_domains == ["docs.example.com"]
    assert decide(settings, result, "web_extract", {"urls": ["https://example.com/"]}) is Verdict.BLOCK
    assert decide(settings, result, "web_extract", {"urls": ["https://docs.example.com/"]}) is Verdict.ALLOW


def test_configured_writer_with_missing_destination_asks(settings: Settings) -> None:
    settings.raw["tools"]["mcp_notes_save"] = {"capability": "file.write", "risk": "LOCAL_WRITE", "path_args": ["path"]}
    request = f"Save a summary to {OUTPUT}."
    result = compile_with(settings, request, FakeLLM(default=write_draft(request)))
    assert decide(settings, result, "mcp_notes_save", {"content": "missing path"}) is Verdict.ASK_USER


def test_omitted_grant_asks_without_summary_injection(make_fence: Callable[..., AgentsFence],
                                                                      settings: Settings, capsys: pytest.CaptureFixture[str]) -> None:
    settings.policy.inject_summary = False
    fence = make_fence(FakeLLM(default=draft(purpose="read")))
    start_task(fence, f"Save a summary to {OUTPUT}.")
    assert not fence.store.get("s1").policy.allow_local_writes
    assert verdict(tool(fence, "write_file", {"path": os.path.expanduser(OUTPUT), "content": "x"})) == "ASK_USER"
