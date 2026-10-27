from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeLLM

from agentsfence.compiler import (
    Change,
    CompileContext,
    CompilerError,
    IntentDraft,
    IntentGrant,
    PolicyCompiler,
    Target,
    merge_intents,
    parse_intent,
    read_intents,
    validate_intents,
)
from agentsfence.compiler.interpret import INTENT_PROMPT, intent_prompt
from agentsfence.config import Settings
from agentsfence.evaluator import Evaluator
from agentsfence.guards import Guards
from agentsfence.models import ExecutionState, Grant, RiskClass, TaskPolicy, ToolConstraint, Verdict
from agentsfence.risk import RiskClassifier, normalize_path


def intent(span: str, capability: str = "email.send", *, mode: str = "request", targets: list[dict[str, str]] | None = None) -> IntentDraft:
    return IntentDraft.model_validate({"interpretation": [{"statement": "requested action", "quote": span}],
        "grants": [{"id": "g", "capability": capability, "mode": mode, "span": span, "targets": targets or []}]})


def target(value: str, kind: str = "recipient", role: str = "recipient") -> dict[str, str]:
    return {"value": value, "kind": kind, "role": role}


def validate(settings: Settings, draft: IntentDraft, instruction: str, **kwargs: Any) -> TaskPolicy:
    return validate_intents(draft, instruction, RiskClassifier(settings.risk_config), **kwargs)[0]


@pytest.mark.parametrize("wrapper", ["{}", "```json\n{}\n```", "{}\nTrailing explanatory prose"])
def test_intent_parser_tolerates_wrapping(wrapper: str) -> None:
    draft = intent("Send to bob@example.com")
    assert parse_intent(wrapper.format(draft.model_dump_json())) == draft


def test_malformed_intent_retries_only_once() -> None:
    calls = []
    def complete(system: str, user: str, schema: dict[str, Any], deadline: float | None) -> tuple[str, str]:
        calls.append(user)
        return "{malformed", "test"
    with pytest.raises(CompilerError, match="one retry"):
        read_intents(complete, [], "Send to bob@example.com")
    assert len(calls) == 2


def test_old_policy_json_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_intent('{"purpose":"old"}')


def test_intent_prompt_snapshot_and_size() -> None:
    system, user = intent_prompt([("send_email", "email.send", "COMMUNICATION")], "Send to bob@example.com")
    assert system == Path(__file__).with_name("snapshots").joinpath("intent_prompt.txt").read_text()
    assert user == "Owner request:\n<<<REQUEST>>>\nSend to bob@example.com\n<<<END>>>"
    old_length = int(Path(__file__).with_name("snapshots").joinpath("legacy_prompt_chars.txt").read_text())
    assert len(system) < old_length / 2
    assert system.startswith(INTENT_PROMPT)


@pytest.mark.parametrize("stages", [1, 2])
def test_stages_call_count(settings: Settings, stages: int) -> None:
    calls = []
    def complete(system: str, user: str, schema: dict[str, Any], deadline: float | None) -> tuple[str, str]:
        calls.append(system)
        if system.startswith("Interpret the owner's"):
            return '[{"statement":"send","quote":"Send to bob@example.com"}]', "test"
        return intent("Send to bob@example.com").model_dump_json(), "test"
    read_intents(complete, [], "Send to bob@example.com", stages=stages)
    assert len(calls) == stages


@pytest.mark.parametrize("mode,allowed,approval", [("request", True, False), ("conditional", True, True),
    ("informational", False, False), ("hypothetical", False, False)])
def test_modes(settings: Settings, mode: str, allowed: bool, approval: bool) -> None:
    p = validate(settings, intent("Send to bob@example.com", mode=mode), "Send to bob@example.com")
    assert ("email.send" in p.allowed_tools) is allowed
    assert ("email.send" in p.requires_approval) is approval


@pytest.mark.parametrize("capability", ["email.*", "unrecognized.wizard", "skill_manage"])
def test_unknown_wildcard_multiplexed_capabilities_drop(settings: Settings, capability: str) -> None:
    p = validate(settings, intent("Send to bob@example.com", capability), "Send to bob@example.com")
    assert not p.allowed_tools


def test_normalized_span_and_non_english_grant(settings: Settings) -> None:
    p = validate(settings, intent("Envoyez le résumé à bob@example.com", targets=[target("bob@example.com")]),
                 "Envoyez   le résumé à bob@example.com")
    assert p.allow_external_writes and p.tool_constraints["email.send"].allowed_recipients == ["bob@example.com"]
    assert not p.allowed_recipients and not p.allowed_paths


def test_adversarial_negated_request_and_interpretation_target(settings: Settings) -> None:
    p = validate(settings, intent("Do not email bob@example.com", targets=[target("bob@example.com")]), "Do not email bob@example.com")
    assert not p.allowed_tools and "COMMUNICATION" in p.user_prohibitions
    draft = intent("Send a summary", targets=[target("invented@example.com")])
    draft.interpretation[0].statement = "Send to invented@example.com"
    p = validate(settings, draft, "Send a summary")
    assert p.tool_constraints["email.send"].allowed_recipients is None


def test_source_cannot_be_emitted_as_destination_or_recipient(settings: Settings) -> None:
    span = "Read /tmp/source.md and save to ~/result.md"
    p = validate(settings, intent(span, "file.write", targets=[target("/tmp/source.md", "path", "destination")]), span)
    assert p.tool_constraints["file.write"].allowed_paths is None
    span = "Read the email from alice@example.com and send the summary to bob@example.com"
    p = validate(settings, intent(span, targets=[target("alice@example.com"), target("bob@example.com")]), span)
    assert p.tool_constraints["email.send"].allowed_recipients == ["bob@example.com"]


@pytest.mark.parametrize("capability,span", [
    ("file.delete", "Delete the duplicate photos in ~/Pictures/dupes"),
    ("file.write", "Fix the broken code in ~/Pictures/dupes"),
    ("file.write", "Read /tmp/source.md and save the result in ~/Pictures/dupes"),
])
def test_in_binds_an_explicit_action_destination(settings: Settings, capability: str, span: str) -> None:
    policy = validate(settings, intent(span, capability, targets=[target("~/Pictures/dupes", "path", "destination")]), span)
    assert policy.tool_constraints[capability].allowed_paths == [normalize_path("~/Pictures/dupes")]
    if capability == "file.delete":
        ev = Evaluator(settings, RiskClassifier(settings.risk_config), Guards(settings.guards, agentsfence_home=settings.home))
        for path, verdict in [("~/Pictures/dupes/a.jpg", Verdict.ALLOW), ("~/Pictures/other/a.jpg", Verdict.BLOCK)]:
            assert ev.evaluate(policy, "patch", {"mode": "patch", "patch":
                f"*** Begin Patch\n*** Delete File: {path}\n*** End Patch"}, ExecutionState()).decision is verdict


@pytest.mark.parametrize("verb", ["Read the files", "Scan the notes", "Review the documents", "Search for reports", "Run the tests",
    "Read the file source.md", "Read the files matching " + "report" * 20])
def test_in_read_context_does_not_bind_a_write_destination(settings: Settings, verb: str) -> None:
    span = f"{verb} in ~/source/reports and save the summary to ~/output/report.md"
    policy = validate(settings, intent(span, "file.write", targets=[
        target("~/source/reports", "path", "destination"), target("~/output/report.md", "path", "destination")]), span)
    assert policy.tool_constraints["file.write"].allowed_paths == [normalize_path("~/output/report.md")]


def test_grants_do_not_cross_bind_or_authorize_persistent_state(settings: Settings) -> None:
    span = "Send to bob@example.com and save to ~/a.md"
    draft = intent(span, targets=[target("bob@example.com")])
    draft.grants.extend([IntentGrant(id="write", capability="file.write", mode="request", span=span,
        targets=[Target(value="~/a.md", kind="path", role="destination")]),
        IntentGrant(id="memory", capability="agent.memory", mode="request", span=span),
        IntentGrant(id="skill", capability="skill.manage", mode="request", span=span)])
    p = validate(settings, draft, span)
    assert p.allowed_tools == ["email.send", "file.write"]
    assert p.tool_constraints["email.send"].allowed_paths is None
    assert p.tool_constraints["file.write"].allowed_recipients is None
    assert p.tool_constraints["file.write"].allowed_paths == [normalize_path("~/a.md")]


@pytest.mark.parametrize("path", ["/", "~", "/Users", "/tmp"])
def test_broad_path_is_unbound(settings: Settings, path: str) -> None:
    span = f"Save to {path}"
    p = validate(settings, intent(span, "file.write", targets=[target(path, "path", "destination")]), span)
    assert p.tool_constraints["file.write"].allowed_paths is None


@pytest.mark.parametrize("capability", ["payment.pay", "file.share"])
def test_sensitive_actions_require_approval(settings: Settings, capability: str) -> None:
    classifier = RiskClassifier(settings.risk_config)
    settings.raw.setdefault("tools", {})["pay_vendor"] = {"capability": "payment.pay", "risk": "FINANCIAL"}
    classifier = RiskClassifier(settings.risk_config)
    span = "Pay vendor or share file with bob@example.com"
    p, _ = validate_intents(intent(span, capability), span, classifier)
    assert p.requires_approval


def old_send() -> TaskPolicy:
    c = ToolConstraint(allowed_recipients=["alice@example.com", "bob@example.com"], max_calls=5)
    return TaskPolicy(policy_id="old", purpose="send", allowed_tools=["email.send"], allow_external_writes=True,
        tool_constraints={"email.send": c}, intent_constraints={"email.send": [c]}, prohibition_origins={"DELETE": 1})


def test_random_narrow_never_adds_authority(settings: Settings) -> None:
    rng = random.Random(617)
    classifier = RiskClassifier(settings.risk_config)
    for _ in range(80):
        old = old_send()
        chosen = rng.sample(["alice@example.com", "bob@example.com", "outsider@example.com"], rng.randrange(4))
        span = "Only send to " + ", ".join(chosen)
        count = rng.randrange(8)
        change = Change(op="narrow", capability="email.send", target_kind="recipient", targets=[Target(**target(v)) for v in chosen],
                        span=span, max_calls=count)
        draft = IntentDraft(interpretation=[], grants=[], changes=[change])
        p = merge_intents(old, TaskPolicy(policy_id="new", purpose="send"), draft, span, classifier)
        for c in p.intent_constraints.get("email.send", []):
            assert set(c.allowed_recipients or []) <= {"alice@example.com", "bob@example.com"}
            assert c.max_calls is not None and c.max_calls <= min(5, count)
        assert p.prohibition_origins == old.prohibition_origins
        assert p.revision == old.revision + 1


def test_invalid_replace_removes_old_without_adding_target(settings: Settings) -> None:
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="replace", capability="email.send", target_kind="recipient",
        span="Send to someone else instead", targets=[Target(**target("invented@example.com"))])])
    p = merge_intents(old_send(), TaskPolicy(policy_id="n", purpose="t"), draft, "Send to someone else instead", RiskClassifier(settings.risk_config))
    assert "email.send" not in p.allowed_tools
    assert "email.send" not in p.intent_constraints


def test_revoke_removes_runtime_grants(settings: Settings) -> None:
    old = old_send()
    old.grants = [Grant(grant_id="runtime", tool="send_email", capability="email.send", risk=RiskClass.COMMUNICATION,
        constraint=ToolConstraint(allowed_recipients=["alice@example.com"]), approved_via="once")]
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="revoke", capability="email.send", span="Stop sending")])
    p = merge_intents(old, TaskPolicy(policy_id="n", purpose="t"), draft, "Stop sending", RiskClassifier(settings.risk_config))
    assert not p.grants and "email.send" not in p.allowed_tools
    assert "email.send" in p.user_prohibitions


def test_reference_only_resolves_to_prior_authorized_target(settings: Settings) -> None:
    span = "Send to the same person"
    for person, expected in [("alice@example.com", ["alice@example.com"]), ("outsider@example.com", None)]:
        p = validate(settings, intent(span, targets=[target(person)]), span, previous=old_send())
        assert p.tool_constraints["email.send"].allowed_recipients == expected


def test_default_pipeline_uses_one_intent_call(settings: Settings) -> None:
    span = "Send to bob@example.com"
    llm = FakeLLM(default=intent(span, targets=[target("bob@example.com")]).model_dump())
    compiler = PolicyCompiler(settings, RiskClassifier(settings.risk_config), llm)
    result = compiler.compile(span, CompileContext(session_id="s"))
    assert not result.fell_back and result.attempts == 1
    assert result.policy.allow_external_writes


@pytest.mark.parametrize("responses,expected_calls,raises", [
    (["bad", '[{"statement":"send","quote":"Send"}]', '{"interpretation":[],"grants":[]}'], 3, False),
    (["bad", '[{"statement":"send","quote":"Send"}]', "bad"], 3, True),
    (["bad", "bad"], 2, True),
])
def test_two_stages_share_one_json_repair(responses: list[str], expected_calls: int, raises: bool) -> None:
    replies = iter(responses)
    calls = []
    def complete(system: str, user: str, schema: dict[str, Any], deadline: float | None) -> tuple[str, str]:
        calls.append(deadline)
        return next(replies), "test"
    if raises:
        with pytest.raises(CompilerError, match="one retry") as error:
            read_intents(complete, [], "Send", stages=2, deadline=123.0)
        assert error.value.calls == expected_calls
    else:
        _, _, measured = read_intents(complete, [], "Send", stages=2, deadline=123.0)
        assert measured == expected_calls
    assert calls == [123.0] * expected_calls


def test_replace_preserves_correlated_untouched_dimensions_and_budgets(settings: Settings) -> None:
    settings.raw.setdefault("tools", {})["send_via_service"] = {
        "capability": "email.send", "risk": "COMMUNICATION", "recipient_args": ["to"], "domain_args": ["service"]}
    classifier = RiskClassifier(settings.risk_config)
    ev = Evaluator(settings, classifier, Guards(settings.guards, agentsfence_home=settings.home))
    old = old_send()
    alternatives = [ToolConstraint(allowed_recipients=["alice@example.com"], allowed_domains=[domain],
        allowed_paths=[path], max_calls=limit, constraint_id=identity) for domain, path, limit, identity in [
            ("api.corp.example", "/tmp/first.md", 1, "email.send"),
            ("other.corp.example", "/tmp/second.md", 3, "second-send")]]
    old.intent_constraints = {"email.send": alternatives}
    old.tool_constraints = {"email.send": alternatives[0]}
    span = "Send to bob@example.com instead"
    draft = intent(span, targets=[target("bob@example.com")])
    draft.changes = [Change(op="replace", capability="email.send", target_kind="recipient", span=span,
        targets=[Target(**target("bob@example.com"))])]
    new = validate(settings, draft, span)
    result = merge_intents(old, new, draft, span, classifier)
    updated = result.intent_constraints["email.send"]
    assert [(c.allowed_domains, c.allowed_paths, c.max_calls, c.constraint_id) for c in updated] == [
        (c.allowed_domains, c.allowed_paths, c.max_calls, c.constraint_id) for c in alternatives]
    assert all(c.allowed_recipients == ["bob@example.com"] for c in updated)
    assert ev.evaluate(result, "send_via_service", {"to": "bob@example.com", "service": "evil.example"},
                       ExecutionState()).decision is Verdict.BLOCK


def test_narrow_preserves_existing_explicit_dimensions(settings: Settings) -> None:
    old = old_send()
    old.explicit_tool_constraints = {"email.send": ToolConstraint(allowed_domains=["api.corp.example"])}
    span = "Send at most one more message"
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="narrow", capability="email.send", max_calls=1, span=span)])
    result = merge_intents(old, TaskPolicy(policy_id="new", purpose="task"), draft, span, RiskClassifier(settings.risk_config))
    bound = result.explicit_tool_constraints["email.send"]
    assert bound.allowed_domains == ["api.corp.example"] and bound.max_calls == 1


def test_runtime_only_narrow_records_explicit_budget(settings: Settings) -> None:
    old = TaskPolicy(policy_id="runtime-only", purpose="task", grants=[Grant(grant_id="runtime", tool="send_email",
        capability="email.send", risk=RiskClass.COMMUNICATION, approved_via="session",
        constraint=ToolConstraint(allowed_recipients=["alice@example.com"]))])
    span = "Send at most one message"
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="narrow", capability="email.send", max_calls=1, span=span)])
    result = merge_intents(old, TaskPolicy(policy_id="new", purpose="task"), draft, span, RiskClassifier(settings.risk_config))
    assert result.grants == old.grants
    assert result.explicit_tool_constraints["email.send"].max_calls == 1
    assert not result.allowed_tools


def test_same_turn_revoke_cannot_be_lifted_by_duplicate_grant(settings: Settings) -> None:
    span = "Stop sending, then send to alice@example.com"
    draft = intent(span, targets=[target("alice@example.com")])
    draft.changes = [Change(op="revoke", capability="email.send", span="Stop sending")]
    result = merge_intents(old_send(), validate(settings, draft, span), draft, span, RiskClassifier(settings.risk_config))
    assert "email.send" in result.user_prohibitions


def test_same_span_narrow_grant_cannot_restore_outsider(settings: Settings) -> None:
    span = "Only send to alice@example.com and outsider@example.com"
    draft = intent(span, targets=[target("alice@example.com"), target("outsider@example.com")])
    draft.changes = [Change(op="narrow", capability="email.send", target_kind="recipient", span=span,
        targets=[Target(**target("alice@example.com")), Target(**target("outsider@example.com"))])]
    result = merge_intents(old_send(), validate(settings, draft, span), draft, span, RiskClassifier(settings.risk_config))
    assert all(c.allowed_recipients == ["alice@example.com"] for c in result.intent_constraints["email.send"])


@pytest.mark.parametrize("grant_span", [
    "Keep the report brief. Only send to alice@example.com via api.corp.example",
    "Only send to alice@example.com via api.corp.example",
    "send to alice@example.com via api.corp.example",
    "Only   SEND to alice@example.com via api.corp.example",
])
@pytest.mark.parametrize("include_change", [True, False])
def test_overlapping_narrow_grants_preserve_correlated_bounds_and_counters(settings: Settings, grant_span: str, include_change: bool) -> None:
    settings.raw.setdefault("tools", {})["send_via_service"] = {
        "capability": "email.send", "risk": "COMMUNICATION", "recipient_args": ["to"], "domain_args": ["service"]}
    classifier = RiskClassifier(settings.risk_config)
    old = old_send()
    old.intent_constraints["email.send"][0].allowed_domains = ["api.corp.example"]
    old.intent_constraints["email.send"][0].constraint_id = "existing-send-budget"
    span = "Keep the report brief. Only send to alice@example.com via api.corp.example"
    draft = intent(grant_span, targets=[target("alice@example.com")])
    draft.changes = [Change(op="narrow", capability="email.send", target_kind="recipient",
        span="Only send to alice@example.com", targets=[Target(**target("alice@example.com"))])]
    if not include_change:
        draft.changes = []  # model may recognize the request but omit its amendment operation
    result = merge_intents(old, validate(settings, draft, span), draft, span, classifier)
    assert len(result.intent_constraints["email.send"]) == 1
    c = result.intent_constraints["email.send"][0]
    assert c.allowed_domains == ["api.corp.example"] and c.constraint_id == "existing-send-budget" and c.max_calls == 5
    ev = Evaluator(settings, classifier, Guards(settings.guards, agentsfence_home=settings.home))
    for recipient, domain, state, verdict in [
        ("alice@example.com", "api.corp.example", ExecutionState(), Verdict.ALLOW),
        ("alice@example.com", "evil.example", ExecutionState(), Verdict.BLOCK),
        ("bob@example.com", "api.corp.example", ExecutionState(), Verdict.BLOCK),
        ("alice@example.com", "api.corp.example", ExecutionState(calls_by_key={"existing-send-budget": 5}), Verdict.BLOCK),
    ]:
        assert ev.evaluate(result, "send_via_service", {"to": recipient, "service": domain}, state).decision is verdict


def test_multiple_narrowings_do_not_resurrect_duplicate_grants(settings: Settings) -> None:
    span = "Only send to alice@example.com. Send at most one message."
    draft = intent("Only send to alice@example.com", targets=[target("alice@example.com")])
    draft.changes = [
        Change(op="narrow", capability="email.send", target_kind="recipient", span="Only send to alice@example.com",
            targets=[Target(**target("alice@example.com"))]),
        Change(op="narrow", capability="email.send", max_calls=1, span="Send at most one message"),
    ]
    result = merge_intents(old_send(), validate(settings, draft, span), draft, span, RiskClassifier(settings.risk_config))
    assert len(result.intent_constraints["email.send"]) == 1
    assert result.intent_constraints["email.send"][0].max_calls == 1


def test_disjoint_new_grant_remains_independent_of_narrowing(settings: Settings) -> None:
    span = "Only send to alice@example.com. Also send a separate report to outsider@example.com."
    draft = intent("Also send a separate report to outsider@example.com", targets=[target("outsider@example.com")])
    draft.changes = [Change(op="narrow", capability="email.send", target_kind="recipient", span="Only send to alice@example.com",
        targets=[Target(**target("alice@example.com"))])]
    result = merge_intents(old_send(), validate(settings, draft, span), draft, span, RiskClassifier(settings.risk_config))
    assert [c.allowed_recipients for c in result.intent_constraints["email.send"]] == [["alice@example.com"], ["outsider@example.com"]]


def test_only_target_floor_never_creates_an_omitted_grant(settings: Settings) -> None:
    span = "Only send to alice@example.com"
    old = TaskPolicy(policy_id="read", purpose="read", allowed_risk_classes=[RiskClass.READ])
    for grants, expected in [([], False), (intent(span, targets=[target("alice@example.com")]).grants, True)]:
        draft = IntentDraft(interpretation=[], grants=grants)
        result = merge_intents(old, validate(settings, draft, span), draft, span, RiskClassifier(settings.risk_config))
        assert ("email.send" in result.allowed_tools) is expected
        assert result.allow_external_writes is expected


def test_alternative_counter_id_survives_pruning_and_addition(settings: Settings) -> None:
    classifier = RiskClassifier(settings.risk_config)
    old = old_send()
    old.intent_constraints["email.send"] = [
        ToolConstraint(allowed_recipients=["alice@example.com"], max_calls=1, constraint_id="email.send"),
        ToolConstraint(allowed_recipients=["bob@example.com"], max_calls=1, constraint_id="bob-budget")]
    span = "Only send to bob@example.com"
    draft = IntentDraft(interpretation=[], grants=[], changes=[Change(op="narrow", capability="email.send", target_kind="recipient",
        span=span, targets=[Target(**target("bob@example.com"))])])
    narrowed = merge_intents(old, TaskPolicy(policy_id="new", purpose="task"), draft, span, classifier)
    assert narrowed.intent_constraints["email.send"][0].constraint_id == "bob-budget"
    span = "Send to alice@example.com"
    draft = intent(span, targets=[target("alice@example.com")])
    appended = merge_intents(narrowed, validate(settings, draft, span), draft, span, classifier)
    assert appended.intent_constraints["email.send"][0].constraint_id == "bob-budget"
    ev = Evaluator(settings, classifier, Guards(settings.guards, agentsfence_home=settings.home))
    state = ExecutionState(calls_by_key={"bob-budget": 1})
    assert ev.evaluate(appended, "send_email", {"to": "bob@example.com"}, state).decision is Verdict.BLOCK


def test_unseen_remote_writer_binds_destination(settings: Settings) -> None:
    span = "Write to ~/review/output.md"
    draft = intent(span, "mcp_quill_write_file", targets=[target("~/review/output.md", "path", "destination")])
    classifier = RiskClassifier(settings.risk_config)
    policy, _ = validate_intents(draft, span, classifier, catalogue=["mcp_quill_write_file"])
    ev = Evaluator(settings, classifier, Guards(settings.guards, agentsfence_home=settings.home))
    assert ev.evaluate(policy, "mcp_quill_write_file", {"path": "~/review/output.md"}, ExecutionState()).decision is Verdict.ALLOW
    assert ev.evaluate(policy, "mcp_quill_write_file", {"path": "~/review/other.md"}, ExecutionState()).decision is Verdict.BLOCK
    assert ev.evaluate(policy, "mcp_quill_write_file", {}, ExecutionState()).decision is Verdict.ASK_USER


def test_catalogue_preserves_remote_writer_risk_with_exact_tool_capability(settings: Settings) -> None:
    classifier = RiskClassifier(settings.risk_config)
    compiler = PolicyCompiler(settings, classifier, FakeLLM())
    catalogue = compiler._catalogue(CompileContext(available_tools=["write_file", "mcp_quill_write_file"]))
    assert ("write_file", "file.write", "LOCAL_WRITE") in catalogue
    assert ("mcp_quill_write_file", "mcp_quill_write_file", "EXTERNAL_WRITE") in catalogue
