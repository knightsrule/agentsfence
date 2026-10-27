"""Compatibility builder for canned historical model fixtures.

Only tests use this builder. Its emitted response is always IntentDraft JSON;
production has no legacy policy schema or lexical grant gates.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentsfence.compiler.interpret import Change, IntentDraft, IntentGrant, Interpretation, Prohibition, Target
from agentsfence.config import load_settings
from agentsfence.models import RiskClass
from agentsfence.risk import RiskClassifier


class Evidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    permission: str = Field(description="Risk class or capability this quote justifies, e.g. COMMUNICATION or email.send")
    quote: str = Field(description="Exact words copied from the user's instruction")


class DraftConstraint(BaseModel):
    model_config = ConfigDict(extra="ignore")

    allowed_recipients: list[str] | None = None
    allowed_domains: list[str] | None = None
    allowed_paths: list[str] | None = None
    max_calls: int | None = Field(default=None, ge=0)


class FixtureDraft(BaseModel):
    """The structured output requested from the compiler model."""

    model_config = ConfigDict(extra="ignore")

    purpose: str = Field(description="snake_case purpose, e.g. summarize_mortgage_statement")
    summary: str = Field(default="", description="One sentence, plain English")
    allowed_capabilities: list[str] = Field(default_factory=list)
    denied_capabilities: list[str] = Field(default_factory=list)
    allowed_risk_classes: list[RiskClass] = Field(default_factory=lambda: [RiskClass.READ])
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allow_local_writes: bool = False
    allow_external_writes: bool = False
    allow_destructive_actions: bool = False
    allow_financial_actions: bool = False
    allow_execution: bool = False
    allow_permission_changes: bool = False
    max_external_writes: int | None = None
    tool_constraints: dict[str, DraftConstraint] = Field(default_factory=dict)
    requires_approval: list[str] = Field(default_factory=list)
    user_prohibitions: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @field_validator("allowed_risk_classes", mode="before")
    @classmethod
    def _risk_classes(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return [RiskClass.READ]
        names = [(x.value if isinstance(x, RiskClass) else str(x)).strip().upper() for x in v]
        return [n for n in names if n in RiskClass.__members__]

    def intents(self, instruction: str = "") -> IntentDraft:
        classifier = RiskClassifier(load_settings().risk_config)
        grants = []
        caps = list(dict.fromkeys([*self.allowed_capabilities, *self.tool_constraints]))
        # These canned fixtures describe model semantics; classification is test-only.
        verbs = {"READ": r"read|fetch|open|search|browse|summar", "LOCAL_WRITE": r"save|copy|write|create|fix|edit|update|remember|store|export|download|implement|record|generate|add|refactor",
                 "COMMUNICATION": r"send|email|mail|invite|forward|message|reply|share", "DELETE": r"delete|remove|trash|duplicates|clean",
                 "EXECUTION": r"run|execute|fix|test|install|build", "FINANCIAL": r"pay|buy|transfer|purchase|order",
                 "PERMISSION_CHANGE": r"share|permission|grant", "EXTERNAL_WRITE": r"create|update|edit|schedule|upload|draft|add|post|invite"}
        for cap in caps:
            profile = classifier.classify(cap, {})
            risk = classifier.capability_risk(cap) if "." in cap and not cap.startswith("mcp_") else profile.risk
            if self.allow_local_writes and any(e.permission == "LOCAL_WRITE" for e in self.evidence) and re.search(r"write|save|patch|memory|skill", cap):
                risk = RiskClass.LOCAL_WRITE
            matching = [e.quote for e in self.evidence if e.permission.upper() == risk.value or e.permission == cap]
            span = next((q for q in matching if re.search(r"\b(?:" + verbs.get(risk.value, r"(?!)") + r")", q, re.I)), matching[0] if matching else "")
            if risk is RiskClass.READ:
                span = instruction or span
            mode = "request"
            if matching and not re.search(r"\b(?:" + verbs.get(risk.value, r"(?!)") + r")", span, re.I):
                mode = "informational"
            if re.match(r"\s*(?:explain|list|tell me|what|how|compare|review|analyze|describe|research|read about|summarize (?:how|save|the save))\b", span, re.I) and not re.search(r"[.!]\s*(?:Then\s+)?(?:delete|send|save)\b", span, re.I):
                mode = "informational"
            if cap in self.requires_approval or risk.value in self.requires_approval or re.match(r"\s*if\b", span, re.I):
                mode = "conditional"
            c = self.tool_constraints.get(cap, DraftConstraint())
            targets = [Target(value=v, kind="recipient", role="recipient") for v in (c.allowed_recipients if c.allowed_recipients is not None else self.allowed_recipients)]
            targets += [Target(value=v, kind="domain", role="destination") for v in (c.allowed_domains if c.allowed_domains is not None else self.allowed_domains)]
            targets += [Target(value=v, kind="path", role="destination") for v in (c.allowed_paths if c.allowed_paths is not None else self.allowed_paths)]
            grants.append(IntentGrant(id=f"fixture-{len(grants)}", capability=cap, mode=mode, span=span, targets=targets, max_calls=c.max_calls))
        prohibitions = []
        from agentsfence.compiler import extract_prohibitions
        for ban in [*self.user_prohibitions, *self.denied_capabilities]:
            if instruction and (ban in extract_prohibitions(instruction) or (ban.endswith(".read") and re.search(r"(?:do not|don't|never)\s+read\s+" + {"email":"(?:email|messages?|inbox)","file":"(?:files?|local)","web":"(?:web|pages?)"}.get(ban.split(".")[0], r"(?!)"), instruction, re.I))):
                subject = {"risk_class": ban} if ban.upper() in RiskClass.__members__ else {"capability": ban}
                prohibitions.append(Prohibition(span=instruction, **subject))
        changes = []
        if instruction and re.search(r"\bonly\b(?!\s+(?:once|read))|\binstead\b", instruction, re.I):
            for g in grants:
                for kind in {t.kind for t in g.targets}:
                    changes.append(Change(op="replace", capability=g.capability, target_kind=kind,
                                          targets=[t for t in g.targets if t.kind == kind], span=g.span))
        return IntentDraft(interpretation=[Interpretation(statement=self.purpose, quote=instruction)],
                           grants=grants, prohibitions=prohibitions, changes=changes, summary=self.summary or self.purpose)

    def model_dump_json(self, **kw: Any) -> str:
        return self.intents().model_dump_json(**kw)

PolicyDraft = FixtureDraft


def bound_targets(policy: Any, field: str) -> list[str]:
    """Inspect independently bound intent targets, preserving their policy representation."""
    name = "allowed_domains" if field == "allowed_external_domains" else field
    values = list(getattr(policy, field))
    for alternatives in policy.intent_constraints.values():
        for c in alternatives:
            values.extend(getattr(c, name) or [])
    return sorted(set(values))
