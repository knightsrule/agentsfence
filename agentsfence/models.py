"""Pydantic data models for AgentsFence.

The central object is :class:`TaskPolicy`: an authorization contract compiled
from the user's intent. It is deliberately independent of the agent's plan —
the agent may replan freely, but every action must fall inside this envelope.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RiskClass(str, Enum):
    """What a tool call can do to the world, independent of its name."""

    READ = "READ"
    LOCAL_WRITE = "LOCAL_WRITE"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    COMMUNICATION = "COMMUNICATION"
    DELETE = "DELETE"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    FINANCIAL = "FINANCIAL"
    EXECUTION = "EXECUTION"
    UNKNOWN = "UNKNOWN"


#: Risk classes whose effects leave the user's machine or can't be undone.
CONSEQUENTIAL: frozenset[RiskClass] = frozenset(
    {
        RiskClass.EXTERNAL_WRITE,
        RiskClass.COMMUNICATION,
        RiskClass.DELETE,
        RiskClass.PERMISSION_CHANGE,
        RiskClass.FINANCIAL,
        RiskClass.EXECUTION,
        RiskClass.UNKNOWN,
    }
)


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ASK_USER = "ASK_USER"


class ToolProfile(BaseModel):
    """How AgentsFence understands one concrete tool (after classification)."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    capability: str
    risk: RiskClass
    #: ``mapped`` (explicit config), ``pattern`` (glob), ``inferred`` (verb heuristic), ``unknown``.
    source: Literal["mapped", "pattern", "inferred", "unknown"] = "mapped"
    recipient_args: tuple[str, ...] = ()
    domain_args: tuple[str, ...] = ()
    path_args: tuple[str, ...] = ()
    #: Arguments holding patch text whose headers name the files touched.
    patch_args: tuple[str, ...] = ()
    #: Arguments that define *what* the action does (e.g. ``command``), used to bind approvals.
    action_args: tuple[str, ...] = ()


class ToolConstraint(BaseModel):
    """Argument-level limits on one tool or capability."""

    model_config = ConfigDict(extra="forbid")

    #: Stable execution-counter key for an independent semantic grant.
    constraint_id: str | None = None
    allowed_recipients: list[str] | None = None
    allowed_domains: list[str] | None = None
    allowed_paths: list[str] | None = None
    max_calls: int | None = Field(default=None, ge=0)

    def is_empty(self) -> bool:
        return all(
            v is None
            for v in (self.allowed_recipients, self.allowed_domains, self.allowed_paths, self.max_calls)
        )


class Grant(BaseModel):
    """A minimal capability delta approved by the user at runtime.

    A grant covers exactly one action: the same tool, capability and risk
    class, and the same action fingerprint (a hash of the arguments that define
    what the call does: command, code, recipients, paths, ...). Message
    *content* is not part of the fingerprint.
    """

    grant_id: str
    tool: str
    capability: str
    risk: RiskClass | None = None
    fingerprint: str | None = None
    #: Human-readable description of the approved action (for /fence and audit).
    description: str = ""
    constraint: ToolConstraint
    approved_via: str  # "once" | "session" | "always" | "host-auto"
    granted_at: datetime = Field(default_factory=utcnow)


class TaskPolicy(BaseModel):
    """Task-scoped least-authority contract compiled from user intent."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str
    task_id: str | None = None
    session_id: str | None = None
    purpose: str = Field(min_length=1, max_length=200)
    summary: str = ""
    #: Display and audit only; never an input to authorization.
    interpretation: list[dict[str, str]] = Field(default_factory=list)

    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    allowed_risk_classes: list[RiskClass] = Field(default_factory=lambda: [RiskClass.READ])
    tool_constraints: dict[str, ToolConstraint] = Field(default_factory=dict)
    #: Complete alternatives for semantic grants; dimensions within one grant
    #: must match together, so destinations cannot cross-combine.
    intent_constraints: dict[str, list[ToolConstraint]] = Field(default_factory=dict)
    #: Deterministic follow-up restrictions. They restrict earlier authority and
    #: runtime approvals; they never introduce a tool or turn on a ceiling.
    explicit_tool_constraints: dict[str, ToolConstraint] = Field(default_factory=dict)

    allowed_external_domains: list[str] = Field(default_factory=list)
    #: Explicit "only use" boundary. Unlike a general domain allowlist, approvals
    #: cannot bypass it. None means no boundary; [] permits no external domain.
    restricted_external_domains: list[str] | None = None
    allowed_recipients: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)

    allow_local_writes: bool = False
    allow_external_writes: bool = False
    allow_destructive_actions: bool = False
    allow_financial_actions: bool = False
    allow_execution: bool = False
    allow_permission_changes: bool = False
    #: Upper bound on external writes + communications for the whole task. ``None`` = no cap.
    max_external_writes: int | None = None

    #: Tools / capabilities / risk classes that always need a human confirmation.
    requires_approval: list[str] = Field(default_factory=list)
    #: Things the user explicitly forbade. These win over everything, including approvals.
    user_prohibitions: list[str] = Field(default_factory=list)
    prohibition_origins: dict[str, int] = Field(default_factory=dict)
    instruction_conflicts: list[str] = Field(default_factory=list)
    last_user_turn: int = 1
    compiler_status: Literal["unverified", "verified", "fallback"] = "unverified"
    compiler_error: str | None = None

    grants: list[Grant] = Field(default_factory=list)

    source: Literal["llm", "fallback", "inherited", "manual"] = "llm"
    compiler_model: str | None = None
    request_digest: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    revision: int = 1
    #: Latest owner revision awaiting compilation. All dispatch waits for it.
    pending_revision: int | None = None
    #: Failed or in-flight revision: earlier consequential grants are suspended.
    suspended_since: int | None = None

    @field_validator("allowed_recipients", "allowed_external_domains")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return sorted({s.strip().lower() for s in v if s and s.strip()})

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires_at is not None and (now or utcnow()) >= self.expires_at

    def with_ttl(self, ttl: timedelta | None) -> TaskPolicy:
        if ttl is not None:
            self.expires_at = self.created_at + ttl
        return self


class Decision(BaseModel):
    """Result of evaluating one tool call against a policy."""

    decision: Verdict
    reason: str
    rule_id: str | None = None
    risk: RiskClass | None = None
    capability: str | None = None
    #: For ASK_USER: the smallest grant that would authorize this exact call.
    proposed_grant: ToolConstraint | None = None
    #: For ALLOW via a runtime approval: which grant was used.
    grant_id: str | None = None
    #: Hash of the arguments that define this exact action (see risk.action_fingerprint).
    fingerprint: str | None = None
    #: Human-readable description of the exact action (command, recipients, paths).
    action: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Verdict.ALLOW


NON_PATH_TARGET = "<non-path-action>"


class ExecutionState(BaseModel):
    """Mutable per-policy counters used for call-count constraints."""

    calls_by_tool: dict[str, int] = Field(default_factory=dict)
    calls_by_capability: dict[str, int] = Field(default_factory=dict)
    calls_by_risk: dict[str, int] = Field(default_factory=dict)
    #: Aggregate distinct-path history survives independent grant replacement;
    #: NON_PATH_TARGET stores the count of actions without verified paths.
    #: Keys are capability:<name> or risk:<class>.
    targets_by_scope: dict[str, dict[str, int]] = Field(default_factory=dict)
    #: Older records lacked aggregate path/risk history. Conservatively retain
    #: their consumed calls when a new explicit budget is introduced.
    untracked_path_calls_by_scope: dict[str, int] = Field(default_factory=dict)
    #: Calls counted against each matching ``tool_constraints`` key.
    calls_by_key: dict[str, int] = Field(default_factory=dict)
    #: Path-bound writes and deletes count distinct targets, not calls: for each key,
    #: the reserved or executed calls per normalized path. Rewriting a file the task
    #: already wrote is not a new target.
    targets_by_key: dict[str, dict[str, int]] = Field(default_factory=dict)
    grant_uses: dict[str, int] = Field(default_factory=dict)
    external_writes: int = 0

    def uses(self, key: str) -> int:
        """How much of a ``max_calls`` budget ``key`` has used: calls plus distinct targets."""
        return self.calls_by_key.get(key, 0) + sum(1 for n in self.targets_by_key.get(key, {}).values() if n > 0)

    def new_targets(self, key: str, targets: list[str]) -> list[str]:
        counted = self.targets_by_key.get(key, {})
        return [t for t in targets if counted.get(t, 0) <= 0]



class AuditEvent(BaseModel):
    """One line in the audit log. Argument values are redacted before this is built."""

    event: str
    timestamp: datetime = Field(default_factory=utcnow)
    session_id: str | None = None
    task_id: str | None = None
    policy_id: str | None = None
    tool: str | None = None
    tool_call_id: str | None = None
    capability: str | None = None
    risk: str | None = None
    arguments: dict[str, Any] | None = None
    decision: str | None = None
    reason: str | None = None
    rule_id: str | None = None
    details: dict[str, Any] | None = None
