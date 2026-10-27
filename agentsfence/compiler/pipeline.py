"""Compiler pipeline stage."""

from __future__ import annotations

import contextvars
import threading
import time as time
import uuid
from concurrent.futures import Future, TimeoutError
from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..config import Settings
from ..models import TaskPolicy
from ..risk import RiskClassifier
from .floor import _explicit_target_constraints, explicit_domain_restriction, extract_prohibitions
from .interpret import (
    CompilerError,
    IntentDraft,
    LLMClient,
    make_client,
    read_intents,
)
from .merge import _grant_within_policy, merge_intents
from .split import split_instruction
from .validate import _digest, validate_intents


class CompileContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str | None = None
    task_id: str | None = None
    platform: str = ""
    available_tools: list[str] = Field(default_factory=list)
    existing_policy: TaskPolicy | None = None
    deadline: float | None = None  # monotonic host-hook budget; never part of a policy

class CompileResult(BaseModel):
    policy: TaskPolicy
    fell_back: bool = False
    error: str | None = None
    dropped: list[str] = Field(default_factory=list)
    attempts: int = 0
    approval_required: list[str] = Field(default_factory=list)
    intent: IntentDraft | None = None

class PolicyCompiler:
    def __init__(self, settings: Settings, classifier: RiskClassifier, client: LLMClient | None = None):
        self.settings = settings
        self.classifier = classifier
        self.client = client or make_client(settings)
        self._call_slots = threading.BoundedSemaphore(settings.compiler.max_concurrent_requests)

    def compile(self, user_request: str, context: CompileContext | None = None) -> CompileResult:
        context = context or CompileContext()
        deadline = time.monotonic() + self.settings.compiler.timeout_seconds
        deadline = min(deadline, context.deadline) if context.deadline is not None else deadline
        instruction, _ = split_instruction(user_request)
        try:
            draft, model, attempts = read_intents(self._complete, self._catalogue(context),
                instruction[:self.settings.compiler.max_request_chars], previous=context.existing_policy,
                stages=self.settings.compiler.stages, deadline=deadline)
            policy, dropped = validate_intents(draft, instruction, self.classifier, session_id=context.session_id,
                task_id=context.task_id, catalogue=context.available_tools, previous=context.existing_policy,
                require_sensitive_approval=self.settings.compiler.require_sensitive_approval, user_request=user_request)
            policy.compiler_model = model
            return CompileResult(policy=policy.with_ttl(self._ttl()), dropped=dropped, attempts=attempts, intent=draft)
        except Exception as exc:
            policy = self.fallback(context, user_request)
            policy.user_prohibitions = extract_prohibitions(instruction)
            policy.restricted_external_domains = explicit_domain_restriction(instruction)
            policy.explicit_tool_constraints = _explicit_target_constraints(instruction)
            return CompileResult(policy=policy, fell_back=True, error=str(exc), attempts=getattr(exc, "calls", 0) or 1)

    def amend(self, existing: TaskPolicy, user_request: str, context: CompileContext | None = None) -> CompileResult:
        context = (context or CompileContext()).model_copy(update={"existing_policy": existing})
        result = self.compile(user_request, context)
        instruction, _ = split_instruction(user_request)
        merged = merge_intents(existing, result.policy, result.intent or IntentDraft(interpretation=[], grants=[]),
                              instruction, self.classifier, require_sensitive_approval=self.settings.compiler.require_sensitive_approval)
        if result.fell_back:
            merged.suspended_since = existing.pending_revision or merged.revision
            merged.explicit_tool_constraints.update(result.policy.explicit_tool_constraints)
            merged.grants = [g for g in merged.grants if _grant_within_policy(g, merged)]
        result.policy = merged
        return result

    def fallback(self, context: CompileContext, user_request: str = "") -> TaskPolicy:
        fb = dict(self.settings.fallback_policy)
        pol = TaskPolicy(
            policy_id=f"pol-{uuid.uuid4().hex[:12]}", session_id=context.session_id, task_id=context.task_id,
            purpose=str(fb.pop("purpose", "fallback_read_only")),
            summary=str(fb.pop("summary", "Read-only fallback policy.")),
            source="fallback", request_digest=_digest(user_request) if user_request else None,
            **{k: v for k, v in fb.items() if k in TaskPolicy.model_fields},
        )
        return pol.with_ttl(self._ttl())

    def _ttl(self) -> timedelta | None:
        h = self.settings.policy.ttl_hours
        return timedelta(hours=h) if h else None

    def _catalogue(self, context: CompileContext) -> list[tuple[str, str, str]]:
        out = []
        for name in context.available_tools:
            p = self.classifier.classify(name, {})
            # An inferred remote writer can share file.write's name but not its
            # LOCAL_WRITE risk. Advertise the exact tool so validation preserves
            # its actual risk instead of proposing the generic local capability.
            capability = name if self.classifier.capability_risk(p.capability) is not p.risk else p.capability
            out.append((name, capability, p.risk.value))
        return out

    def _complete(self, system: str, user: str, schema: dict[str, Any], deadline: float | None) -> tuple[str, str | None]:
        """Bound queueing and provider time; abandoned workers can only return strings."""
        remaining = (deadline - time.monotonic()) if deadline is not None else self.settings.compiler.timeout_seconds
        if remaining <= 0:
            raise CompilerError("compiler timed out before the host hook deadline")
        if not self._call_slots.acquire(timeout=remaining):
            raise CompilerError("compiler capacity exhausted; provider requests are still running")
        remaining = (deadline - time.monotonic()) if deadline is not None else remaining
        if remaining <= 0:
            self._call_slots.release()
            raise CompilerError("compiler capacity exhausted before the host hook deadline")
        future: Future[tuple[str, str | None]] = Future()
        context = contextvars.copy_context()

        def call() -> None:
            try:
                result = context.run(self.client.complete, system, user, schema)
                model = getattr(self.client, "name", None)
            except BaseException as exc:
                self._call_slots.release()
                future.set_exception(exc)
            else:
                self._call_slots.release()
                future.set_result((result, model))

        worker = threading.Thread(target=call, daemon=True, name="agentsfence-compiler")
        try:
            worker.start()
        except BaseException:
            self._call_slots.release()
            raise
        try:
            return future.result(timeout=remaining)
        except TimeoutError as exc:
            raise CompilerError("compiler timed out before the host hook deadline") from exc
