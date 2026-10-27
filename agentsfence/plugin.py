"""Hermes Agent plugin integration.

Hook map (see HERMES_API.md for the verified Hermes contracts):

==========================  ================================================
Hermes hook                 AgentsFence behaviour
==========================  ================================================
``pre_llm_call``            first user turn → compile + store policy;
                            later turns → amend from the owner's new message
``pre_tool_call``           evaluate → ``None`` (ALLOW) / ``block`` / ``approve``
``post_approval_response``  record the user's choice, mint an exact-action grant
``post_tool_call``          settle or release call-count reservations
``subagent_start``          bind the child session to the parent's policy
``on_session_reset``        drop the session's policy (``/new``)
``on_session_finalize``     drop it at a session boundary; keep it on shutdown
                            so ``--resume`` keeps the same restrictions
==========================  ================================================

Two Hermes behaviours shape this module:

* Hermes swallows exceptions raised by hook callbacks and then lets the tool
  run. Every enforcement path here catches all exceptions and turns them into
  an explicit ``block``. If AgentsFence itself fails to start, ``register``
  installs a stub that blocks every tool call.
* Hermes resolves ``pre_tool_call`` directives as ``block`` > ``approve`` > none,
  whatever order plugins registered in, so another plugin's ``approve`` never
  hides AgentsFence's ``block``. `agentsfence doctor` verifies that behaviour
  (see ``preflight``) before a profile is protected.
"""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import logging
import math
import os
import sys
import threading
import time
import uuid
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from . import failsafe
from .audit import AuditLog, configure_logging
from .compiler import (
    CompileContext,
    CompilerError,
    LLMClient,
    PolicyCompiler,
    _explicit_target_constraints,
    combined_instruction,
    explicit_domain_restriction,
    extract_prohibitions,
    instruction_conflicts,
    make_client,
    merge_policies,
    split_instruction,
)
from .config import Settings, hermes_home, load_settings
from .diagnostics import public_compiler_error, record_compilation_state, register_runtime
from .evaluator import Evaluator
from .guards import Guards
from .models import AuditEvent, Decision, RiskClass, TaskPolicy, ToolConstraint, Verdict, utcnow
from .policy_store import PendingApproval, PolicyRecord, PolicyStore, Reservation
from .render import approval_message, block_message, conflict_notice, describe_policy, model_context_note, plain_actions
from .risk import RiskClassifier

logger = logging.getLogger("agentsfence.plugin")

RULE_PREFIX = "agentsfence:"
_OUTBOUND = (RiskClass.EXTERNAL_WRITE, RiskClass.COMMUNICATION)
#: Only a human's answer mints a grant. ("smart_approve" — an auxiliary LLM — does not.)
_APPROVED_CHOICES = {"once", "session", "always"}


def _default_yolo() -> bool:
    """True for Hermes' process/session approval bypass modes."""
    try:
        from tools.approval import is_approval_bypass_active

        if is_approval_bypass_active():
            return True
    except Exception:
        # Inside a Hermes process, losing the approval API must not turn an
        # unattended approval mode into an apparently human-gated question.
        if "hermes_cli.plugins" in sys.modules:
            return True
    return os.environ.get("HERMES_YOLO_MODE", "").strip().lower() in {"1", "true", "yes", "on"}


def _default_approval_auto(rule_key: str) -> bool:
    """Detect per-rule allowlists and unattended cron approvals.

    Hermes checks the same ``plugin_rule:`` key before showing a prompt. Cron
    sessions have no human to answer, regardless of whether Hermes' configured
    response is approve or deny, so a strict/fallback question is blocked.
    """
    if os.environ.get("HERMES_CRON_SESSION", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    try:
        from tools.approval import get_current_session_key, is_approved

        return bool(is_approved(get_current_session_key(), f"plugin_rule:{rule_key}"))
    except Exception:
        return "hermes_cli.plugins" in sys.modules


def _default_catalogue() -> list[str]:
    try:
        from tools.registry import registry

        return sorted(registry.get_all_tool_names())
    except Exception:
        return []


def _default_is_gateway() -> bool:
    try:
        from tools.approval import _is_gateway_approval_context

        return bool(_is_gateway_approval_context())
    except Exception:
        return bool(os.environ.get("HERMES_GATEWAY_SESSION"))


def host_hook_budget() -> tuple[float | None, str]:
    """Hermes' hook-callback timeout and its source: "host", "disabled" (0) or "assumed".

    Hermes bounds hooks by ``plugins.hook_callback_timeout`` (0 disables the bound).
    If that lookup ever fails, 30s (Hermes' default) is assumed, not verified.
    """
    try:
        from hermes_cli.plugins import _resolve_hook_callback_timeout
    except ImportError:
        return 30.0, "assumed"
    try:
        budget = float(_resolve_hook_callback_timeout())
        if not math.isfinite(budget) or budget < 0:
            raise ValueError("invalid host hook timeout")
    except Exception as exc:
        logger.warning("Hermes hook timeout lookup failed (%s); assuming a 30s budget", type(exc).__name__)
        return 30.0, "assumed"
    return (None, "disabled") if budget == 0 else (budget, "host")


def _host_hook_deadline() -> float | None:
    budget, _source = host_hook_budget()
    return time.monotonic() + budget * 0.8 if budget else None


def compile_budget(settings: Settings) -> dict[str, Any]:
    """The effective compile budget: the compiler timeout, capped at 80% of Hermes' hook timeout.

    ``limited_by`` names the setting that decides it; raising the other one changes nothing.
    """
    host, source = host_hook_budget()
    timeout = settings.compiler.timeout_seconds
    hook_bound = host * 0.8 if host else None
    seconds = min(timeout, hook_bound) if hook_bound is not None else timeout
    limited_by = "plugins.hook_callback_timeout" if hook_bound is not None and hook_bound < timeout else "compiler.timeout_seconds"
    return {"budget_seconds": round(seconds, 1), "budget_source": source, "limited_by": limited_by,
            "compiler_timeout": timeout, "hook_timeout": host}


BUDGET_ADVICE = ("Use a faster compiler model, or raise both limits with `agentsfence settings --compile-budget SECONDS`: "
                 "the budget is the smaller of AgentsFence's `compiler.timeout_seconds` and 80% of Hermes' "
                 "`plugins.hook_callback_timeout`, so raising one alone changes nothing.")


def budget_limit(budget: dict[str, Any]) -> str:
    """Which setting decides the compile budget, in words."""
    limited_by, source = budget.get("limited_by"), budget.get("budget_source")
    if limited_by == "plugins.hook_callback_timeout":
        if source == "assumed":
            return "Hermes' hook timeout could not be read, so its 30s default is assumed"
        return (f"Hermes' `plugins.hook_callback_timeout` ({budget.get('hook_timeout'):g}s, of which AgentsFence uses 80%) "
                "sets it")
    if limited_by == "compiler.timeout_seconds":
        return f"AgentsFence's `compiler.timeout_seconds` ({budget.get('compiler_timeout'):g}s) sets it"
    return f"Budget source: {source}"  # evidence recorded before 0.2.0a7


def budget_warning(seconds: float | None, budget: dict[str, Any], model: str | None) -> str | None:
    """Advisory only: a compile that used over half its budget is close to falling back."""
    limit = budget.get("budget_seconds")
    if not seconds or not limit or seconds <= limit / 2:
        return None
    return (f"The compile took {seconds:.1f}s of its {limit:.0f}s budget with {model or 'the policy model'}; a slower one "
            f"falls back to read-only. {budget_limit(budget)}. {BUDGET_ADVICE}")


class AgentsFence:
    """All plugin state and hook handlers. One instance per Hermes process."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: LLMClient | None = None,
        plugin_llm_factory: Callable[[], Any] | None = None,
        store: PolicyStore | None = None,
        audit: AuditLog | None = None,
        catalogue_fn: Callable[[], list[str]] = _default_catalogue,
        yolo_fn: Callable[[], bool] = _default_yolo,
        approval_auto_fn: Callable[[str], bool] = _default_approval_auto,
        gateway_fn: Callable[[], bool] = _default_is_gateway,
        persist: bool = True,
        plugin_dir: Path | None = None,
    ):
        self.settings = settings or load_settings()
        home = self.settings.home
        self.classifier = RiskClassifier(self.settings.risk_config)
        self.guards = Guards(self.settings.guards, agentsfence_home=home, plugin_dir=plugin_dir)
        self.evaluator = Evaluator(self.settings, self.classifier, self.guards)
        self._client = client
        # Resolved lazily: a broken host LLM must not stop the hooks registering.
        self._plugin_llm_factory = plugin_llm_factory
        self._compiler: PolicyCompiler | None = None
        self._compiler_lock = threading.Lock()
        self.store = store or PolicyStore(home / "policies", persist=persist)
        self.audit = audit or AuditLog(home / "audit.jsonl" if persist else None, self.settings.audit)
        self.catalogue_fn = catalogue_fn
        self.yolo_fn = yolo_fn
        self.approval_auto_fn = approval_auto_fn
        self.gateway_fn = gateway_fn
        self._compiling: dict[str, int] = {}
        self._turn_locks: dict[str, threading.Lock] = {}
        self._background_slots = threading.BoundedSemaphore(self.settings.compiler.max_concurrent_requests)
        self.host_safety_fn: Callable[[], str | None] | None = None

    @property
    def compiler(self) -> PolicyCompiler:
        with self._compiler_lock:
            return self._get_compiler()

    def _get_compiler(self) -> PolicyCompiler:
        # Built lazily so a misconfigured provider surfaces as a compile-time
        # fallback (audited), not as a plugin load failure.
        if self._compiler is None:
            try:
                client = self._client
                if client is None and self.settings.compiler.provider.lower() == "hermes":
                    if self._plugin_llm_factory is None:
                        raise RuntimeError("compiler.provider=hermes requires running inside Hermes")
                    client = make_client(self.settings, plugin_llm=self._plugin_llm_factory())
                self._compiler = PolicyCompiler(self.settings, self.classifier, client)
            except Exception as exc:
                logger.error("compiler unavailable: %s", exc)
                reason = str(exc)

                class _Broken:
                    name = "unavailable"

                    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
                        raise RuntimeError(f"compiler unavailable: {reason}")

                self._compiler = PolicyCompiler(self.settings, self.classifier, _Broken())
        return self._compiler

    # ------------------------------------------------------------------
    # pre_llm_call
    # ------------------------------------------------------------------

    def on_pre_llm_call(self, **kw: Any) -> dict[str, str] | None:
        kw["_agentsfence_deadline"] = _host_hook_deadline()
        try:
            return self._pre_llm_call(**kw)
        except Exception as exc:
            logger.exception("pre_llm_call failed")
            self._audit("error", session_id=kw.get("session_id"), details={"hook": "pre_llm_call", "error": str(exc)})
            return None

    def _record_compilation_state(self, sid: str, active: bool) -> None:
        try:
            record_compilation_state(self.settings, sid, active)
        except (OSError, ValueError, TypeError):
            logger.exception("Unable to record compilation status")

    def _pre_llm_call(self, **kw: Any) -> dict[str, str] | None:
        session_id = str(kw.get("session_id") or "")
        task_id = str(kw.get("task_id") or "")
        sender = str(kw.get("sender_id") or "")
        message = kw.get("user_message")
        user_message = message if isinstance(message, str) else ""
        sid = session_id or (f"task:{task_id}" if task_id else "")
        if not sid:
            return None
        instruction, _ = split_instruction(user_message)
        with self.store.locked():
            if self.store.is_linked_child(sid):
                if task_id:
                    self.store.alias_task(sid, task_id)
                return None
            rec = self.store.get(sid)
            if rec is not None and rec.policy.is_expired() and user_message and (not rec.owner_sender_id or not sender or sender == rec.owner_sender_id):
                self._audit("policy_expired", session_id=sid, task_id=task_id, policy=rec.policy,
                            details={"action": "recompile from the new message"})
                self.store.drop(sid)
                rec = None
            initial = rec is None
            if rec is None:
                placeholder = TaskPolicy(policy_id=f"pol-{uuid.uuid4().hex[:12]}", session_id=sid,
                                         task_id=task_id or None, purpose="permission_update", source="fallback", revision=0)
                if self.settings.policy.ttl_hours:
                    placeholder.expires_at = utcnow() + timedelta(hours=self.settings.policy.ttl_hours)
                rec = self.store.put(sid, placeholder, task_id=task_id or None)
                rec.owner_sender_id = sender or None
            elif task_id:
                self.store.alias_task(sid, task_id)
            rec.turns_seen += 1
            rec.policy.last_user_turn = rec.turns_seen
            rec.policy.instruction_conflicts = instruction_conflicts(instruction)
            if not user_message and not initial:
                self.store.save(rec)
                return None
            previous = rec.policy.model_copy(deep=True)
            other_sender = bool(rec.owner_sender_id and sender and sender != rec.owner_sender_id)
            floor = TaskPolicy(policy_id=rec.policy.policy_id, purpose=rec.policy.purpose,
                               user_prohibitions=extract_prohibitions(instruction),
                               instruction_conflicts=instruction_conflicts(instruction),
                               restricted_external_domains=None if other_sender else explicit_domain_restriction(instruction),
                               explicit_tool_constraints={} if other_sender else _explicit_target_constraints(instruction))
            rec.policy = merge_policies(rec.policy, floor, self.classifier)
            # Applying the floor is part of this owner revision, not an extra
            # compiled revision. begin_revision advances the generation once.
            rec.policy.revision = previous.revision
            rec.policy.pending_revision = previous.pending_revision
            rec.policy.suspended_since = previous.suspended_since
            for ban in floor.user_prohibitions:
                rec.policy.prohibition_origins.setdefault(ban, rec.turns_seen)
            rec.policy.last_user_turn = rec.turns_seen
            if other_sender:
                self.store.save(rec)
                self._audit("amend_restricted", session_id=sid, task_id=task_id, policy=rec.policy,
                            details={"reason": "message from a sender who does not own this task", "prohibitions_added": floor.user_prohibitions})
                return None
            revision = self.store.begin_revision(rec, instruction)
            snapshot = rec.policy.model_copy(deep=True)
            turn = rec.turns_seen
            # Interpret every owner message no successful compile has covered:
            # a superseded or failed revision's message (e.g. a revocation) must
            # never be skipped by the revision that replaces it.
            queued = [u.instruction for u in rec.unresolved]
            fresh = snapshot.revision == 0  # nothing compiled yet for this task
            self._compiling[sid] = self._compiling.get(sid, 0) + 1
            self._record_compilation_state(sid, True)
        started = time.monotonic()
        deadline = kw.get("_agentsfence_deadline")
        deadline = min(deadline, started + self.settings.compiler.timeout_seconds) if deadline is not None else started + self.settings.compiler.timeout_seconds
        arguments = (sid, task_id, user_message, queued, str(kw.get("platform") or ""), deadline, revision, snapshot, turn, fresh)
        if not self._background_slots.acquire(blocking=False):
            self._finish_revision_failure(sid, revision, snapshot, "compiler capacity exhausted; permission updates are still running")
            self._finish_compilation(sid)
        else:
            context = contextvars.copy_context()
            worker = threading.Thread(target=lambda: context.run(self._compile_revision, *arguments),
                                      daemon=True, name="agentsfence-policy-update")
            try:
                worker.start()
            except BaseException:
                self._background_slots.release()
                self._finish_revision_failure(sid, revision, snapshot, "unable to start policy update")
                self._finish_compilation(sid)
                raise
        if self.settings.policy.inject_summary:
            note = "[AgentsFence] Permissions are being updated. Tool calls will wait for the current task policy."
            if conflict := conflict_notice(snapshot):
                note += " " + conflict + " Tell the user about this conflict before acting."
            if not initial:
                note += "\n" + model_context_note(previous)
            self._audit("policy_context_injected", session_id=sid, policy=snapshot,
                        details={"revision": revision, "pending": True})
            return {"context": note}
        return None

    def _finish_revision_failure(self, sid: str, revision: int, snapshot: TaskPolicy, error: str) -> None:
        failed = snapshot.model_copy(deep=True)
        failed.suspended_since = revision
        failed.compiler_status = "fallback"
        failed.compiler_error = public_compiler_error(error)
        if self.store.install_revision(sid, revision, failed, resolved=False) is not None:
            self._audit("policy_compiled" if failed.source == "fallback" else "policy_amended", session_id=sid, policy=failed,
                        details={"policy": _policy_summary_dict(failed), "interpretation": failed.interpretation,
                                 "fell_back": True, "error": failed.compiler_error, "attempts": 0})
            self._policy_context(failed, True, inject=False)

    def _compile_revision(self, sid: str, task_id: str, message: str, queued: list[str], platform: str, deadline: float,
                          revision: int, snapshot: TaskPolicy, turn: int, initial: bool) -> None:
        try:
            request = combined_instruction(queued) if len(queued) > 1 else message
            if len(queued) > 1 and len(request) > self.settings.compiler.max_request_chars:
                # Truncating would drop the newest instructions; keep the suspension instead.
                raise CompilerError(f"{len(queued)} unprocessed owner messages exceed the compiler input limit; "
                                    "start a new task to restore consequential permissions")
            ctx = CompileContext(session_id=sid, task_id=task_id or None, platform=platform,
                                 available_tools=self.catalogue_fn(), deadline=deadline)
            with self._compiler_lock:
                self._sync_route()
                compiler = self._get_compiler()
                evidence = self.evidence()
            result = compiler.compile(request, ctx) if initial else compiler.amend(snapshot, request, ctx)
            new = result.policy
            new.policy_id = snapshot.policy_id
            new.session_id = sid
            self._annotate_policy(new, message, turn, result.fell_back, result.error, previous=snapshot)
            installed = self.store.install_revision(sid, revision, new, resolved=not result.fell_back)
            if installed is None:
                self._audit("policy_revision_discarded", session_id=sid, task_id=task_id,
                            details={"revision": revision, "reason": "superseded, dropped, or expired"})
                return
            self._audit("policy_compiled" if initial else "policy_amended", session_id=sid, task_id=task_id, policy=new,
                        details={"policy": _policy_summary_dict(new), "interpretation": new.interpretation,
                                 "fell_back": result.fell_back, "error": new.compiler_error, "dropped": result.dropped,
                                 "attempts": result.attempts, "approval_required": result.approval_required,
                                 "provenance": _finished(evidence, new.compiler_model)})
            self._policy_context(new, result.fell_back, result.approval_required, inject=False)
        except Exception as exc:
            logger.exception("background policy update failed")
            self._finish_revision_failure(sid, revision, snapshot, str(exc))
        finally:
            self._background_slots.release()
            self._finish_compilation(sid)

    def _finish_compilation(self, sid: str) -> None:
        with self.store.locked():
            remaining = self._compiling.get(sid, 1) - 1
            if remaining:
                self._compiling[sid] = remaining
            else:
                self._compiling.pop(sid, None)
                self._record_compilation_state(sid, False)

    def _annotate_policy(self, policy: TaskPolicy, message: str, turn: int, fell_back: bool, error: str | None,
                         *, previous: TaskPolicy | None = None) -> None:
        # Model-backed denials have the same origin as deterministic denials.
        # Older persisted policies without provenance keep an unknown origin.
        policy.prohibition_origins = {ban: previous.prohibition_origins[ban] if previous and ban in previous.user_prohibitions else turn
                                      for ban in policy.user_prohibitions
                                      if not previous or ban not in previous.user_prohibitions or ban in previous.prohibition_origins}
        policy.last_user_turn = turn
        policy.instruction_conflicts = instruction_conflicts(message)
        policy.compiler_status = "fallback" if fell_back else "verified"
        policy.compiler_error = public_compiler_error(error) if fell_back else None

    def _sync_route(self) -> None:
        """Keep Hermes' compiler slot on the profile's default model (inherit mode) before a compile."""
        if not self.settings.compiler.hermes_task:
            return
        try:
            from .profiles import compiler_route, read_config, sync_compiler_route

            fresh = load_settings()
            fresh.compiler.hermes_task = self.settings.compiler.hermes_task
            if fresh.compiler != self.settings.compiler:
                self.settings.compiler = fresh.compiler
                self._compiler = None
            self.settings.evaluation.strict_yolo = fresh.evaluation.strict_yolo
            self.settings.audit = fresh.audit
            self.audit.settings = fresh.audit
            changed = sync_compiler_route(hermes_home(), self.settings)
            if changed:
                self._audit("compiler_route_synced", details=changed)
            if not compiler_route(read_config(hermes_home())).get("model"):
                raise ValueError("Set a profile default or a dedicated compiler with `agentsfence settings --model MODEL`.")
            if getattr(self, "_route_unavailable", False):
                self._compiler = None
            self._route_unavailable = False
        except Exception as exc:
            logger.warning("AgentsFence could not sync the compiler route", exc_info=True)
            reason = str(exc)
            self._route_unavailable = True

            class UnavailableRoute:
                name = "unavailable"

                def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
                    raise RuntimeError(f"compiler route unavailable: {reason}")

            # Compile the complete instruction through the usual fallback path,
            # retaining prohibitions and domain restrictions on initial and amended tasks.
            self._compiler = PolicyCompiler(self.settings, self.classifier, UnavailableRoute())

    def evidence(self) -> dict[str, Any]:
        """Provenance for compiler evidence: version, route and settings in effect right now."""
        from . import __version__

        try:
            from .diagnostics import evidence_digest
            from .profiles import AUX_TASK, read_config

            home = hermes_home()
            route = (read_config(home).get("auxiliary") or {}).get(AUX_TASK) or {}
            return {"agentsfence_version": __version__, "evidence_digest": evidence_digest(home, self.settings),
                    "route": {"provider": str(route.get("provider") or "auto"), "model": str(route.get("model") or "")},
                    "routing": routing_mode(self.settings), **compile_budget(self.settings), "started": time.monotonic()}
        except Exception:
            return {"agentsfence_version": __version__, "evidence_digest": None, "started": time.monotonic()}

    def _policy_context(self, policy: TaskPolicy, fell_back: bool, approval_required: list[str] | None = None, *, inject: bool = True) -> dict[str, str] | None:
        if fell_back:
            notice = "AgentsFence FALLBACK: " + (policy.compiler_error or "Policy compilation failed.")
            notice += " Read-only policy active." if policy.source == "fallback" else " Earlier consequential permissions are suspended until a successful update."
            print(notice, file=sys.stderr)
        if approval_required:
            print("AgentsFence could not confirm authority for " + "; ".join(approval_required)
                  + ". Approval is required before an ungranted action can proceed; explicit restrictions still apply.", file=sys.stderr)
        _broadcast_status({"session_id": policy.session_id, "state": "fallback" if fell_back else "active"})
        conflict = conflict_notice(policy)
        if conflict:
            print(conflict, file=sys.stderr)
            self._audit("instruction_conflict", session_id=policy.session_id, policy=policy,
                        details={"conflicts": policy.instruction_conflicts})
        if self.settings.policy.inject_summary and inject:
            self._audit("policy_context_injected", session_id=policy.session_id, policy=policy,
                        details={"revision": policy.revision, "fell_back": fell_back})
            note = model_context_note(policy)
            if fell_back:
                note += " Tell the user that AgentsFence policy compilation failed and explain the fallback shown above."
            if approval_required:
                note += (" Tell the user clearly that AgentsFence could not confirm authority for "
                         + "; ".join(approval_required)
                         + ". Ask for approval through the tool approval gate before an ungranted action. Explicit restrictions remain binding.")
            if conflict:
                # The user must learn why a requested action is blocked, not guess at a model refusal.
                note += (" Before acting, tell the user in one sentence that their message both forbids and asks for "
                         f"{plain_actions(policy.instruction_conflicts)}, that the prohibition applies, and that a new "
                         "message asking for exactly that action allows it.")
            return {"context": note}
        return None

    # ------------------------------------------------------------------
    # pre_tool_call
    # ------------------------------------------------------------------

    def on_pre_tool_call(self, **kw: Any) -> dict[str, str] | None:
        try:
            if self.host_safety_fn and (conflict := self.host_safety_fn()):
                self._audit("decision", session_id=kw.get("session_id"), tool=kw.get("tool_name"),
                            tool_call_id=kw.get("tool_call_id"), arguments=kw.get("args"),
                            decision=Decision(decision=Verdict.BLOCK, reason=conflict, rule_id="extension-conflict"))
                return {"action": "block", "message": conflict}
            return self._pre_tool_call(**kw)
        except Exception as exc:
            logger.exception("pre_tool_call failed; blocking")
            self._audit("error", session_id=kw.get("session_id"), tool=kw.get("tool_name"), decision="BLOCK", details={"hook": "pre_tool_call", "error": str(exc)})
            return {"action": "block", "message": "AgentsFence BLOCKED this action: internal error while checking authorization (fail-closed)."}

    def check(self, tool_name: str, args: dict[str, Any] | None, *, session_id: str = "", task_id: str = "", tool_call_id: str = "", deadline: float | None = None) -> Decision:
        """Evaluate and record a tool call; returns the Decision (used by the hook and the demo)."""
        sid = session_id or (f"task:{task_id}" if task_id else "")
        call_id = tool_call_id or f"call-{uuid.uuid4().hex[:12]}"
        yolo = self.yolo_fn()
        wait_started = time.monotonic()
        waited_for_revision = False
        deadline = deadline or _host_hook_deadline() or (time.monotonic() + self.settings.compiler.timeout_seconds)
        waited_identity: str | None = None
        while True:
            with self.store.locked():
                rec = self.store.get(session_id or None, task_id or None)
                if waited_identity is not None and (rec is None or rec.policy.policy_id != waited_identity):
                    d = Decision(decision=Verdict.BLOCK, reason="The task ended while permissions were being updated.", rule_id="policy-dropped")
                    self._audit("decision", session_id=session_id or None, task_id=task_id, tool=tool_name,
                                tool_call_id=call_id, decision=d, arguments=args)
                    return d
                if rec is not None and rec.policy.pending_revision is not None and time.monotonic() < deadline:
                    owner = rec.session_id
                    waited_identity = rec.policy.policy_id
                    waited_for_revision = True
                else:
                    rec = self.store.get(session_id or None, task_id or None)
                    root = self.store.resolve_session(sid)
                    if rec is None and (self._compiling.get(sid) or self._compiling.get(root or "")):
                        d = Decision(decision=Verdict.BLOCK, reason="Task policy compilation is still running. Wait for it to finish before retrying the task.", rule_id="policy-compiling")
                        self._audit("decision", session_id=session_id or None, task_id=task_id, tool=tool_name,
                                    tool_call_id=call_id, decision=d, arguments=args)
                        return d
                    if rec is None:
                        rec_or_decision = self._missing_policy(session_id, task_id, tool_name, args)
                        if isinstance(rec_or_decision, Decision):
                            return rec_or_decision
                        rec = rec_or_decision
                    a = self.evaluator.assess(rec.policy, tool_name, args, rec.state, yolo=yolo)
                    d = a.decision
                    if (d.decision is Verdict.ASK_USER
                            and (rec.policy.source == "fallback" or rec.policy.suspended_since is not None
                                 or rec.policy.pending_revision is not None or self.settings.evaluation.strict_yolo)
                            and self.approval_auto_fn(self._rule_key(rec.policy, tool_name, d))):
                        a = self.evaluator.block_auto_approved(rec.policy, a)
                        d = a.decision
                    if d.decision is Verdict.ALLOW:
                        self.store.reserve(
                            rec,
                            call_id,
                            Reservation(
                                tool=tool_name,
                                capability=a.profile.capability,
                                risk=a.profile.risk,
                                constraint_keys=a.constraint_keys,
                                counted_targets=a.counted_targets,
                                grant_id=d.grant_id,
                                outbound=a.profile.risk in _OUTBOUND,
                            ),
                        )
                    elif d.decision is Verdict.ASK_USER:
                        # Counters are reserved while the user decides, so parallel calls
                        # can't race past a budget; released again on denial.
                        self.store.reserve_pending(
                            rec,
                            PendingApproval(
                                tool_call_id=call_id,
                                rule_key=self._rule_key(rec.policy, tool_name, d),
                                tool=tool_name,
                                capability=a.profile.capability,
                                risk=a.profile.risk,
                                constraint=d.proposed_grant or _empty_constraint(),
                                constraint_keys=a.constraint_keys,
                                counted_targets=a.counted_targets,
                                fingerprint=a.fingerprint,
                                action=a.action,
                                rule_id=d.rule_id,
                            ),
                        )
                    break
            outcome = self.store.wait_revision(owner, waited_identity, deadline)
            if outcome in {"dropped", "expired"}:
                d = Decision(decision=Verdict.BLOCK, reason="The task authorization ended while permissions were being updated.", rule_id=f"policy-{outcome}")
                self._audit("decision", session_id=session_id or None, task_id=task_id, tool=tool_name,
                            tool_call_id=call_id, decision=d, arguments=args)
                return d
        self._audit(
            "decision",
            session_id=session_id or (rec.session_id if sid else None),
            task_id=task_id,
            policy=rec.policy,
            tool=tool_name,
            tool_call_id=call_id,
            decision=d,
            arguments=args,
            details={"waited_for_revision": waited_for_revision,
                     "policy_wait_seconds": round(time.monotonic() - wait_started, 4) if waited_for_revision else 0},
        )
        return d

    def _pre_tool_call(self, **kw: Any) -> dict[str, str] | None:
        tool_name = str(kw.get("tool_name") or "")
        args = kw.get("args") if isinstance(kw.get("args"), dict) else {}
        session_id = str(kw.get("session_id") or "")
        task_id = str(kw.get("task_id") or "")
        tool_call_id = str(kw.get("tool_call_id") or "")
        d = self.check(tool_name, args, session_id=session_id, task_id=task_id, tool_call_id=tool_call_id)
        rec = self.store.get(session_id or None, task_id or None)
        if d.decision is Verdict.ALLOW:
            return None
        if d.decision is Verdict.BLOCK:
            return {"action": "block", "message": block_message(tool_name, d, rec.policy if rec else None)}
        rule_key = self._rule_key(rec.policy, tool_name, d) if rec else f"{RULE_PREFIX}unknown"
        return {"action": "approve", "message": approval_message(tool_name, d, rec.policy if rec else None), "rule_key": rule_key}

    def _missing_policy(self, session_id: str, task_id: str, tool_name: str, args: dict[str, Any] | None) -> PolicyRecord | Decision:
        mode = self.settings.evaluation.missing_policy
        if not session_id:
            # A call carrying only a task id we have never seen (nested dispatch from an
            # unknown context). Inventing a fresh policy here could drop a parent's bans.
            d = Decision(decision=Verdict.BLOCK, reason="This call belongs to no known task session.", rule_id="no-policy-for-task")
            self._audit("decision", task_id=task_id, tool=tool_name, decision=d, arguments=args)
            return d
        if mode == "block":
            d = Decision(decision=Verdict.BLOCK, reason="No task authorization exists for this session.", rule_id="no-policy")
            self._audit("decision", session_id=session_id, task_id=task_id, tool=tool_name, decision=d, arguments=args)
            return d
        policy = self.compiler.fallback(CompileContext(session_id=session_id, task_id=task_id or None))
        rec = self.store.put(session_id, policy, task_id=task_id or None)
        self._audit("policy_missing", session_id=session_id, task_id=task_id, policy=policy, details={"applied": "fallback_read_only"})
        return rec

    def rule_key_for(self, policy: TaskPolicy, tool_name: str, d: Decision) -> str:
        return self._rule_key(policy, tool_name, d)

    @staticmethod
    def _rule_key(policy: TaskPolicy, tool_name: str, d: Decision) -> str:
        material = "|".join([tool_name, d.capability or "", d.rule_id or "", d.fingerprint or ""])
        digest = hashlib.sha256(material.encode()).hexdigest()[:16]
        # Scoped to this task AND this exact action: an "[a]lways" answer in Hermes
        # can never blanket-approve other commands, recipients, tools, or tasks.
        return f"{RULE_PREFIX}{policy.policy_id}:{digest}"

    # ------------------------------------------------------------------
    # approvals & post-tool reconciliation
    # ------------------------------------------------------------------

    def on_post_approval_response(self, **kw: Any) -> None:
        try:
            pattern_key = str(kw.get("pattern_key") or "")
            if not pattern_key.startswith("plugin_rule:" + RULE_PREFIX):
                return
            rule_key = pattern_key[len("plugin_rule:") :]
            choice = str(kw.get("choice") or "")
            found = self.store.find_pending(tool_call_id=str(kw.get("tool_call_id") or "") or None, rule_key=rule_key)
            if found is None:
                self._audit("approval_orphan", details={"rule_key": rule_key, "choice": choice})
                return
            rec, pending = found
            if choice in _APPROVED_CHOICES:
                grant = self.store.grant_from_pending(rec, pending, choice)
                self._audit(
                    "approval_granted",
                    session_id=rec.session_id,
                    policy=rec.policy,
                    tool=pending.tool,
                    tool_call_id=pending.tool_call_id,
                    details={"choice": choice, "surface": kw.get("surface"), "grant": grant.model_dump(mode="json"),
                             "wait_seconds": _waited(pending)},
                )
            else:
                self.store.discard_pending(rec, pending.tool_call_id)
                self.store.release(rec, pending.tool_call_id)
                self._audit("approval_denied", session_id=rec.session_id, policy=rec.policy, tool=pending.tool,
                            tool_call_id=pending.tool_call_id, details={"choice": choice, "wait_seconds": _waited(pending)})
        except Exception:
            logger.exception("post_approval_response failed")

    def on_post_tool_call(self, **kw: Any) -> None:
        try:
            session_id = str(kw.get("session_id") or "")
            task_id = str(kw.get("task_id") or "")
            call_id = str(kw.get("tool_call_id") or "")
            if not call_id:
                return
            rec = self.store.get(session_id or None, task_id or None)
            if rec is None:
                return
            status = str(kw.get("status") or "")
            pending = rec.pending.get(call_id)
            if status == "blocked":
                if pending is not None:
                    self.store.discard_pending(rec, call_id)
                    self._audit("approval_denied", session_id=rec.session_id, policy=rec.policy, tool=pending.tool,
                                tool_call_id=call_id, details={"via": "post_tool_call", "wait_seconds": _waited(pending)})
                if self.store.release(rec, call_id):
                    self._audit("reservation_released", session_id=rec.session_id, tool=str(kw.get("tool_name") or ""), tool_call_id=call_id)
                return
            if pending is not None:
                # Approved by the host gate without an approval event: the CLI prompt
                # path, --yolo, a session/permanent allowlist hit, or cron approve mode.
                # Recorded as a single use of this exact action.
                grant = self.store.grant_from_pending(rec, pending, "host-auto")
                self._audit(
                    "approval_granted",
                    session_id=rec.session_id,
                    policy=rec.policy,
                    tool=pending.tool,
                    tool_call_id=call_id,
                    details={"choice": "host-auto", "note": "approved via Hermes gate (CLI prompt, yolo, allowlist or cron); choice not reported to plugins",
                             "grant": grant.model_dump(mode="json"), "wait_seconds": _waited(pending)},
                )
            self.store.settle(rec, call_id)
        except Exception:
            logger.exception("post_tool_call failed")

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def on_subagent_start(self, **kw: Any) -> None:
        try:
            child = str(kw.get("child_session_id") or "")
            parent = str(kw.get("parent_session_id") or "")
            if child and parent:
                self.store.link_child(child, parent)
                self._audit("subagent_bound", session_id=parent, details={"child_session_id": child, "role": kw.get("child_role")})
        except Exception:
            logger.exception("subagent_start failed")

    def on_session_reset(self, **kw: Any) -> None:
        sid = str(kw.get("session_id") or "")
        if sid:
            self.store.drop(sid)
            self._audit("policy_dropped", session_id=sid, details={"reason": "session_reset"})

    def on_session_finalize(self, **kw: Any) -> None:
        sid = str(kw.get("session_id") or "")
        reason = str(kw.get("reason") or "")
        if not sid or self.store.is_linked_child(sid):
            return
        if reason == "shutdown":
            # Hermes exited; the session can be resumed with --resume/--continue.
            # Keep the record (it still expires with the policy TTL) so a resumed
            # session keeps its restrictions instead of recompiling from scratch.
            return
        self.store.drop(sid)
        self._audit("policy_dropped", session_id=sid, details={"reason": reason or "session_boundary"})

    # ------------------------------------------------------------------
    # /fence slash command
    # ------------------------------------------------------------------

    def slash_command(self, raw_args: str = "") -> str:
        if self.gateway_fn():
            # One gateway process serves many chats and the command handler is not
            # told which one is asking: never show policies or audit rows here.
            return "AgentsFence: /fence is available in the Hermes CLI only (it could reveal other chats' tasks here)."
        arg = (raw_args or "").strip().lower()
        if arg in ("", "show", "policy"):
            recs = [r for r in self.store._records.values() if not self.store.is_linked_child(r.session_id)]
            if not recs:
                return "AgentsFence: no active task policy in this process."
            return "\n\n".join(f"[{r.session_id}]\n{describe_policy(r.policy)}" for r in recs[-3:])
        if arg.startswith("audit"):
            rows = self.audit.tail(10)
            return "\n".join(
                f"{r.get('timestamp', '')[:19]} {r.get('event')} {r.get('tool', '')} {r.get('decision', '')} {r.get('rule_id', '')}".rstrip()
                for r in rows
            ) or "AgentsFence: audit log is empty."
        return "Usage: /fence [show|audit]"

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _audit(
        self,
        event: str,
        *,
        session_id: Any = None,
        task_id: Any = None,
        policy: TaskPolicy | None = None,
        tool: Any = None,
        tool_call_id: Any = None,
        decision: Decision | str | None = None,
        arguments: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        try:
            original_session = str(session_id) if session_id else None
            session_id = self.store.resolve_session(original_session)
            if original_session and session_id != original_session:
                details = {**(details or {}), "source_session_id": original_session}
            d = decision if isinstance(decision, Decision) else None
            test_run = os.environ.get("AGENTSFENCE_TEST_RUN", "").strip()
            if test_run:  # a live `agentsfence test` turn: its rows are read back by the test
                details = {**(details or {}), "test_run": test_run[:64]}
            self.audit.record(
                AuditEvent(
                    event=event,
                    session_id=str(session_id) if session_id else None,
                    task_id=str(task_id) if task_id else None,
                    policy_id=policy.policy_id if policy else None,
                    tool=str(tool) if tool else None,
                    tool_call_id=str(tool_call_id) if tool_call_id else None,
                    capability=d.capability if d else None,
                    risk=d.risk.value if d and d.risk else None,
                    arguments=self.audit.redact_args(arguments) if arguments is not None else None,
                    decision=d.decision.value if d else (decision if isinstance(decision, str) else None),
                    reason=d.reason if d else None,
                    rule_id=d.rule_id if d else None,
                    details=details,
                )
            )
        except Exception:
            logger.exception("audit failed")


def _waited(pending: PendingApproval) -> float:
    """Seconds between asking and the answer (or the host's verdict) for an approval."""
    return round((utcnow() - pending.created_at).total_seconds(), 2)


def _finished(evidence: dict[str, Any], model: str | None) -> dict[str, Any]:
    """Provenance for an audit row: the operation's evidence plus its model and duration."""
    record = {k: v for k, v in evidence.items() if k != "started"}
    record.update(compiler_model=model, seconds=round(time.monotonic() - float(evidence.get("started") or time.monotonic()), 2))
    return record


def _broadcast_status(payload: dict[str, Any]) -> None:
    """Tell a connected Desktop about a status change, without ever waiting for it.

    Visibility is best effort. Hermes' event bridge can block (for example while it
    imports its gateway stack), and a hook that waits on it would leave the turn
    marked as compiling, so delivery runs on a daemon thread.
    """
    from .testkit import TEST_SESSION_PREFIX

    if str(payload.get("session_id") or "").startswith(TEST_SESSION_PREFIX):
        return  # a test session is not a chat

    def deliver() -> None:
        try:
            from hermes_cli.plugin_events import broadcast_plugin_event

            broadcast_plugin_event("agentsfence", "status.changed", payload)
        except Exception:
            pass

    with contextlib.suppress(Exception):
        threading.Thread(target=deliver, name="agentsfence-status-event", daemon=True).start()


def _empty_constraint() -> ToolConstraint:
    return ToolConstraint(allowed_recipients=[], allowed_domains=[], allowed_paths=[], max_calls=1)


def _policy_summary_dict(policy: TaskPolicy) -> dict[str, Any]:
    """Policy fields for the audit log. The free-text summary (model-written, may
    paraphrase the request) is replaced by its length and hash."""
    data = policy.model_dump(mode="json", exclude={"grants", "request_digest", "summary"}, exclude_none=True)
    if policy.summary:
        data["summary"] = {"redacted": True, "len": len(policy.summary), "sha256": hashlib.sha256(policy.summary.encode()).hexdigest()[:12]}
    return data


# ----------------------------------------------------------------------
# Hermes entry point
# ----------------------------------------------------------------------

_INSTANCES: dict[Path, AgentsFence] = {}
# How the last register() in this process ended: "enforcing" (normal hooks active)
# or "recovery_block" (a blocking fallback is active). register() can recover from a
# startup failure and return normally, so returning is never proof of enforcement.
REGISTRATION: dict[str, Any] = {"outcome": None, "error": None, "recovery_installed": False}


def registration_outcome() -> dict[str, Any]:
    return dict(REGISTRATION)


def mark_recovery(error: str) -> None:
    REGISTRATION.update(outcome="recovery_block", error=error)


def routing_mode(settings: Settings) -> str:
    """How compiles reach a model in this process: evidence from another mode isn't current.

    "task": Hermes routes AgentsFence's compiler slot; "host-model": the slot could not be
    registered, so Hermes' own model answers.
    """
    return "task" if settings.compiler.hermes_task else "host-model"


def host_status(_args: Any = None) -> dict[str, Any]:
    """This process's own AgentsFence state for `hermes agentsfence status` (never a profile-wide check)."""
    from . import __version__
    from .profiles import profile_name

    home = hermes_home()
    fence = get_instance()
    compatibility_error = None
    if fence and fence.host_safety_fn:
        try:
            compatibility_error = fence.host_safety_fn()
        except Exception:
            compatibility_error = "Unable to check Hermes' tool extension registry; tool calls fail closed."
    return {"schema": failsafe.STATUS_SCHEMA, "kind": "status", "outcome": REGISTRATION["outcome"] or "unknown",
            "error": REGISTRATION["error"], "agentsfence_version": __version__, "loader_version": failsafe.LOADER_VERSION,
            "python": sys.executable, "hermes_home": str(home), "profile": profile_name(home), "time": time.time(),
            "routing": routing_mode(fence.settings) if fence else None, "compatibility_error": compatibility_error}


def _host_probe(kind: str, scenarios: list[str] | None = None) -> dict[str, Any]:
    from .host_probe import probe_compiler

    if kind == "models":
        from .testkit.models import probe

        return probe()
    fence = get_instance()
    if fence is None:
        return {"ok": False, "error": "AgentsFence is not enforcing in this process."}
    if kind == "compiler-eval":
        from .host_probe import probe_compiler_eval

        return probe_compiler_eval(fence)
    if kind in ("test", "test-all"):
        from .testkit import harness
        from .testkit.scenarios import select

        try:
            chosen = select(scenarios or None, include_probes=kind == "test-all")
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        # Test-only process: explicitly register the isolated mock handlers.
        from tools.registry import registry

        from .testkit import mock_tools
        for name, schema, handler in mock_tools.TOOLS:
            registry.register(name=name, toolset=mock_tools.TOOLSET, schema=schema, handler=handler)
        return harness.run(fence, chosen, native=True)
    if kind == "jobs":
        from .testkit.jobs import dry_run_jobs

        return dry_run_jobs(fence, hermes_home())
    return probe_compiler(fence)


def _enter_recovery(ctx: Any, exc: BaseException) -> None:
    """Block every tool call after a startup failure; diagnostics are best-effort."""
    error = failsafe.describe(exc)
    failsafe.install_block(ctx, error)  # propagate if even this fails: the loader tries again
    REGISTRATION.update(outcome="recovery_block", error=error, recovery_installed=True)
    steps: list[Callable[[], object]] = [lambda: failsafe.register_status_command(ctx, host_status, None),
                                         lambda: failsafe.write_load_status(host_status())]
    for step in steps:
        try:
            step()
        except Exception:
            logger.debug("AgentsFence recovery diagnostics unavailable", exc_info=True)


def register(ctx: Any) -> None:
    """Called by Hermes' plugin loader. Never leaves Hermes unguarded."""
    configure_logging()
    REGISTRATION.update(outcome=None, error=None, recovery_installed=False)
    try:
        fence = AgentsFence(
            plugin_llm_factory=lambda: ctx.llm,
            plugin_dir=Path(__file__).resolve().parent,
        )
        # Enforcement first: nothing optional may run before the veto is in place.
        ctx.register_hook("pre_tool_call", fence.on_pre_tool_call)
        from .compatibility import tool_hook_conflict
        fence.host_safety_fn = lambda: tool_hook_conflict(fence.on_pre_tool_call)
        for hook, callback in (("pre_llm_call", fence.on_pre_llm_call), ("post_tool_call", fence.on_post_tool_call),
                               ("post_approval_response", fence.on_post_approval_response),
                               ("subagent_start", fence.on_subagent_start), ("on_session_reset", fence.on_session_reset),
                               ("on_session_finalize", fence.on_session_finalize)):
            ctx.register_hook(hook, callback)
    except Exception as exc:
        logger.exception("AgentsFence failed to start; blocking all tool calls")
        _enter_recovery(ctx, exc)
        return
    _INSTANCES[hermes_home().resolve()] = fence
    _register_optional(ctx, fence)
    REGISTRATION.update(outcome="enforcing")
    logger.info("AgentsFence registered (compiler=%s, home=%s)", fence.settings.compiler.provider, fence.settings.home)
    diagnostics: list[tuple[str, Callable[[], object]]] = [
        ("status command", lambda: failsafe.register_status_command(ctx, host_status, _host_probe)),
        ("load status", lambda: failsafe.write_load_status(host_status(), fence.settings.home)),
        ("runtime status", lambda: register_runtime(fence.settings))]
    for name, step in diagnostics:
        try:  # diagnostics never remove or bypass enforcement
            step()
        except Exception:
            logger.warning("Unable to record AgentsFence %s", name, exc_info=True)


def _register_optional(ctx: Any, fence: AgentsFence) -> None:
    """Features that improve operation; a failure here never disables enforcement.

    Lifecycle upkeep (recovery, `hermes pm install`, protecting new profiles) never
    runs in a chat process: it would rebuild the environment the chat runs from.
    The CLI and the Desktop pane run it; compiles keep the route in sync.
    """
    try:
        from .profiles import AUX_TASK

        ctx.register_auxiliary_task(AUX_TASK, display_name="AgentsFence policy compiler",
                                    description="Turn your request into permissions. Choose a reliable model; faster models reduce startup delay.")
        fence.settings.compiler.hermes_task = AUX_TASK
    except Exception as exc:
        logger.warning("Auxiliary task registration failed: %s", type(exc).__name__)

        def unavailable_auxiliary() -> Any:
            raise RuntimeError("Hermes auxiliary task registration failed; restart the backend.")
        fence._plugin_llm_factory = unavailable_auxiliary
    if os.environ.get("AGENTSFENCE_TEST_TOOLS", "").strip().lower() in {"1", "true", "yes", "on"}:
        try:  # Mock Gmail/Drive tools for `agentsfence test`. Off by default.
            from .testkit.mock_tools import register_with

            register_with(ctx.register_tool)
            logger.warning("AgentsFence test tools registered (AGENTSFENCE_TEST_TOOLS=1)")
        except Exception:
            logger.warning("AgentsFence test tools unavailable", exc_info=True)
    try:
        ctx.register_command("fence", fence.slash_command, description="Show the AgentsFence task policy / audit log", args_hint="[show|audit]")
    except Exception:
        logger.warning("AgentsFence could not register /fence", exc_info=True)


def get_instance() -> AgentsFence | None:
    return _INSTANCES.get(hermes_home().resolve())
