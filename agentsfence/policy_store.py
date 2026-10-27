"""Task policy store.

Holds one :class:`PolicyRecord` per Hermes session: the compiled policy, the
execution counters, pending approvals and call reservations. Records are kept
in memory and mirrored to ``$AGENTSFENCE_HOME/policies/<session>.json`` (mode
0600) so a gateway restart does not silently drop authority *or* restrictions.

Subagent sessions are linked to their parent's record: they share the same
policy and the same counters, so delegation can never multiply a call budget.

All mutation happens under a single re-entrant lock. The pre-tool-call path
evaluates and reserves inside one critical section, so concurrent tool calls
cannot race past a ``max_calls`` limit.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from .models import NON_PATH_TARGET, ExecutionState, Grant, RiskClass, TaskPolicy, ToolConstraint, utcnow

logger = logging.getLogger("agentsfence.store")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class PendingApproval(BaseModel):
    tool_call_id: str
    rule_key: str
    tool: str
    capability: str
    risk: RiskClass
    constraint: ToolConstraint
    constraint_keys: list[str] = Field(default_factory=list)
    #: Distinct targets counted instead of a call (see ExecutionState.targets_by_key).
    counted_targets: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    action: str = ""
    rule_id: str | None = None
    choice: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Reservation(BaseModel):
    tool: str
    capability: str
    risk: RiskClass
    constraint_keys: list[str] = Field(default_factory=list)
    counted_targets: list[str] = Field(default_factory=list)
    grant_id: str | None = None
    outbound: bool = False


class UnresolvedTurn(BaseModel):
    """An owner instruction no successful compile has interpreted yet."""

    revision: int
    instruction: str


class PolicyRecord(BaseModel):
    session_id: str
    policy: TaskPolicy
    state: ExecutionState = Field(default_factory=ExecutionState)
    pending: dict[str, PendingApproval] = Field(default_factory=dict)
    reservations: dict[str, Reservation] = Field(default_factory=dict)
    task_ids: list[str] = Field(default_factory=list)
    turns_seen: int = 0
    #: Gateway sender who created the policy; only they can add authority later.
    owner_sender_id: str | None = None
    #: Owner instructions awaiting a successful compile, oldest first. A
    #: superseded or failed revision's message stays here, so the next compile
    #: still interprets it (a revocation can never be skipped).
    unresolved: list[UnresolvedTurn] = Field(default_factory=list)


class _Link(BaseModel):
    parent_session_id: str


class PolicyStore:
    def __init__(self, directory: Path | None, *, persist: bool = True):
        self.directory = directory
        self.persist = persist and directory is not None
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._revisions: dict[str, int] = {}
        self._records: dict[str, PolicyRecord] = {}
        self._links: dict[str, str] = {}
        self._task_alias: dict[str, str] = {}
        if self.persist and directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(OSError):
                os.chmod(directory, 0o700)
            self._prune_expired()

    # -- locking -----------------------------------------------------------

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self._lock:
            yield

    # -- lookup ------------------------------------------------------------

    def resolve_session(self, session_id: str | None) -> str | None:
        """Follow subagent links to the root session."""
        seen: set[str] = set()
        sid = session_id
        with self._lock:
            while sid and sid not in seen:
                seen.add(sid)
                parent = self._links.get(sid) or self._load_link(sid)
                if not parent:
                    return sid
                sid = parent
        return sid

    def get(self, session_id: str | None = None, task_id: str | None = None) -> PolicyRecord | None:
        with self._lock:
            sid = self.resolve_session(session_id) if session_id else None
            if sid:
                rec = self._records.get(sid) or self._load(sid)
                if rec is not None:
                    return rec
            if task_id:
                # Nested dispatch (e.g. execute_code) passes only a task id.
                owner = self._task_alias.get(task_id)
                if owner is None:
                    owner = self._find_task_on_disk(task_id)
                if owner is not None:
                    root = self.resolve_session(owner) or owner
                    return self._records.get(root) or self._load(root)
            return None

    def is_linked_child(self, session_id: str) -> bool:
        with self._lock:
            return bool(self._links.get(session_id) or self._load_link(session_id))

    # -- mutation ----------------------------------------------------------

    def put(self, session_id: str, policy: TaskPolicy, *, task_id: str | None = None, keep_state: bool = False) -> PolicyRecord:
        with self._lock:
            existing = self._records.get(session_id)
            rec = PolicyRecord(session_id=session_id, policy=policy)
            if existing is not None and keep_state:
                rec.state = existing.state
                rec.pending = existing.pending
                rec.reservations = existing.reservations
                rec.task_ids = existing.task_ids
                rec.turns_seen = existing.turns_seen
                rec.owner_sender_id = existing.owner_sender_id
                rec.unresolved = existing.unresolved
                # Amendments already preserve earlier grants. Their grant list is
                # authoritative: an explicit narrowing may have revoked a grant.
                # Readding the old list here would undo that user instruction.
            self._records[session_id] = rec
            if task_id:
                self.alias_task(session_id, task_id)
            self.save(rec)
            self._changed.notify_all()
            return rec

    def begin_revision(self, rec: PolicyRecord, instruction: str | None = None) -> int:
        """Suspend earlier authority before releasing the owner-turn lock.

        ``instruction`` (the owner's message after split_instruction) is queued
        until a compile that covers it succeeds.
        """
        with self._lock:
            revision = max(self._revisions.get(rec.session_id, 0), rec.policy.revision,
                           rec.policy.pending_revision or 0) + 1
            self._revisions[rec.session_id] = revision
            rec.policy.pending_revision = revision
            rec.policy.suspended_since = revision
            if instruction is not None:
                rec.unresolved.append(UnresolvedTurn(revision=revision, instruction=instruction))
            self.save(rec)
            self._changed.notify_all()
            return revision

    def install_revision(self, session_id: str, revision: int, policy: TaskPolicy, *, resolved: bool = True) -> PolicyRecord | None:
        """Install only the newest live revision, preserving execution state.

        ``resolved`` means the compile interpreted every queued instruction up to
        ``revision``; a failed compile leaves them queued for the next one.
        """
        with self._lock:
            rec = self._records.get(session_id)
            if rec is None or rec.policy.pending_revision != revision or rec.policy.is_expired():
                self._changed.notify_all()
                return None
            # A non-owner's prohibition can arrive while the owner revision is
            # compiling. Preserve those newer restrictions in its result.
            later_bans = {ban: origin for ban, origin in rec.policy.prohibition_origins.items()
                          if origin > policy.last_user_turn and ban in rec.policy.user_prohibitions}
            policy.user_prohibitions = sorted(set(policy.user_prohibitions) | set(later_bans))
            policy.prohibition_origins.update(later_bans)
            policy.last_user_turn = max(policy.last_user_turn, rec.policy.last_user_turn)
            policy.revision = revision
            policy.pending_revision = None
            installed = self.put(session_id, policy, keep_state=True)
            if resolved:
                installed.unresolved = [u for u in installed.unresolved if u.revision > revision]
                self.save(installed)
            return installed

    def wait_revision(self, session_id: str, policy_id: str, deadline: float) -> str:
        """Wait without holding the evaluation lock; expiry/drop cancel dispatch."""
        with self._changed:
            while True:
                rec = self._records.get(session_id)
                if rec is None or rec.policy.policy_id != policy_id:
                    return "dropped"
                if rec.policy.is_expired():
                    self._changed.notify_all()
                    return "expired"
                if rec.policy.pending_revision is None:
                    return "ready"
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timeout"
                if rec.policy.expires_at is not None:
                    remaining = min(remaining, max(0, (rec.policy.expires_at - utcnow()).total_seconds()))
                self._changed.wait(remaining)

    def alias_task(self, session_id: str, task_id: str) -> None:
        with self._lock:
            root = self.resolve_session(session_id) or session_id
            self._task_alias[task_id] = root
            rec = self._records.get(root) or self._load(root)
            if rec is not None and task_id not in rec.task_ids:
                rec.task_ids.append(task_id)
                self.save(rec)

    def link_child(self, child_session_id: str, parent_session_id: str) -> None:
        with self._lock:
            if child_session_id == parent_session_id:
                return
            self._links[child_session_id] = parent_session_id
            if self.persist:
                self._write(self._link_path(child_session_id), _Link(parent_session_id=parent_session_id).model_dump_json())

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._records.pop(session_id, None)
            self._changed.notify_all()
            self._links.pop(session_id, None)
            for tid in [t for t, s in self._task_alias.items() if s == session_id]:
                self._task_alias.pop(tid, None)
            if self.persist:
                for p in (self._path(session_id), self._link_path(session_id)):
                    with contextlib.suppress(FileNotFoundError):
                        p.unlink()

    # -- reservations & approvals -----------------------------------------

    def reserve(self, rec: PolicyRecord, tool_call_id: str, res: Reservation, *, count_grant: bool = True) -> None:
        """Count a call as executed *before* it runs (released if it is later blocked)."""
        with self._lock:
            s = rec.state
            prior_capability_calls = s.calls_by_capability.get(res.capability, 0)
            prior_risk_calls = s.calls_by_risk.get(res.risk.value, 0)
            legacy_risk_calls = sum(s.calls_by_capability.values()) if not s.calls_by_risk else 0
            for scope, prior in ((f"capability:{res.capability}", prior_capability_calls),
                                 (f"risk:{res.risk.value}", max(prior_risk_calls, legacy_risk_calls))):
                if scope not in s.targets_by_scope:
                    s.targets_by_scope[scope] = {}
                    if prior:
                        s.untracked_path_calls_by_scope[scope] = prior
                for target in res.counted_targets or [NON_PATH_TARGET]:
                    tracked = s.targets_by_scope[scope]
                    tracked[target] = tracked.get(target, 0) + 1
            s.calls_by_tool[res.tool] = s.calls_by_tool.get(res.tool, 0) + 1
            s.calls_by_capability[res.capability] = s.calls_by_capability.get(res.capability, 0) + 1
            s.calls_by_risk[res.risk.value] = prior_risk_calls + 1
            for k in res.constraint_keys:
                if res.counted_targets:
                    targets = s.targets_by_key.setdefault(k, {})
                    for t in res.counted_targets:
                        targets[t] = targets.get(t, 0) + 1
                else:
                    s.calls_by_key[k] = s.calls_by_key.get(k, 0) + 1
            if res.grant_id and count_grant:
                s.grant_uses[res.grant_id] = s.grant_uses.get(res.grant_id, 0) + 1
            if res.outbound:
                s.external_writes += 1
            rec.reservations[tool_call_id or f"anon-{uuid.uuid4().hex}"] = res
            self.save(rec)

    def release(self, rec: PolicyRecord, tool_call_id: str) -> bool:
        with self._lock:
            res = rec.reservations.pop(tool_call_id, None)
            if res is None:
                return False
            s = rec.state
            s.calls_by_tool[res.tool] = max(0, s.calls_by_tool.get(res.tool, 0) - 1)
            s.calls_by_capability[res.capability] = max(0, s.calls_by_capability.get(res.capability, 0) - 1)
            s.calls_by_risk[res.risk.value] = max(0, s.calls_by_risk.get(res.risk.value, 0) - 1)
            for scope in (f"capability:{res.capability}", f"risk:{res.risk.value}"):
                tracked = s.targets_by_scope.get(scope, {})
                for target in res.counted_targets or [NON_PATH_TARGET]:
                    if tracked.get(target, 0) > 1:
                        tracked[target] -= 1
                    else:
                        tracked.pop(target, None)
            for k in res.constraint_keys:
                if res.counted_targets:
                    targets = s.targets_by_key.get(k, {})
                    for t in res.counted_targets:
                        if targets.get(t, 0) > 1:
                            targets[t] -= 1
                        else:
                            targets.pop(t, None)
                else:
                    s.calls_by_key[k] = max(0, s.calls_by_key.get(k, 0) - 1)
            if res.grant_id:
                s.grant_uses[res.grant_id] = max(0, s.grant_uses.get(res.grant_id, 0) - 1)
            if res.outbound:
                s.external_writes = max(0, s.external_writes - 1)
            self.save(rec)
            return True

    def settle(self, rec: PolicyRecord, tool_call_id: str) -> None:
        """The call ran: keep its counts, forget the reservation handle."""
        with self._lock:
            if rec.reservations.pop(tool_call_id, None) is not None:
                self.save(rec)

    def add_pending(self, rec: PolicyRecord, pending: PendingApproval) -> None:
        with self._lock:
            rec.pending[pending.tool_call_id] = pending
            self.save(rec)

    def find_pending(self, *, tool_call_id: str | None = None, rule_key: str | None = None) -> tuple[PolicyRecord, PendingApproval] | None:
        with self._lock:
            for rec in self._records.values():
                if tool_call_id and tool_call_id in rec.pending:
                    return rec, rec.pending[tool_call_id]
            if rule_key:
                for rec in self._records.values():
                    matches = [p for p in rec.pending.values() if p.rule_key == rule_key and p.choice is None]
                    if matches:
                        return rec, min(matches, key=lambda p: p.created_at)
            return None

    def grant_from_pending(self, rec: PolicyRecord, pending: PendingApproval, approved_via: str) -> Grant:
        """Turn an approval into a grant for exactly the approved action.

        The call's counters were already reserved when the question was asked
        (see :meth:`reserve_pending`), so concurrent calls could not race past a
        budget while the user was deciding. Here the approved call consumes the
        grant's first use.
        """
        with self._lock:
            constraint = pending.constraint.model_copy()
            if approved_via in ("session", "always"):
                # Repeatable for the rest of this task — for this exact action only.
                constraint = constraint.model_copy(update={"max_calls": None})
            grant = Grant(
                grant_id=f"g-{uuid.uuid4().hex[:10]}",
                tool=pending.tool,
                capability=pending.capability,
                risk=pending.risk,
                fingerprint=pending.fingerprint or None,
                description=pending.action,
                constraint=constraint,
                approved_via=approved_via,
            )
            rec.policy.grants.append(grant)
            rec.pending.pop(pending.tool_call_id, None)
            rec.state.grant_uses[grant.grant_id] = rec.state.grant_uses.get(grant.grant_id, 0) + 1
            res = rec.reservations.get(pending.tool_call_id)
            if res is not None:
                res.grant_id = grant.grant_id
            else:  # no reservation (older record): count the call now
                self.reserve(rec, pending.tool_call_id, _reservation_for(pending, grant.grant_id), count_grant=False)
            self.save(rec)
            return grant

    def reserve_pending(self, rec: PolicyRecord, pending: PendingApproval) -> None:
        """Record a question and reserve its counters until the user answers."""
        with self._lock:
            rec.pending[pending.tool_call_id] = pending
            self.reserve(rec, pending.tool_call_id, _reservation_for(pending, None))

    def discard_pending(self, rec: PolicyRecord, tool_call_id: str) -> PendingApproval | None:
        with self._lock:
            p = rec.pending.pop(tool_call_id, None)
            if p is not None:
                self.save(rec)
            return p

    # -- persistence -------------------------------------------------------

    def _prune_expired(self) -> None:
        """Delete records whose policy expired (kept across shutdowns for --resume)."""
        if self.directory is None:
            return
        for path in self.directory.glob("*.json"):
            if path.name.endswith(".link.json"):
                continue
            try:
                rec = PolicyRecord.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue  # corrupt records are left for inspection; they never load as permissive
            if rec.policy.is_expired():
                with contextlib.suppress(OSError):
                    path.unlink()

    def _find_task_on_disk(self, task_id: str) -> str | None:
        if not self.persist or self.directory is None:
            return None
        for path in self.directory.glob("*.json"):
            if path.name.endswith(".link.json"):
                continue
            try:
                rec = PolicyRecord.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if task_id in rec.task_ids:
                self._records.setdefault(rec.session_id, rec)
                for tid in rec.task_ids:
                    self._task_alias[tid] = rec.session_id
                return rec.session_id
        return None

    def save(self, rec: PolicyRecord) -> None:
        if not self.persist:
            return
        try:
            self._write(self._path(rec.session_id), rec.model_dump_json(indent=2))
        except OSError as exc:  # persistence is best-effort; memory remains authoritative
            logger.warning("could not persist policy for %s: %s", rec.session_id, exc)

    def _load(self, session_id: str) -> PolicyRecord | None:
        if not self.persist:
            return None
        path = self._path(session_id)
        if not path.is_file():
            return None
        try:
            rec = PolicyRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            # A corrupt record must not silently become "no restrictions":
            # callers treat a missing record as missing policy (fallback / block).
            logger.error("corrupt policy record %s: %s", path, exc)
            return None
        self._records[session_id] = rec
        # A persisted pending revision has no live worker after restart. Keep
        # its consequential suspension, while reads regain the fallback path.
        if rec.policy.pending_revision is not None:
            rec.policy.suspended_since = rec.policy.pending_revision
            rec.policy.pending_revision = None
        for tid in rec.task_ids:
            self._task_alias[tid] = session_id
        return rec

    def _load_link(self, session_id: str) -> str | None:
        if not self.persist:
            return None
        path = self._link_path(session_id)
        if not path.is_file():
            return None
        try:
            parent = _Link.model_validate_json(path.read_text(encoding="utf-8")).parent_session_id
        except Exception:
            return None
        self._links[session_id] = parent
        return parent

    def _path(self, session_id: str) -> Path:
        assert self.directory is not None
        return self.directory / f"{_SAFE_NAME.sub('_', session_id)}.json"

    def _link_path(self, session_id: str) -> Path:
        assert self.directory is not None
        return self.directory / f"{_SAFE_NAME.sub('_', session_id)}.link.json"

    @staticmethod
    def _write(path: Path, content: str) -> None:
        tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)


def dump_policy(policy: TaskPolicy) -> dict[str, object]:
    data: dict[str, object] = json.loads(policy.model_dump_json(exclude_none=True))
    return data


def _reservation_for(pending: PendingApproval, grant_id: str | None) -> Reservation:
    return Reservation(
        tool=pending.tool,
        capability=pending.capability,
        risk=pending.risk,
        constraint_keys=pending.constraint_keys,
        counted_targets=pending.counted_targets,
        grant_id=grant_id,
        outbound=pending.risk in (RiskClass.EXTERNAL_WRITE, RiskClass.COMMUNICATION),
    )
