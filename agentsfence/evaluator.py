"""Deterministic runtime policy evaluation.

No LLM is consulted here. Given a compiled :class:`TaskPolicy`, a tool name and
its arguments, the evaluator returns ``ALLOW``, ``BLOCK`` or ``ASK_USER``.

Hard stops are evaluated together and the most restrictive result wins, so a
BLOCK can never be downgraded to a question by an earlier check:

 1. policy expired                                   → BLOCK
 2. guards: self-protection                          → BLOCK
 3. user prohibitions ("do not send anything")       → BLOCK
 4. policy deny list                                 → BLOCK
    explicit user domain/target boundaries            → BLOCK before grants
      (URLs in any call; every destination of the network programs a shell
      command runs, which must be verifiable: ssh-family, mail and git remotes,
      proxies and expansions are not)
    guards: secrets / Hermes home / cross-profile,
    patch text naming no parseable files             → ASK_USER (remembered; combined at the end)
 5. a runtime grant for this *exact* action          → ALLOW (also satisfies the ASKs above)
 6. per-tool argument constraints                    → BLOCK on violation
    (call limits count distinct paths for writes and deletes)
 7. risk-class ceiling + allow list                  → configured verdict if outside
 8. recipient binding (messages, shares, and
    external writes that name people)                → BLOCK / ASK_USER
 9. domain allow list                                → BLOCK / ASK_USER
10. exfiltration-shaped URLs                         → ASK_USER
11. path allow list for writes/deletes               → BLOCK
12. external-write budget                            → BLOCK
13. requires_approval                                → ASK_USER
14. otherwise                                        → ALLOW

The final verdict is the most restrictive of step 5–14's result and any
remembered ASK_USER. When Hermes would auto-approve (``--yolo``,
``approvals.mode: off``) an ASK_USER becomes BLOCK if ``strict_yolo`` is on, or
always when the policy is the read-only fallback.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .config import Settings
from .guards import GuardHit, Guards
from .models import (
    NON_PATH_TARGET,
    Decision,
    ExecutionState,
    Grant,
    RiskClass,
    TaskPolicy,
    ToolConstraint,
    ToolProfile,
    Verdict,
)
from .risk import (
    RiskClassifier,
    Targets,
    action_fingerprint,
    domain_matches,
    domain_of,
    normalize_recipient,
    path_within,
)

_OUTBOUND = (RiskClass.EXTERNAL_WRITE, RiskClass.COMMUNICATION)
_RECIPIENT_BOUND = (RiskClass.COMMUNICATION, RiskClass.PERMISSION_CHANGE)
_PATH_BOUND = (RiskClass.LOCAL_WRITE, RiskClass.DELETE)
_SEVERITY = {Verdict.ALLOW: 0, Verdict.ASK_USER: 1, Verdict.BLOCK: 2}
_SHELL_NETWORK = ("shell.network_read", "shell.network_write")


def _domain_bound(profile: ToolProfile) -> bool:
    """Does this tool address a web domain, so an explicit domain bound must verify it?

    Inferred tools carry every generic domain-argument hint, which says nothing about
    where a message or calendar write goes; only a mapping's own ``domain_args`` or a
    web/browser capability does.
    """
    declared = profile.source in ("mapped", "pattern") and bool(profile.domain_args)
    return declared or profile.capability.split(".", 1)[0] in ("web", "browser")


def entry_matches(entry: str, profile: ToolProfile) -> bool:
    """Does a policy entry (tool name, capability, glob, or risk class) cover this tool?"""
    e = (entry or "").strip()
    if not e:
        return False
    if e.upper() in RiskClass.__members__:
        return profile.risk.value == e.upper()
    el = e.lower()
    return fnmatch.fnmatchcase(profile.tool_name.lower(), el) or fnmatch.fnmatchcase(profile.capability.lower(), el)


@dataclass
class Assessment:
    decision: Decision
    profile: ToolProfile
    targets: Targets
    constraint_keys: list[str] = field(default_factory=list)
    fingerprint: str = ""
    action: str = ""
    #: Distinct targets this call counts against call limits instead of one call.
    counted_targets: list[str] = field(default_factory=list)


def counted_targets(profile: ToolProfile, targets: Targets) -> list[str]:
    """The paths a write or delete counts against a call limit instead of one call.

    Only for path-bound classes with fully verified paths: a patch whose files
    cannot all be read from its text still counts as a call.
    """
    if profile.risk not in _PATH_BOUND or not targets.paths or targets.unverified_paths:
        return []
    return sorted(set(targets.paths))


class Evaluator:
    def __init__(self, settings: Settings, classifier: RiskClassifier, guards: Guards):
        self.settings = settings
        self.classifier = classifier
        self.guards = guards

    # -- public -------------------------------------------------------------

    def evaluate(
        self,
        policy: TaskPolicy,
        tool_name: str,
        arguments: dict[str, object] | None,
        state: ExecutionState,
        *,
        yolo: bool = False,
        now: datetime | None = None,
    ) -> Decision:
        return self.assess(policy, tool_name, arguments, state, yolo=yolo, now=now).decision

    def assess(
        self,
        policy: TaskPolicy,
        tool_name: str,
        arguments: dict[str, object] | None,
        state: ExecutionState,
        *,
        yolo: bool = False,
        now: datetime | None = None,
    ) -> Assessment:
        args = dict(arguments or {})
        profile = self.classifier.classify(tool_name, args)
        targets = self.classifier.extract_targets(profile, args)
        fingerprint, action = action_fingerprint(profile, args, targets)
        result = self._assess(policy, profile, targets, state, now, fingerprint, action)
        result.counted_targets = counted_targets(profile, targets)
        return self.block_auto_approved(policy, result) if yolo else result

    def block_auto_approved(self, policy: TaskPolicy, result: Assessment) -> Assessment:
        """A question cannot guard an action the host will approve unaided."""
        d = result.decision
        if d.decision is Verdict.ASK_USER:
            if policy.source == "fallback" or policy.suspended_since is not None or policy.pending_revision is not None:
                result.decision = d.model_copy(
                    update={
                        "decision": Verdict.BLOCK,
                        "reason": d.reason + " (no task policy could be compiled, and Hermes would auto-approve)",
                        "rule_id": "fallback-no-human",
                    }
                )
            elif self.settings.evaluation.strict_yolo:
                result.decision = d.model_copy(
                    update={
                        "decision": Verdict.BLOCK,
                        "reason": d.reason + " (approval unavailable: Hermes is in an auto-approve mode and strict_yolo is on)",
                        "rule_id": "strict-yolo",
                    }
                )
        return result

    # -- internals ----------------------------------------------------------

    def _assess(
        self,
        policy: TaskPolicy,
        profile: ToolProfile,
        targets: Targets,
        state: ExecutionState,
        now: datetime | None,
        fingerprint: str,
        action: str,
    ) -> Assessment:
        risk = profile.risk
        cap = profile.capability

        def out(verdict: Verdict, rule_id: str, reason: str, *, keys: list[str] | None = None, grant: Grant | None = None) -> Assessment:
            proposed = self._proposed_grant(targets) if verdict is Verdict.ASK_USER else None
            return Assessment(
                Decision(
                    decision=verdict,
                    reason=reason,
                    rule_id=rule_id,
                    risk=risk,
                    capability=cap,
                    proposed_grant=proposed,
                    grant_id=grant.grant_id if grant else None,
                    fingerprint=fingerprint,
                    action=action,
                ),
                profile,
                targets,
                keys or [],
                fingerprint,
                action,
            )

        # 1. expiry
        if policy.is_expired(now):
            return out(Verdict.BLOCK, "policy-expired", "The task authorization has expired. Start a new task.")

        # 2–4. hard stops. All are checked; any BLOCK wins over any ASK.
        hit = self.guards.check(risk, targets)
        if hit is not None and hit.verdict is Verdict.BLOCK:
            return out(Verdict.BLOCK, hit.rule_id, hit.reason)
        for entry in policy.user_prohibitions:
            if entry_matches(entry, profile):
                origin = policy.prohibition_origins.get(entry)
                reason = f"You told the agent not to do this ({entry}); {cap} is blocked."
                if origin:
                    reason += f" This prohibition came from {'earlier ' if origin < policy.last_user_turn else ''}turn {origin}."
                if entry in policy.instruction_conflicts:
                    reason += " Your current message both forbids and requests this action. Restate the specific exception in a new message."
                return out(Verdict.BLOCK, "user-prohibition", reason)
        for entry in policy.denied_tools:
            if entry_matches(entry, profile):
                return out(Verdict.BLOCK, "policy-deny", f"{cap} is denied for this task ({entry}).")

        # Explicit target boundaries survive earlier approvals. A follow-up can
        # narrow the task after an action received a repeatable runtime grant.
        if policy.restricted_external_domains is not None:
            network = targets.network
            if (network is not None and not network.verified) or (network is None and cap in _SHELL_NETWORK):
                return out(Verdict.BLOCK, "domain-unverifiable",
                           "Cannot verify every destination of this shell command against your explicit domain restriction.")
            hosts = list(dict.fromkeys([*targets.domains, *(network.hosts if network else ())]))
            bad = [d for d in hosts if not domain_matches(d, policy.restricted_external_domains)]
            if bad:
                return out(Verdict.BLOCK, "domain-not-authorized",
                           f"Domain {', '.join(bad)} is outside the domains you explicitly permitted.")
            if not targets.domains and _domain_bound(profile):
                return out(Verdict.BLOCK, "domain-unverifiable",
                           f"Cannot verify the domain of this {cap} call against your explicit domain restriction.")
        constrained = self._constraint_checks(policy, profile, targets, state, risk, out,
                                              constraints=policy.explicit_tool_constraints)
        if constrained is not None:
            if constrained.decision.decision is Verdict.ASK_USER:
                # No approval can establish a target that an explicit user
                # boundary requires us to verify before dispatch.
                constrained.decision = constrained.decision.model_copy(update={"decision": Verdict.BLOCK})
            return constrained
        explicit_keys = [key for key in policy.explicit_tool_constraints if entry_matches(key, profile)]

        # Questions that stand regardless of policy (combined with the result below).
        soft: GuardHit | None = hit if hit is not None and hit.verdict is Verdict.ASK_USER else None
        if soft is None and targets.unverified_paths and risk is not RiskClass.READ:
            soft = GuardHit(Verdict.ASK_USER, "path-unverifiable", "The patch text names no files AgentsFence can verify; confirm the change.")

        # Unmapped tools whose name merely *sounds* read-only.
        if risk is RiskClass.READ and profile.source == "inferred" and not self.settings.evaluation.trust_inferred_reads:
            risk = RiskClass.UNKNOWN

        # The owner's latest instruction must be interpreted before any old
        # authority (including an exact-action approval) can be reused.
        if policy.pending_revision is not None:
            return out(Verdict.ASK_USER, "policy-compiling", "Task permissions are being updated. Confirm this action or wait for the policy update.", keys=explicit_keys)
        if policy.suspended_since is not None and risk is not RiskClass.READ:
            return out(Verdict.ASK_USER, "policy-suspended", "The latest permission update could not be compiled; earlier consequential authority is suspended. Confirm this action.", keys=explicit_keys)

        # 5. a grant the user approved for this exact action
        for grant in policy.grants:
            if self._grant_covers(grant, profile, fingerprint, state):
                return out(Verdict.ALLOW, "approved-grant", f"Covered by your earlier approval ({grant.approved_via}) of: {grant.description or action}.", grant=grant, keys=explicit_keys)

        result = self._policy_checks(policy, profile, targets, state, risk, out)
        result.constraint_keys = list(dict.fromkeys([*explicit_keys, *result.constraint_keys]))
        if soft is not None and _SEVERITY[result.decision.decision] < _SEVERITY[Verdict.ASK_USER]:
            return out(Verdict.ASK_USER, soft.rule_id, soft.reason, keys=result.constraint_keys)
        if soft is not None and result.decision.decision is Verdict.ASK_USER:
            # Both ask: the guard's reason is the more specific one.
            return out(Verdict.ASK_USER, soft.rule_id, soft.reason, keys=result.constraint_keys)
        return result

    def _constraint_checks(
        self,
        policy: TaskPolicy,
        profile: ToolProfile,
        targets: Targets,
        state: ExecutionState,
        risk: RiskClass,
        out: Callable[..., Assessment],
        *,
        constraints: dict[str, ToolConstraint] | None = None,
        match_keys: bool = True,
    ) -> Assessment | None:
        cap = profile.capability

        # 6. per-tool constraints
        explicit = constraints is policy.explicit_tool_constraints
        constraints = policy.tool_constraints if constraints is None else constraints
        keys = [k for k in constraints if entry_matches(k, profile)] if match_keys else list(constraints)
        question: Assessment | None = None
        for key in keys:
            c = constraints[key]
            if c.allowed_recipients is not None:
                allowed = {normalize_recipient(r) for r in c.allowed_recipients}
                bad = [r for r in targets.recipients if r not in allowed]
                if bad:
                    return out(Verdict.BLOCK, "recipient-not-authorized", f"Recipient {', '.join(bad)} is not one the user authorized for {key}.")
                if not targets.recipients and risk in _RECIPIENT_BOUND:
                    question = out(Verdict.ASK_USER, "recipient-unverifiable", f"Cannot determine the recipient of this {cap} call.")
            if c.allowed_domains is not None:
                bad = [d for d in targets.domains if not domain_matches(d, c.allowed_domains)]
                if bad:
                    return out(Verdict.BLOCK, "domain-not-authorized", f"Domain {', '.join(bad)} is outside what the user authorized for {key}.")
            if c.allowed_paths is not None:
                bad = [p for p in targets.paths if not path_within(p, c.allowed_paths)]
                if bad:
                    return out(Verdict.BLOCK, "path-not-authorized", f"Path {', '.join(bad)} is outside what the user authorized for {key}.")
                # Any consequential class the compiler can bind to paths (remote
                # writers and commands included) must name a verifiable path.
                if not targets.paths and risk is not RiskClass.READ:
                    question = out(Verdict.ASK_USER, "path-unverifiable", f"Cannot determine the destination of this {cap} call.")
            if c.max_calls is not None:
                per_target = counted_targets(profile, targets)
                used = state.uses(key)
                scope = f"risk:{risk.value}" if key.upper() in RiskClass.__members__ else f"capability:{cap}"
                legacy_risk_calls = max((n for k, n in state.untracked_path_calls_by_scope.items() if k.startswith("risk:")), default=0)
                if per_target:
                    # A write or delete limit bounds how many files the task touches:
                    # rewriting or patching one it already touched is not a new use.
                    fresh = state.new_targets(key, per_target)
                    if explicit:
                        history = state.targets_by_scope.get(scope, {})
                        prior = {p for p, n in history.items() if n > 0 and p != NON_PATH_TARGET}
                        unknown = legacy_risk_calls if scope.startswith("risk:") else state.untracked_path_calls_by_scope.get(scope, 0)
                        if scope not in state.targets_by_scope:
                            unknown = sum(state.calls_by_capability.values()) if scope.startswith("risk:") else state.calls_by_capability.get(cap, 0)
                        used = max(used, len(prior) + unknown + history.get(NON_PATH_TARGET, 0))
                        fresh = [p for p in fresh if p not in prior]
                    if fresh and used + len(fresh) > c.max_calls:
                        return out(Verdict.BLOCK, "call-limit-exceeded",
                                   f"{key} may touch at most {c.max_calls} file(s) in this task; {', '.join(fresh)} would exceed it.")
                else:
                    if explicit:
                        historical = (state.calls_by_risk.get(risk.value, 0) + legacy_risk_calls if scope.startswith("risk:")
                                      else state.calls_by_tool.get(profile.tool_name, 0) if key.lower() == profile.tool_name.lower()
                                      else state.calls_by_capability.get(cap, 0))
                        if scope.startswith("risk:") and not state.calls_by_risk and state.calls_by_capability:
                            historical = sum(state.calls_by_capability.values())
                        used = max(used, historical)
                    if used >= c.max_calls:
                        return out(Verdict.BLOCK, "call-limit-exceeded", f"{key} may be used at most {c.max_calls} time(s) in this task.")

        return question

    def _policy_checks(
        self,
        policy: TaskPolicy,
        profile: ToolProfile,
        targets: Targets,
        state: ExecutionState,
        risk: RiskClass,
        out: Callable[..., Assessment],
    ) -> Assessment:
        cap = profile.capability
        alternatives = {k: cs for k, cs in policy.intent_constraints.items() if entry_matches(k, profile)}
        ordinary = {k: c for k, c in policy.tool_constraints.items() if k not in alternatives}
        keys = [k for k in ordinary if entry_matches(k, profile)]
        constrained = self._constraint_checks(policy, profile, targets, state, risk, out, constraints=ordinary)
        if constrained is not None:
            return constrained
        bound_recipient = any(ordinary[k].allowed_recipients is not None for k in keys)
        bound_path = any(ordinary[k].allowed_paths is not None for k in keys)
        for capability, choices in alternatives.items():
            failure: Assessment | None = None
            selected: tuple[str, ToolConstraint] | None = None
            for index, constraint in enumerate(choices):
                key = constraint.constraint_id or (capability if len(choices) == 1 else f"intent:{capability}:{index}")
                assessed = self._constraint_checks(policy, profile, targets, state, risk, out,
                                                   constraints={key: constraint}, match_keys=False)
                if assessed is None:
                    selected = key, constraint
                    break
                if failure is None or _SEVERITY[assessed.decision.decision] < _SEVERITY[failure.decision.decision]:
                    failure = assessed
                    failure.constraint_keys = [key]
            if selected is None:
                return failure or out(Verdict.BLOCK, "intent-target-not-authorized", f"No complete grant authorizes the targets of {cap}.")
            key, constraint = selected
            keys.append(key)
            bound_recipient |= constraint.allowed_recipients is not None
            bound_path |= constraint.allowed_paths is not None

        # 7. ceiling + allow list
        if risk is RiskClass.UNKNOWN:
            # Unknown tools are allowed only by exact name, and only in a policy
            # the user wrote (source "manual") — never by a compiled policy.
            explicit = policy.source == "manual" and profile.tool_name in policy.allowed_tools
        else:
            explicit = any(entry_matches(e, profile) for e in policy.allowed_tools)
        if not (self._ceiling(policy, risk) and (explicit or risk in policy.allowed_risk_classes)):
            verdict = self.settings.evaluation.unauthorized.get(risk, Verdict.BLOCK)
            if risk is RiskClass.UNKNOWN:
                reason = f"{profile.tool_name} is not a recognized tool; its effects are unknown."
            else:
                reason = f"{cap} ({risk.value}) is outside this task's authority ({policy.purpose})."
            return out(verdict, f"unauthorized-{risk.value.lower()}", reason, keys=keys)

        # 8. recipient binding. External writes that carry people (calendar
        # attendees, share lists, CRM contacts) are bound like messages.
        binds = risk in _RECIPIENT_BOUND or (risk is RiskClass.EXTERNAL_WRITE and bool(targets.recipients))
        if binds and not bound_recipient:
            if policy.allowed_recipients or (policy.source == "manual" and policy.allowed_external_domains):
                bad = [r for r in targets.recipients if not self._recipient_bound(r, policy)]
                if bad:
                    return out(Verdict.BLOCK, "recipient-not-authorized", f"Recipient {', '.join(bad)} was not named by the user.", keys=keys)
                if not targets.recipients:
                    return out(Verdict.ASK_USER, "recipient-unverifiable", f"Cannot determine the recipient of this {cap} call.", keys=keys)
            elif policy.source != "manual" or self.settings.guards.require_bound_recipients:
                who = ", ".join(targets.recipients) or "an unspecified recipient"
                return out(Verdict.ASK_USER, "unbound-recipient", f"The user authorized {cap} but did not name recipients; confirm sending to {who}.", keys=keys)

        # 9. domain allow list
        if policy.allowed_external_domains and targets.domains:
            bad = [d for d in targets.domains if not domain_matches(d, policy.allowed_external_domains)]
            if bad:
                verdict = Verdict.ASK_USER if risk is RiskClass.READ else Verdict.BLOCK
                return out(verdict, "domain-not-authorized", f"Domain {', '.join(bad)} is outside the task's allowed domains.", keys=keys)

        # 10. exfiltration-shaped URLs
        for url in targets.urls:
            host = domain_of(url)
            if host and policy.allowed_external_domains and domain_matches(host, policy.allowed_external_domains):
                continue
            why = self.guards.suspicious_url(url)
            if why:
                return out(Verdict.ASK_USER, "exfil-url", f"URL to {host or url[:60]} looks like it may carry data out ({why}).", keys=keys)

        # 11. path allow list
        path_targeted = cap.startswith("file.") or bool(targets.paths) or (profile.source != "inferred" and bool(profile.path_args))
        if alternatives and risk in (*_PATH_BOUND, RiskClass.EXTERNAL_WRITE) and path_targeted and not bound_path and policy.source != "manual":
            return out(Verdict.ASK_USER, "unbound-path", f"The user authorized {cap} but no destination was bound; confirm this change.", keys=keys)
        if policy.allowed_paths and risk in _PATH_BOUND:
            if targets.unverified_paths and not targets.paths:
                return out(Verdict.ASK_USER, "path-unverifiable", "The patch text names no files AgentsFence can verify against the allowed paths.", keys=keys)
            bad = [p for p in targets.paths if not path_within(p, policy.allowed_paths)]
            if bad:
                return out(Verdict.BLOCK, "path-not-authorized", f"Path {', '.join(bad)} is outside the task's allowed paths.", keys=keys)

        # 12. external-write budget
        if risk in _OUTBOUND and policy.max_external_writes is not None and state.external_writes >= policy.max_external_writes:
            return out(Verdict.BLOCK, "external-write-budget", f"This task allows at most {policy.max_external_writes} outbound action(s).", keys=keys)

        # 13. explicit approval requirement
        for entry in policy.requires_approval:
            if entry_matches(entry, profile):
                return out(Verdict.ASK_USER, "requires-approval", f"The task policy requires confirmation for {cap}.", keys=keys)

        how = "explicitly allowed" if explicit else f"{risk.value} is within task scope"
        return out(Verdict.ALLOW, "policy-allow", f"{cap}: {how}.", keys=keys)

    @staticmethod
    def _ceiling(policy: TaskPolicy, risk: RiskClass) -> bool:
        return {
            RiskClass.READ: True,
            RiskClass.LOCAL_WRITE: policy.allow_local_writes,
            RiskClass.EXTERNAL_WRITE: policy.allow_external_writes,
            RiskClass.COMMUNICATION: policy.allow_external_writes,
            RiskClass.DELETE: policy.allow_destructive_actions,
            RiskClass.FINANCIAL: policy.allow_financial_actions,
            RiskClass.EXECUTION: policy.allow_execution,
            RiskClass.PERMISSION_CHANGE: policy.allow_permission_changes,
            RiskClass.UNKNOWN: True,  # gated by exact-name listing in a manual policy instead
        }[risk]

    @staticmethod
    def _recipient_bound(recipient: str, policy: TaskPolicy) -> bool:
        if policy.allowed_recipients:
            return recipient in {normalize_recipient(r) for r in policy.allowed_recipients}
        # A domain may stand in for a recipient only when the user explicitly
        # wrote the policy. Compiler-extracted browsing domains never widen a
        # send/share permission to every address at that domain.
        if policy.source == "manual" and "@" in recipient and policy.allowed_external_domains:
            return domain_matches(recipient.rsplit("@", 1)[1], policy.allowed_external_domains)
        return False

    @staticmethod
    def _grant_covers(grant: Grant, profile: ToolProfile, fingerprint: str, state: ExecutionState) -> bool:
        """A grant covers only the exact action the user approved."""
        if grant.fingerprint is None or grant.fingerprint != fingerprint:
            return False
        if grant.tool != profile.tool_name or grant.capability != profile.capability or grant.risk is not profile.risk:
            return False
        c = grant.constraint
        return not (c.max_calls is not None and state.grant_uses.get(grant.grant_id, 0) >= c.max_calls)

    @staticmethod
    def _proposed_grant(targets: Targets) -> ToolConstraint:
        # Empty lists mean "none": a grant never widens to targets the user did not see.
        return ToolConstraint(
            allowed_recipients=list(targets.recipients),
            allowed_domains=list(targets.domains),
            allowed_paths=list(targets.paths),
            max_calls=1,
        )
