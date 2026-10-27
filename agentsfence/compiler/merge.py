"""Compiler merge stage."""

from __future__ import annotations

import re
from typing import Literal

from ..evaluator import entry_matches
from ..models import Grant, RiskClass, TaskPolicy, ToolConstraint, ToolProfile
from ..risk import RiskClassifier, domain_matches, normalize_path, normalize_recipient, path_within
from .floor import _explicit_target_constraints, _norm_ws, quote_in
from .interpret import _FLAG_FOR, Change, IntentDraft, IntentGrant, Target
from .validate import (
    _clean_domain,
    _literal_domain,
    _literal_path,
    _literal_recipient,
    _norm_allowed_path,
    clean_capability,
    validate_intents,
)


def _constraint_profile(key: str, classifier: RiskClassifier | None) -> ToolProfile | None:
    if classifier is None:
        return None
    if key.upper() in RiskClass.__members__:
        return ToolProfile(tool_name=key, capability=key, risk=RiskClass(key.upper()))
    if key in classifier.tools or "." not in key:
        return classifier.classify(key, {})
    return ToolProfile(tool_name=key, capability=key, risk=classifier.capability_risk(key))

def _grant_within_policy(grant: Grant, policy: TaskPolicy) -> bool:
    """Keep approvals only while their exact targets remain inside the task."""
    profile = ToolProfile(tool_name=grant.tool, capability=grant.capability, risk=grant.risk or RiskClass.UNKNOWN)
    if any(entry_matches(e, profile) for e in [*policy.user_prohibitions, *policy.denied_tools]):
        return False
    c = grant.constraint
    if policy.restricted_external_domains is not None and any(
        not domain_matches(d, policy.restricted_external_domains) for d in (c.allowed_domains or [])):
        return False
    for key, bound in policy.explicit_tool_constraints.items():
        if not entry_matches(key, profile):
            continue
        for field in ("allowed_recipients", "allowed_domains", "allowed_paths"):
            allowed, actual = getattr(bound, field), getattr(c, field)
            if allowed is None:
                continue
            if not actual or (field == "allowed_paths" and any(not path_within(v, allowed) for v in actual)) or (
                field == "allowed_domains" and any(not domain_matches(v, allowed) for v in actual)) or (
                field == "allowed_recipients" and any(v not in allowed for v in actual)):
                return False
    return True

_DIMENSION: dict[Literal["recipient", "domain", "path"], str] = {
    "recipient": "allowed_recipients", "domain": "allowed_domains", "path": "allowed_paths"}

def _spans_overlap(left: str, right: str, instruction: str) -> bool:
    """Ambiguous or overlapping quotes cannot represent an independent grant."""
    text = _norm_ws(instruction)
    ranges = []
    for span in (left, right):
        quote = _norm_ws(span).strip(" .\"'")
        if len(quote) < 3:
            return True
        starts = [m.start() for m in re.finditer(f"(?={re.escape(quote)})", text)]
        if not starts:
            return True
        ranges.append([(start, start + len(quote)) for start in starts])
    return any(a < d and c < b for a, b in ranges[0] for c, d in ranges[1])

def _matches_subject(entry: str, change: Change, classifier: RiskClassifier) -> bool:
    profile = _constraint_profile(entry, classifier)
    return profile is not None and (profile.risk is change.risk_class if change.risk_class else
        (subject := clean_capability(change.capability or "", classifier, [])) is not None and entry_matches(subject[0], profile))

def _remove_authority(policy: TaskPolicy, change: Change, classifier: RiskClassifier) -> None:
    policy.allowed_tools = [e for e in policy.allowed_tools if not _matches_subject(e, change, classifier)]
    if change.risk_class is not None:
        policy.allowed_risk_classes = [r for r in policy.allowed_risk_classes if r is not change.risk_class]
    else:
        resolved = clean_capability(change.capability or "", classifier, [])
        if resolved is not None:
            policy.allowed_risk_classes = [r for r in policy.allowed_risk_classes if r is not resolved[1] or r is RiskClass.READ]
    policy.tool_constraints = {k: v for k, v in policy.tool_constraints.items() if not _matches_subject(k, change, classifier)}
    policy.intent_constraints = {k: v for k, v in policy.intent_constraints.items() if not _matches_subject(k, change, classifier)}
    policy.grants = [g for g in policy.grants if not _matches_subject(g.capability, change, classifier)]

def _intersect_targets(old: list[str] | None, stated: list[str], field: str) -> list[str]:
    if old is None:
        return stated
    matches = path_within if field == "allowed_paths" else domain_matches if field == "allowed_domains" else lambda v, targets: v in targets
    return list(dict.fromkeys([v for v in old if matches(v, stated)] + [v for v in stated if matches(v, old)]))

def _change_targets(change: Change) -> list[str]:
    literal = {"recipient": _literal_recipient, "domain": _literal_domain, "path": _literal_path}
    clean = {"recipient": normalize_recipient, "domain": _clean_domain, "path": _norm_allowed_path}
    values = [value for target in change.targets if target.kind == change.target_kind and literal[target.kind](target.value, change.span)
              if (value := clean[target.kind](target.value))]
    return list(dict.fromkeys(values))

def _floor_narrowings(old: TaskPolicy, draft: IntentDraft, instruction: str, classifier: RiskClassifier) -> list[Change]:
    """Recognized English only-target bounds restrict existing authority even if
    the model omits a change operation. They never introduce a capability.
    """
    changes = []
    entries = [*old.allowed_tools, *(r.value for r in old.allowed_risk_classes), *(g.capability for g in old.grants)]
    for span in re.split(r"[;!\n]|\.(?:\s|$)", instruction):
        if not re.search(r"\bonly\b", span, re.I) or re.search(r"\b(?:instead|rather than)\b", span, re.I):
            continue
        for subject, bound in _explicit_target_constraints(span).items():
            for kind, field in _DIMENSION.items():
                values = getattr(bound, field)
                if values is None:
                    continue
                # Bounds contain canonical paths; a change still needs the
                # literal owner spelling (e.g. /tmp rather than /private/tmp).
                raw_paths = re.findall(r"(?:\b(?:to|into|at|under)\s+)((?:~/|/)[\w./-]+)", span, re.I)
                literals = [next((p for p in raw_paths if normalize_path(p) == v), v) if kind == "path" else v for v in values]
                change = Change(op="narrow", span=span, target_kind=kind,
                    risk_class=RiskClass(subject) if subject in RiskClass.__members__ else None,
                    capability=None if subject in RiskClass.__members__ else subject,
                    targets=[Target(value=v, kind=kind, role="recipient" if kind == "recipient" else "destination") for v in literals])
                affected = [e for e in entries if _matches_subject(e, change, classifier)]
                explicit = any(c.op in {"narrow", "replace"} and c.target_kind == kind and quote_in(c.span, instruction)
                    and _spans_overlap(c.span, span, instruction) and any(_matches_subject(e, c, classifier) for e in affected)
                    for c in draft.changes)
                if affected and not explicit:
                    changes.append(change)
    return changes

def merge_intents(old: TaskPolicy, new: TaskPolicy, draft: IntentDraft, instruction: str,
                  classifier: RiskClassifier, *, require_sensitive_approval: bool = True) -> TaskPolicy:
    """Apply verified owner changes, then union independently validated grant alternatives."""
    merged = old.model_copy(deep=True)
    additions = new.model_copy(deep=True)
    turn_bans = set(new.user_prohibitions)
    changes = [*draft.changes, *_floor_narrowings(old, draft, instruction, classifier)]
    narrowing = [c for c in changes if c.op == "narrow" and quote_in(c.span, instruction)]
    independent_grants = [g for g in draft.grants if not any(
        _matches_subject(g.capability, c, classifier) and _spans_overlap(g.span, c.span, instruction)
        for c in narrowing)]
    # Preserve an already authorized exact writer instead of adding every alias.
    exact_writers = [p for e in old.allowed_tools if (p := _constraint_profile(e, classifier)) is not None
                     and p.capability == "file.write" and e != "file.write" and not old.allowed_paths
                     and not any(entry_matches(k, p) and c.allowed_paths is not None for k, c in old.tool_constraints.items())]
    if exact_writers:
        additions.allowed_tools = [e for e in additions.allowed_tools if e != "file.write"]
        additions.intent_constraints.pop("file.write", None)
        additions.tool_constraints.pop("file.write", None)
    for change in changes:
        if not quote_in(change.span, instruction):
            continue
        affected = [e for e in merged.allowed_tools if _matches_subject(e, change, classifier)]
        subject = change.risk_class.value if change.risk_class else change.capability or ""
        if change.op == "revoke":
            _remove_authority(merged, change, classifier)
            turn_bans.add(subject)
            merged.user_prohibitions = sorted(set(merged.user_prohibitions) | {subject})
            continue
        field = _DIMENSION.get(change.target_kind) if change.target_kind else None
        stated = _change_targets(change) if field else []
        if change.op == "replace":
            prior = {e: merged.intent_constraints.get(e) or [merged.tool_constraints.get(e, ToolConstraint())] for e in affected}
            _remove_authority(merged, change, classifier)
            capabilities = affected or ([change.capability] if change.capability else [])
            for cap in capabilities:
                # Discard the duplicate grant; it cannot bypass the old budget.
                choices = additions.intent_constraints.get(cap or "", [])
                additions.intent_constraints[cap or ""] = [c for c in choices if field and getattr(c, field) and not set(getattr(c, field)).issubset(stated)]
                additions.tool_constraints.pop(cap or "", None)
            replacement = IntentDraft(interpretation=[], grants=[IntentGrant(
                id=f"replace-{i}", capability=cap or "", mode="request", span=change.span,
                targets=change.targets, max_calls=change.max_calls) for i, cap in enumerate(capabilities)])
            fragment, _ = validate_intents(replacement, instruction, classifier, previous=old,
                                          require_sensitive_approval=require_sensitive_approval)
            # Invalid replacement bindings never turn into unbounded grants.
            for cap, alternatives in fragment.intent_constraints.items():
                valid = [c for c in alternatives if field is None or bool(getattr(c, field))]
                if valid:
                    additions.allowed_tools.append(cap)
                    for c in valid:
                        for previous in prior.get(cap, [ToolConstraint()]):
                            bound = previous.model_copy(deep=True)
                            if field:
                                setattr(bound, field, getattr(c, field))
                            limits = [v for v in (previous.max_calls, c.max_calls) if v is not None]
                            bound.max_calls = min(limits) if limits else None
                            bound.constraint_id = previous.constraint_id or c.constraint_id
                            additions.intent_constraints.setdefault(cap, []).append(bound)
                    risk = classifier.capability_risk(cap)
                    if risk in _FLAG_FOR:
                        setattr(additions, _FLAG_FOR[risk], True)
            additions.requires_approval.extend(fragment.requires_approval)
            continue
        # Apply every narrowing span when filtering duplicates: a later change
        # must not resurrect a grant removed by an earlier one in this turn.
        fragment, _ = validate_intents(IntentDraft(interpretation=[], grants=independent_grants), instruction, classifier, previous=old,
                                      require_sensitive_approval=require_sensitive_approval)
        for cap in [e for e in additions.allowed_tools if _matches_subject(e, change, classifier)]:
            additions.allowed_tools.remove(cap)
            additions.intent_constraints.pop(cap, None)
            additions.tool_constraints.pop(cap, None)
            if cap in fragment.allowed_tools:
                additions.allowed_tools.append(cap)
                additions.intent_constraints[cap] = fragment.intent_constraints[cap]
        bound = merged.explicit_tool_constraints.get(subject, ToolConstraint()).model_copy(deep=True)
        if field:
            setattr(bound, field, _intersect_targets(getattr(bound, field), stated, field))
        if change.max_calls is not None:
            bound.max_calls = change.max_calls if bound.max_calls is None else min(bound.max_calls, change.max_calls)
        merged.explicit_tool_constraints[subject] = bound
        # Removing broad classes never manufactures concrete authority.
        resolved = clean_capability(change.capability or "", classifier, [])
        if change.risk_class is not None or resolved is not None:
            risk = change.risk_class or (resolved[1] if resolved else RiskClass.UNKNOWN)
            merged.allowed_risk_classes = [r for r in merged.allowed_risk_classes if r is not risk or r is RiskClass.READ]
        for entry in affected:
            alternatives = merged.intent_constraints.get(entry) or [merged.tool_constraints.get(entry, ToolConstraint(
                allowed_recipients=merged.allowed_recipients or None, allowed_domains=merged.allowed_external_domains or None,
                allowed_paths=merged.allowed_paths or None))]
            kept = []
            for constraint in alternatives:
                c = constraint.model_copy(deep=True)
                if field:
                    setattr(c, field, _intersect_targets(getattr(c, field), stated, field))
                    if not getattr(c, field):
                        continue
                if change.max_calls is not None:
                    c.max_calls = change.max_calls if c.max_calls is None else min(c.max_calls, change.max_calls)
                kept.append(c)
            if kept:
                merged.intent_constraints[entry] = kept
                merged.tool_constraints[entry] = kept[0].model_copy(deep=True)
            else:
                merged.allowed_tools = [e for e in merged.allowed_tools if e != entry]
                merged.intent_constraints.pop(entry, None)
                merged.tool_constraints.pop(entry, None)
                merged.grants = [g for g in merged.grants if not _matches_subject(g.capability, change, classifier)]
    lifted = {b for b in merged.user_prohibitions if b not in turn_bans and any(
        entry_matches(b, profile) for e in additions.allowed_tools
        if (profile := _constraint_profile(e, classifier)) is not None)}
    merged.user_prohibitions = sorted((set(merged.user_prohibitions) - lifted) | set(additions.user_prohibitions))
    merged.allowed_tools = list(dict.fromkeys(merged.allowed_tools + additions.allowed_tools))
    merged.denied_tools = sorted(set(merged.denied_tools) | set(additions.denied_tools))
    for flag in set(_FLAG_FOR.values()):
        setattr(merged, flag, getattr(merged, flag) or getattr(additions, flag))
    for cap, alternatives in additions.intent_constraints.items():
        existing_ids = {c.constraint_id for c in merged.intent_constraints.get(cap, [])}
        for c in alternatives:
            if c.constraint_id in existing_ids:
                c.constraint_id = f"intent:{cap}:{new.policy_id}:{len(merged.intent_constraints.get(cap, []))}"
            merged.intent_constraints.setdefault(cap, []).append(c.model_copy(deep=True))
        if alternatives:
            merged.tool_constraints.setdefault(cap, alternatives[0].model_copy(deep=True))
        profile = _constraint_profile(cap, classifier)
        for key, bound in merged.explicit_tool_constraints.items():
            if profile is None or not entry_matches(key, profile):
                continue
            for field in _DIMENSION.values():
                existing = getattr(bound, field)
                if existing is not None:
                    values = [v for c in alternatives for v in (getattr(c, field) or [])]
                    setattr(bound, field, list(dict.fromkeys(existing + values)))
    if additions.restricted_external_domains is not None:
        merged.restricted_external_domains = additions.restricted_external_domains
    merged.requires_approval = sorted(set(merged.requires_approval) | set(additions.requires_approval))
    merged.explicit_tool_constraints.update({k: c.model_copy(deep=True) for k, c in additions.explicit_tool_constraints.items()})
    merged.grants = [g for g in merged.grants if _grant_within_policy(g, merged)]
    merged.revision = old.revision + 1
    merged.summary = (old.summary + " | " + new.summary).strip(" |")[:600]
    merged.interpretation = [*old.interpretation, *new.interpretation]
    merged.instruction_conflicts = new.instruction_conflicts
    merged.suspended_since = None
    return merged

def merge_policies(old: TaskPolicy, new: TaskPolicy, classifier: RiskClassifier | None = None, *,
                   replace_targets: bool = False, narrow_targets: set[str] | None = None) -> TaskPolicy:
    """Merge policy fragments; owner target changes are represented by intent operations."""
    if classifier is None:
        from ..config import load_settings
        classifier = RiskClassifier(load_settings().risk_config)
    return merge_intents(old, new, IntentDraft(interpretation=[], grants=[]), "", classifier)
