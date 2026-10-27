"""Compiler validate stage."""

from __future__ import annotations

import fnmatch
import hashlib
import re
import unicodedata
import uuid
from pathlib import Path

from ..evaluator import entry_matches
from ..models import RiskClass, TaskPolicy, ToolConstraint, ToolProfile
from ..risk import RiskClassifier, domain_of, normalize_path, normalize_recipient
from .floor import (
    _EMAIL_RE,
    _HANDLE_RE,
    _explicit_target_constraints,
    explicit_domain_restriction,
    extract_prohibitions,
    instruction_conflicts,
    quote_in,
)
from .interpret import _FLAG_FOR, IntentDraft


def _literal_recipient(recipient: str, instruction: str) -> bool:
    """The exact address/handle appears as a whole token (not inside not-alice@…)."""
    recipient = unicodedata.normalize("NFKC", recipient).strip().lower()
    if not recipient or not (_EMAIL_RE.fullmatch(recipient) or _HANDLE_RE.fullmatch(recipient)):
        return False
    low = unicodedata.normalize("NFKC", instruction).lower()
    return re.search(r"(?<![a-z0-9.+'-])" + re.escape(recipient) + r"(?![a-z0-9@-]|\.[a-z0-9-])", low) is not None

def _literal_domain(domain: str, instruction: str) -> bool:
    """A host token cannot come only from an email address or longer hostname."""
    low = unicodedata.normalize("NFKC", instruction).lower()
    return re.search(r"(?:^|(?<=[\s/(\"'<,]))" + re.escape(domain) + r"(?=$|[\s/)\"'>,:;?!]|\.(?:\s|$))", low) is not None

def _literal_path(path: str, instruction: str) -> bool:
    p = unicodedata.normalize("NFKC", path).strip()
    if not p:
        return False
    return re.search(_path_pattern(p), unicodedata.normalize("NFKC", instruction)) is not None

def _norm_allowed_path(path: str) -> str | None:
    """Normalize an allowed path; refuse roots that would cover most of the disk."""
    np = normalize_path(path)
    home = normalize_path(str(Path.home()))
    too_broad = {"/", home, normalize_path(str(Path.home().parent)), "/Users", "/home", "/private", "/var", "/etc", "/usr", "/tmp", "/private/tmp", "/opt", "/Volumes"}
    if np in too_broad or len(Path(np).parts) < 3:
        return None
    return np

def _clean_domain(value: str) -> str:
    v = value.strip().lower()
    return (domain_of(v) or v).lstrip("*.") if v else ""

def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]

def clean_capability(entry: str, classifier: RiskClassifier, catalogue: list[str]) -> tuple[str, RiskClass] | None:
    """Resolve concrete, known effects without granting wildcard/multiplex authority."""
    value = entry.strip().lower()
    if not value or any(c in value for c in "*?[") or value.upper() in RiskClass.__members__:
        return None
    spec = classifier.tools.get(value)
    if spec is None and ("." not in value or value in catalogue):
        spec = next((p for p in classifier.patterns if fnmatch.fnmatchcase(value, str(p.get("match") or ""))), None)
    if spec is not None:
        variants = {str(spec.get("risk")), *(str(v) for m in (spec.get("arg_risk") or {}).values() for v in m.values()),
                    *(str(v) for v in (spec.get("arg_present_risk") or {}).values())}
        if len(variants) > 1:
            return None
        profile = classifier.classify(value, {})
        return None if profile.risk is RiskClass.UNKNOWN else (profile.capability, profile.risk)
    configured = [s for s in [*classifier.tools.values(), *classifier.patterns] if str(s.get("capability", "")).lower() == value]
    live = [classifier.classify(name, {}) for name in catalogue]
    candidates = [p for p in live if p.capability == value]
    if configured:
        risks = {str(s.get("risk")) for s in configured}
        if len(risks) != 1 and value != "shell.exec":
            return None
        risk = classifier.capability_risk(value)
    elif candidates:
        risks = {p.risk for p in candidates}
        if len(risks) != 1:
            return None
        risk = candidates[0].risk
    else:
        profile = classifier.infer(value.replace(".", "_"))
        if profile.risk is RiskClass.UNKNOWN or profile.capability.split(".")[0] in {"tool", "mcp"}:
            return None
        value, risk = profile.capability, profile.risk
    return None if risk is RiskClass.UNKNOWN else (value, risk)

_SOURCE_PREFIX = re.compile(r"(?:\b(?:from|of|by|about|regarding|using|with|read|open|load|scan|source|input|notes in|lire|leer|depuis|de|desde|dalla|von|aus)\s+|(?:来源|来自|入力|から)\s*)$", re.I)
_SOURCE_IN_PREFIX = re.compile(r"\b(?:read|open|load|scan|search|summari[sz]e|review|run|execute)\b[^;!?\n]*\bin\s*$", re.I)

_REFERENCE = re.compile(r"\b(?:same (?:person|recipient|file|path|domain|site)|that (?:person|file|path|domain|site)|them|there|previous|earlier)\b", re.I)

def _source_target(value: str, span: str) -> bool:
    """Recognized source markers only remove target authority."""
    normalized = unicodedata.normalize("NFKC", span).lower()
    target = unicodedata.normalize("NFKC", value).lower()
    matches = list(re.finditer(re.escape(target), normalized))
    # The first export/copy path before an explicit output is a source.
    def is_source(match: re.Match[str]) -> bool:
        prefix = normalized[:match.start()]
        clause = re.split(r"\b(?:and|then|but)\b|[;!?\n]|\.(?=\s|$)", prefix)[-1]
        return bool(_SOURCE_PREFIX.search(prefix) or _SOURCE_IN_PREFIX.search(clause) or (
            re.search(r"\b(?:export|copy|convert)\s*$", prefix) and
            re.match(r"\s+(?:as|to|into)\s+(?:~/|/)", normalized[match.end():])))
    return bool(matches) and all(is_source(m) for m in matches)


def authorized_targets(previous: TaskPolicy | None, capability: str, field: str, classifier: RiskClassifier) -> list[str]:
    if previous is None:
        return []
    profile = ToolProfile(tool_name=capability, capability=capability, risk=classifier.capability_risk(capability))
    if not _listed_for_intent(previous, profile):
        return []
    result = list(getattr(previous, field))
    bindings = previous.intent_constraints or {k: [v] for k, v in previous.tool_constraints.items()}
    for key, alternatives in bindings.items():
        if entry_matches(key, profile):
            result.extend(v for c in alternatives for v in (getattr(c, field) or []))
    return list(dict.fromkeys(result))

def _listed_for_intent(policy: TaskPolicy, profile: ToolProfile) -> bool:
    return (profile.risk not in _FLAG_FOR or getattr(policy, _FLAG_FOR[profile.risk])) and (profile.risk in policy.allowed_risk_classes or any(entry_matches(e, profile) for e in policy.allowed_tools)) and not any(
        entry_matches(e, profile) for e in [*policy.denied_tools, *policy.user_prohibitions])

def validate_intents(draft: IntentDraft, instruction: str, classifier: RiskClassifier, *,
                     session_id: str | None = None, task_id: str | None = None, catalogue: list[str] | None = None,
                     previous: TaskPolicy | None = None, require_sensitive_approval: bool = True,
                     user_request: str = "") -> tuple[TaskPolicy, list[str]]:
    """Validate the model's semantics against owner spans; every deterministic step restricts."""
    policy = TaskPolicy(policy_id=f"pol-{uuid.uuid4().hex[:12]}", session_id=session_id, task_id=task_id,
                        purpose="task", summary=draft.summary[:300], source="llm", request_digest=_digest(user_request or instruction))
    policy.user_prohibitions = extract_prohibitions(instruction)
    policy.restricted_external_domains = explicit_domain_restriction(instruction)
    dropped: list[str] = []
    for prohibition in draft.prohibitions:
        if quote_in(prohibition.span, instruction):
            entry = prohibition.risk_class.value if prohibition.risk_class else str(prohibition.capability).strip().lower()
            policy.user_prohibitions.append(entry)
        else:
            dropped.append("prohibition: span absent from owner instruction")
    policy.user_prohibitions = sorted(set(policy.user_prohibitions))
    policy.explicit_tool_constraints = _explicit_target_constraints(instruction)
    policy.instruction_conflicts = instruction_conflicts(instruction)
    policy.interpretation = [v.model_dump() for v in draft.interpretation]
    for grant in draft.grants:
        resolved = clean_capability(grant.capability, classifier, catalogue or [])
        if grant.mode in {"informational", "hypothetical"} or not quote_in(grant.span, instruction) or resolved is None:
            dropped.append(f"grant {grant.id}: mode, span or capability invalid")
            continue
        capability, risk = resolved
        profile = ToolProfile(tool_name=capability, capability=capability, risk=risk)
        span_bans = extract_prohibitions(grant.span)
        if any(entry_matches(e, profile) for e in [*policy.user_prohibitions, *span_bans]):
            dropped.append(f"grant {grant.id}: negated or prohibited")
            continue
        # A file save cannot authorize persistent state.
        file_output = bool(re.search(r"\b(?:save|export|copy|write)\b", grant.span, re.I) and re.search(r"(?:~/|/)[\w./-]+", grant.span))
        if capability == "agent.memory" and file_output:
            dropped.append(f"grant {grant.id}: no memory scope")
            continue
        if capability.split(".")[0] == "skill" and file_output:
            dropped.append(f"grant {grant.id}: no skill scope")
            continue
        bound: dict[str, list[str]] = {"allowed_recipients": [], "allowed_domains": [], "allowed_paths": []}
        for target in grant.targets:
            field = {"recipient": "allowed_recipients", "domain": "allowed_domains", "path": "allowed_paths"}[target.kind]
            role_ok = target.role == "recipient" if target.kind == "recipient" else target.role == "destination"
            if not role_ok or _source_target(target.value, grant.span):
                continue
            literal = {"recipient": _literal_recipient, "domain": _literal_domain, "path": _literal_path}[target.kind](target.value, grant.span)
            reference = bool(_REFERENCE.search(grant.span)) and target.value in authorized_targets(previous, capability, field, classifier)
            if not literal and not reference:
                continue
            if target.kind == "recipient":
                if risk not in {RiskClass.COMMUNICATION, RiskClass.PERMISSION_CHANGE, RiskClass.EXTERNAL_WRITE}:
                    continue
                value = normalize_recipient(target.value)
            elif target.kind == "path":
                if risk not in {RiskClass.LOCAL_WRITE, RiskClass.DELETE, RiskClass.EXECUTION, RiskClass.EXTERNAL_WRITE}:
                    continue
                value = _norm_allowed_path(target.value) or ""
            else:
                value = _clean_domain(target.value)
            if value:
                bound[field].append(value)
        constraint = ToolConstraint(allowed_recipients=list(dict.fromkeys(bound["allowed_recipients"])) or None,
            allowed_domains=list(dict.fromkeys(bound["allowed_domains"])) or None, allowed_paths=list(dict.fromkeys(bound["allowed_paths"])) or None,
            max_calls=grant.max_calls, constraint_id=capability if capability not in policy.intent_constraints else f"intent:{capability}:{_digest(grant.span + grant.id)}")
        policy.allowed_tools.append(capability)
        policy.intent_constraints.setdefault(capability, []).append(constraint)
        policy.tool_constraints.setdefault(capability, constraint.model_copy(deep=True))
        if risk in _FLAG_FOR:
            setattr(policy, _FLAG_FOR[risk], True)
        if grant.mode == "conditional" or (require_sensitive_approval and risk in {RiskClass.FINANCIAL, RiskClass.PERMISSION_CHANGE}):
            policy.requires_approval.append(capability)
    policy.allowed_tools = list(dict.fromkeys(policy.allowed_tools))
    policy.requires_approval = sorted(set(policy.requires_approval))
    return policy, dropped

def _path_pattern(path: str) -> str:
    return r"(?<![\w/:~])" + re.escape(path) + r"(?=$|[\s,;!?\"'<>)]|\.(?:\s|$))"
