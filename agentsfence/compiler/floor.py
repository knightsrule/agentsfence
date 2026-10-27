"""Compiler floor stage."""

from __future__ import annotations

import re
import unicodedata

from ..models import CONSEQUENTIAL, RiskClass, ToolConstraint
from ..risk import URL_RE, domain_matches, domain_of, normalize_recipient
from .split import split_instruction

_ALL_CONSEQUENTIAL = [r.value for r in sorted(CONSEQUENTIAL - {RiskClass.UNKNOWN}, key=lambda r: r.value)] + [RiskClass.LOCAL_WRITE.value, "shell.network_write"]



_NEG = r"(?:do\s+not|don'?t|dont|never|no|without|must\s+not|mustn'?t|should\s*n'?o?t|shouldn'?t|avoid|not\s+allowed\s+to|stop)"

_NEG_EXCEPTIONS = re.compile(r"^\s*(forget|hesitate|miss|fail|worry|wait|need\s+to\s+ask)", re.IGNORECASE)

_EXCEPT = re.compile(r"\b(except|other\s+than|besides|but\s+(?:to|for)|unless|apart\s+from|only\s+to)\b", re.IGNORECASE)

_PROHIBIT_VERBS: dict[str, list[str]] = {
    # "Don't send" also covers pushing data out through the shell (curl -d, scp, git push).
    r"send|e-?mail|mail|message|text|reply|respond|forward|contact|notify|dm": [RiskClass.COMMUNICATION.value, "shell.network_write"],
    r"post|publish|upload|tweet": [RiskClass.COMMUNICATION.value, RiskClass.EXTERNAL_WRITE.value, "shell.network_write"],
    r"share": [RiskClass.PERMISSION_CHANGE.value, RiskClass.COMMUNICATION.value],
    r"delete|remove|trash|erase|wipe|purge|destroy": [RiskClass.DELETE.value],
    r"buy|purchase|pay|order|spend|transfer|checkout|subscribe": [RiskClass.FINANCIAL.value],
    r"modify|change|edit|write|save|create|update|alter|touch": [RiskClass.LOCAL_WRITE.value, RiskClass.EXTERNAL_WRITE.value],
    r"run|execute|install": [RiskClass.EXECUTION.value],
}

_PROHIBIT_RE = [
    (re.compile(rf"\b(?P<neg>{_NEG})\b(?P<gap>[^.;!?\n]{{0,40}}?)\b(?:{verbs})\w*\b(?P<tail>[^.;!?\n]{{0,60}})", re.IGNORECASE), classes)
    for verbs, classes in _PROHIBIT_VERBS.items()
]

_READ_ONLY_RE = re.compile(
    r"\b(read[\s-]?only|only\s+read|just\s+read|only\s+look|just\s+look|look\s+but\s+don'?t\s+touch|don'?t\s+(change|touch)\s+anything|"
    r"without\s+(making\s+)?(any\s+)?changes|no\s+changes|leave\s+everything\s+untouched|only\s+summari[sz]e|just\s+summari[sz]e)\b",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")

_HANDLE_RE = re.compile(r"(?:[a-z]+:[#@+]?[\w:.-]+|[#@][\w.-]+|\+\d[\d\s-]{6,})", re.IGNORECASE)

def extract_prohibitions(instruction: str) -> list[str]:
    """Risk classes the user explicitly forbade. Deterministic; overrides the LLM."""
    found: set[str] = set()
    if _READ_ONLY_RE.search(instruction):
        found.update(_ALL_CONSEQUENTIAL)
    for rx, classes in _PROHIBIT_RE:
        for m in rx.finditer(instruction):
            gap = m.group("gap") or ""
            if _NEG_EXCEPTIONS.match(gap):
                continue
            # Bare "no"/"without" only negates an adjacent verb ("no sending"), not
            # "no problem, send it".
            if m.group("neg").lower() in ("no", "without") and gap.strip():
                continue
            # "don't send it to anyone except John" is a restriction, not a ban.
            if _EXCEPT.search(m.group(0)):
                continue
            found.update(classes)
    return sorted(found)

def _norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", s)).strip().lower()

def quote_in(quote: str, instruction: str) -> bool:
    q = _norm_ws(quote).strip(" .\"'")
    return len(q) >= 3 and q in _norm_ws(instruction)

_DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.IGNORECASE)

_ONLY_DOMAINS = re.compile(
    r"\b(?:only\s+(?:use|visit|browse|read\s+from|search)|using\s+only|stick\s+to|limit\s+(?:yourself|it)\s+to)\s+((?:(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\s*(?:,|and|or)\s*)?)+)",
    re.IGNORECASE,
)

def explicit_domain_restriction(instruction: str) -> list[str] | None:
    """An explicit user domain bound, independent of compiler output."""
    groups = [[d.lower() for d in re.findall(_DOMAIN, m.group(1))] for m in _ONLY_DOMAINS.finditer(instruction)]
    if not groups:
        return None
    bound = groups[0]
    for group in groups[1:]:
        # Each "only" clause is a bound. Combining them cannot widen either one.
        bound = [d for d in dict.fromkeys([*bound, *group]) if domain_matches(d, bound) and domain_matches(d, group)]
    return list(dict.fromkeys(bound))

def instruction_conflicts(message: str) -> list[str]:
    """Display contradictions; this diagnostic never creates authority."""
    instruction, _ = split_instruction(message)
    bans = extract_prohibitions(instruction)
    clauses = re.split(r"[.;!?\n]|\b(?:and|then|but)\b", instruction, flags=re.I)
    found: list[str] = [risk for words, risks in _PROHIBIT_VERBS.items() for risk in risks if risk in bans and risk in RiskClass.__members__ and any(
        re.match(rf"^\s*(?:please\s+)?(?:{words})\w*\b", c, re.I) and not extract_prohibitions(c) for c in clauses)]
    bound = explicit_domain_restriction(instruction)
    if bound is not None:
        found.extend(f"site:{h}" for url in URL_RE.findall(instruction) if (h := domain_of(url)) and not domain_matches(h, bound))
    return sorted(set(found))

def _explicit_target_constraints(instruction: str) -> dict[str, ToolConstraint]:
    """Recognize only literal restrictions; this floor grants no capability."""
    from ..risk import normalize_path
    result: dict[str, ToolConstraint] = {}
    for clause in re.split(r"[;!\n]|\.(?:\s|$)", instruction):
        if not re.search(r"\b(?:only|instead|rather than)\b", clause, re.I):
            continue
        if re.search(r"\b(?:only|just)\s+(?:once|twice|\d+ times)\b", clause, re.I):
            continue
        recipients = [normalize_recipient(v) for v in _EMAIL_RE.findall(clause)]
        if re.search(r"\b(?:send|email|message|share|invite)\b", clause, re.I):
            for risk in (RiskClass.COMMUNICATION, RiskClass.PERMISSION_CHANGE):
                old = result.get(risk.value)
                values = recipients if old is None else [v for v in recipients if v in (old.allowed_recipients or [])]
                result[risk.value] = ToolConstraint(allowed_recipients=values)
        paths = re.findall(r"(?:\b(?:to|into|at|under)\s+)((?:~/|/)[\w./-]+)", clause, re.I)
        if re.search(r"\b(?:save|write|create|modify|edit)\b", clause, re.I):
            result["file.write"] = ToolConstraint(allowed_paths=[normalize_path(v) for v in paths])
    return result
