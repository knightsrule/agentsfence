"""Read-only deterministic compiler fixture; never shipped in the runtime package."""
from __future__ import annotations

import re
from typing import Any

from agentsfence.compiler import _NEG, URL_RE
from agentsfence.compiler.interpret import IntentDraft

_STOPWORDS = frozenset(
    {"the", "and", "for", "with", "this", "that", "from", "your", "my", "our", "please", "can", "you",
     "could", "would", "will", "into", "about", "then", "also", "just", "me", "it", "its"}
)


def rules_draft(instruction: str) -> IntentDraft:
    """Beta offline mode grants reads only; requests never mint write/send grants.

    It emits no grants and no prohibitions of its own: validation applies the
    deterministic prohibition floor and only-domain bounds from the instruction.
    """
    first_clause = re.split(rf"[.;!?\n]|\b{_NEG}\b", URL_RE.sub(" ", instruction).strip(), maxsplit=1, flags=re.IGNORECASE)[0]
    words = [w for w in re.findall(r"[a-z0-9]+", first_clause.lower()) if len(w) > 2 and w not in _STOPWORDS]
    purpose = "_".join(words[:4]) or "task"
    return IntentDraft(interpretation=[], grants=[],
                       summary=f"Read-only offline policy for task '{purpose}'; consequential actions need approval.")


class RulesClient:
    """Deterministic read-only compiler for tests and offline scenario runs; never a user setting.

    It grants READ only and keeps explicit prohibitions and only-domain bounds, like the
    read-only fallback. Production compiles always go through Hermes.
    """

    name = "rules"
    max_attempts = 1

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        instruction = user.split("<<<REQUEST>>>", 1)[-1].split("<<<END>>>", 1)[0]
        return rules_draft(instruction).model_dump_json()
