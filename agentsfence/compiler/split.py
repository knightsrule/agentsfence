"""Compiler split stage."""

from __future__ import annotations

import re
import unicodedata

_HERMES_CONTEXT = re.compile(r"^--- (?:Attached Context|Context Warnings) ---[ \t]*$.*", re.MULTILINE | re.DOTALL)

_FENCE = re.compile(r"```.*?(```|\Z)|~~~.*?(~~~|\Z)", re.DOTALL)

_PASTED_TAG = re.compile(r"<(pasted[_-]?content|tool[_-]?output|document|email|attachment|quote|blockquote)[^>]*>.*?(</\1\s*>|\Z)", re.DOTALL | re.IGNORECASE)

_INLINE_CODE = re.compile(r"`[^`\n]+`")

_QUOTED = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”|‘[^’\n]*’|(?:(?<=^)|(?<=[\s(]))'[^'\n]+'(?=$|[\s.,;:!?)])")

_HEADER_BLOCK = re.compile(r"^(?:from|to|cc|bcc|subject|date|sent|reply-to):[^\n]*\n(?:[^\n]+\n?)*", re.IGNORECASE | re.MULTILINE)

_FORWARD_MARK = re.compile(
    r"^[ \t]*(-{2,}\s*(forwarded message|original message)\s*-{2,}|begin forwarded message:|on .{3,80} wrote:)",
    re.IGNORECASE | re.MULTILINE,
)

def split_instruction(text: str) -> tuple[str, str]:
    """Separate owner instruction from quoted, pasted and forwarded data."""
    quoted: list[str] = []

    def take(m: re.Match[str]) -> str:
        quoted.append(m.group(0))
        return " "

    s = unicodedata.normalize("NFKC", text or "")
    s = _HERMES_CONTEXT.sub(take, s)
    s = _PASTED_TAG.sub(take, s)
    s = _FENCE.sub(take, s)
    s = _HEADER_BLOCK.sub(take, s)
    m = _FORWARD_MARK.search(s)
    if m:
        quoted.append(s[m.start():])
        s = s[: m.start()]
    kept = []
    for line in s.splitlines():
        if line.lstrip().startswith(">"):
            quoted.append(line)
        else:
            kept.append(line)
    s = "\n".join(kept)
    s = _INLINE_CODE.sub(take, s)
    s = _QUOTED.sub(take, s)
    return s.strip(), "\n".join(quoted).strip()



def combined_instruction(instructions: list[str]) -> str:
    """Owner instructions awaiting interpretation, oldest first, as one request.

    Each part is already free of quoted material, so a fence left open in one
    message cannot swallow the next.
    """
    total = len(instructions)
    return "\n\n".join(f"[Owner message {i} of {total}]\n{text}" for i, text in enumerate(instructions, 1))
