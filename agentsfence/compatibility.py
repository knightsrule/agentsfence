"""Refuse host extensions that can rewrite arguments after authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def tool_hook_conflict(own_hook: Callable[..., Any]) -> str | None:
    """Inspect the live registry on every call, without changing callback order.

    Hermes runs all pre-tool hooks on the original arguments and applies their
    modify directives afterwards. Execution middleware can rewrite them later
    still. Until Hermes offers a final-argument veto, neither can coexist safely
    with enforcement. Request middleware runs before the veto and is supported.
    Lookup errors propagate to the caller's fail-closed boundary.
    """
    from hermes_cli.plugins import has_middleware, iter_hook_callbacks

    callbacks = iter_hook_callbacks("pre_tool_call")
    foreign = [cb for cb in callbacks if cb != own_hook]
    if own_hook not in callbacks:
        raise RuntimeError("AgentsFence's enforcement hook is missing from Hermes' registry")
    reasons = []
    if foreign:
        names = sorted({f"{getattr(cb, '__module__', type(cb).__module__)}."
                        f"{getattr(cb, '__qualname__', type(cb).__qualname__)}" for cb in foreign})
        reasons.append("another pre_tool_call hook (" + ", ".join(names) + ")")
    if has_middleware("tool_execution"):
        reasons.append("tool execution middleware")
    if not reasons:
        return None
    return ("AgentsFence BLOCKED this action: incompatible " + " and ".join(reasons)
            + " can change tool arguments after authorization. Disable those extensions in this protected profile "
            "and restart Hermes. Tool request middleware, which runs before authorization, is supported.")
