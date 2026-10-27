"""AgentsFence: task-scoped authorization for AI agents.

Give agents freedom to think. Boundaries on what they can do.

Public API::

    from agentsfence import compile_policy, evaluate

    policy = compile_policy("Summarize my inbox. Do not send anything.")
    decision = evaluate(policy, "mcp_gmail_send_message", {"to": "x@evil.com"})
    decision.decision  # Verdict.BLOCK
"""

from __future__ import annotations

from typing import Any

from .compiler import CompileContext, LLMClient, PolicyCompiler
from .config import Settings, load_settings
from .evaluator import Evaluator
from .guards import Guards
from .models import Decision, ExecutionState, RiskClass, TaskPolicy, ToolConstraint, Verdict
from .risk import RiskClassifier

__version__ = "0.2.0a9"

__all__ = [
    "CompileContext",
    "Decision",
    "ExecutionState",
    "RiskClass",
    "TaskPolicy",
    "ToolConstraint",
    "Verdict",
    "compile_policy",
    "evaluate",
    "__version__",
]


def compile_policy(
    user_request: str,
    context: CompileContext | dict[str, Any] | None = None,
    *,
    settings: Settings | None = None,
    client: LLMClient | None = None,
) -> TaskPolicy:
    """Compile a natural-language request into a task-scoped policy.

    Never raises for compiler failures: returns the conservative fallback
    policy instead (``policy.source == "fallback"``).
    """
    s = settings or load_settings()
    ctx = context if isinstance(context, CompileContext) else CompileContext(**(context or {}))
    return PolicyCompiler(s, RiskClassifier(s.risk_config), client).compile(user_request, ctx).policy


def evaluate(
    policy: TaskPolicy,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    execution_state: ExecutionState | None = None,
    *,
    settings: Settings | None = None,
) -> Decision:
    """Deterministically decide ALLOW / BLOCK / ASK_USER for one tool call."""
    s = settings or load_settings()
    clf = RiskClassifier(s.risk_config)
    ev = Evaluator(s, clf, Guards(s.guards, agentsfence_home=s.home))
    return ev.evaluate(policy, tool_name, arguments or {}, execution_state or ExecutionState())
