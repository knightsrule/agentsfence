"""Explicit compiler probes in Hermes' own Python and profile."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from .diagnostics import public_compiler_error
from .testkit.progress import Progress


def probe_compiler(fence: Any) -> dict[str, Any]:
    """Compile a fixed request under the same deadline a chat's compile gets."""
    from .compiler import CompileContext
    from .plugin import _finished, _host_hook_deadline, budget_warning, compile_budget

    evidence = fence.evidence()
    budget = compile_budget(fence.settings)
    started = time.monotonic()
    result = fence.compiler.compile("Read the report. Do not write, send, delete or run anything.",
                                    CompileContext(deadline=_host_hook_deadline()))
    seconds = round(time.monotonic() - started, 2)
    data = {"ok": not result.fell_back, "fell_back": result.fell_back, "model": result.policy.compiler_model,
            "seconds": seconds, **budget, "error": public_compiler_error(result.error) if result.fell_back else None,
            "warning": None if result.fell_back else budget_warning(seconds, budget, result.policy.compiler_model)}
    fence._audit("compiler_probe", details={**data, "provenance": _finished(evidence, result.policy.compiler_model)})
    return data


def probe_compiler_eval(fence: Any) -> dict[str, Any]:
    """Use the same host-owned compiler client and provenance as normal requests."""
    from .plugin import _finished
    from .testkit.compiler_eval import run

    fence._sync_route()
    evidence = fence.evidence()
    result = run(fence.settings, client=fence.compiler.client)
    model = next((row["model"] for row in reversed(result["timings"]) if row.get("model")), None)
    result["provenance"] = _finished(evidence, model)
    fence._audit("compiler_eval", details={**result, "test_run": True,
                                           "fell_back": bool(result["fallback_compiles"])})
    return result


def run_probe(home: Path, kind: str = "compiler", scenarios: list[str] | None = None,
              *, progress: Progress | None = None) -> dict[str, Any]:
    """Probe in a fresh Hermes process started by Hermes' own launcher.

    The launcher decides the runtime and dependencies; this caller's package is
    never injected, so a stale AgentsFence elsewhere cannot mask the real one.
    """
    from .host_client import probe

    return probe(home, kind, scenarios, progress=progress)


def main() -> None:
    try:
        from dotenv import load_dotenv
        from hermes_constants import get_hermes_home

        load_dotenv(get_hermes_home() / ".env", override=True)
        from hermes_cli.plugins import get_plugin_manager

        from .plugin import get_instance

        get_plugin_manager().discover_and_load()
        fence = get_instance()
        if fence is None:
            # A directory checkout has an isolated package namespace; its
            # registered instance must be probed instead of a wheel copy.
            entry = (get_hermes_home() / "plugins/agentsfence/__init__.py").resolve()
            for module in tuple(sys.modules.values()):
                filename = getattr(module, "__file__", None)
                if isinstance(filename, str) and Path(filename).resolve() == entry:
                    # The checkout's register() is a fail-closed wrapper; its implementation
                    # lives in the checkout package's own plugin module.
                    registered = sys.modules.get(module.__name__ + ".agentsfence.plugin")
                    if registered and hasattr(registered, "get_instance"):
                        fence = registered.get_instance()
                        break
        data = probe_compiler(fence) if fence else {"ok": False, "error": "AgentsFence is not loaded in this profile."}
    except Exception as exc:
        data = {"ok": False, "error": public_compiler_error(str(exc))}
    print("AGENTSFENCE_PROBE=" + json.dumps(data))


if __name__ == "__main__":
    main()
