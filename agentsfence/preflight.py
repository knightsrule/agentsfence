"""Capability preflight: does this Hermes provide everything AgentsFence relies on?

`hermes pm` only tells AgentsFence how to install; it does not establish that Hermes
enforces what AgentsFence depends on. Before install, protect or settings change
anything, and on every doctor run, AgentsFence asks Hermes' own interpreter (a
separate process, so it works before AgentsFence is installed there) to check:

* the plugin hooks AgentsFence registers;
* block precedence, behaviourally: Hermes' own directive resolution, given an
  ``approve`` from an earlier plugin and a ``block`` from a later one, returns ``block``;
* the approval APIs AgentsFence reads (bypass, allowlist, session key, gateway context);
* the plugin hook timeout (``plugins.hook_callback_timeout``);
* plugin model access routed by auxiliary task, and task registration;
* the plugin CLI and slash commands doctor and ``/fence`` use;
* the package manager's plugin ``python_dependencies``.

Optional capabilities (model discovery for ``agentsfence test``) are reported but
never block. Standard library only on this side.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .hermes_env import CHECK_TIMEOUT, HermesInstall, pending_work, unsupported_reason

MARKER = "AGENTSFENCE_PREFLIGHT="

#: Runs in Hermes' interpreter with the Hermes source first on sys.path.
_SCRIPT = r'''
import inspect, json, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
REQUIRED_HOOKS = ["pre_llm_call", "pre_tool_call", "post_tool_call", "post_approval_response",
                  "subagent_start", "on_session_reset", "on_session_finalize"]
missing, optional = [], []

def need(name, check):
    try:
        if not check():
            missing.append(name)
    except Exception as exc:
        missing.append(f"{name} ({type(exc).__name__})")

def want(name, check):
    try:
        if not check():
            optional.append(name)
    except Exception as exc:
        optional.append(f"{name} ({type(exc).__name__})")

def hooks():
    from hermes_cli.plugins import VALID_HOOKS
    absent = [h for h in REQUIRED_HOOKS if h not in VALID_HOOKS]
    if absent:
        raise LookupError(",".join(absent))
    return True

def block_precedence():
    import hermes_cli.lifecycle as lifecycle
    import hermes_cli.plugins as plugins
    original = lifecycle.invoke_hook
    lifecycle.invoke_hook = lambda name, **kw: [
        {"action": "approve", "message": "earlier plugin approves"},
        {"action": "block", "message": "later plugin blocks"},
    ] if name == "pre_tool_call" else original(name, **kw)
    try:
        details = plugins._get_pre_tool_call_directive_details("agentsfence_preflight", {})
    finally:
        lifecycle.invoke_hook = original
    return getattr(details, "action", None) == "block"

def approvals():
    import tools.approval as approval
    for name in ("is_approval_bypass_active", "is_approval_bypass_active_for_session", "is_approved",
                 "get_current_session_key", "_is_gateway_approval_context"):
        if not callable(getattr(approval, name, None)):
            raise LookupError(name)
    return True

def hook_timeout():
    import hermes_cli.plugins as plugins
    original = plugins.load_config_readonly
    plugins.load_config_readonly = lambda: {"plugins": {"hook_callback_timeout": 0.02}}
    try:
        if plugins._resolve_hook_callback_timeout() != 0.02:
            return False
        manager = plugins.PluginManager()
        manager._hooks["pre_tool_call"] = [lambda **kw: time.sleep(0.15)]
        began = time.monotonic()
        results = manager.invoke_hook("pre_tool_call", tool_name="probe", args={})
        return time.monotonic() - began < 0.12 and any(
            isinstance(r, dict) and r.get("action") == "block" for r in results)
    finally:
        plugins.load_config_readonly = original

def task_routing():
    from agent.plugin_llm import PluginLlm
    return "task" in inspect.signature(PluginLlm.complete).parameters

def context_api():
    from hermes_cli.plugins import PluginContext
    return all(callable(getattr(PluginContext, name, None)) for name in
               ("register_hook", "register_auxiliary_task", "register_cli_command", "register_command"))

def extension_registry():
    from hermes_cli.plugins import iter_hook_callbacks, has_middleware
    return callable(iter_hook_callbacks) and callable(has_middleware)

def plugin_dependencies():
    from pm.plugin_declarations import read_python_declaration
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "plugin.yaml").write_text("name: probe\nversion: '0'\npython_dependencies: ['agentsfence==0.0.0']\n")
        return "agentsfence==0.0.0" in read_python_declaration(Path(tmp)).requirements

def model_discovery():
    from hermes_cli.models import list_available_providers, provider_model_ids
    return callable(list_available_providers) and callable(provider_model_ids)

def pricing():
    from hermes_cli.models_pricing import get_pricing_for_provider
    return callable(get_pricing_for_provider)

need("plugin hooks", hooks)
need("block precedence (a plugin's block wins over another plugin's approve)", block_precedence)
need("approval APIs", approvals)
need("plugin hook timeout (plugins.hook_callback_timeout)", hook_timeout)
need("plugin model routing by auxiliary task", task_routing)
need("plugin registration API", context_api)
need("live tool extension registry", extension_registry)
need("plugin python_dependencies in the package manager", plugin_dependencies)
want("model discovery", model_discovery)
want("model pricing", pricing)
print("AGENTSFENCE_PREFLIGHT=" + json.dumps({"missing": missing, "optional_missing": optional}))
'''


def _remedy(missing: list[str]) -> str:
    return (f"This Hermes lacks what AgentsFence needs: {'; '.join(missing)}. Update Hermes (`hermes update`), then "
            "re-run this command. Nothing was changed.")


def run(install: HermesInstall, home_root: Path) -> dict[str, Any]:
    """``{"ok", "missing", "optional_missing", "error"}`` for this Hermes; never starts Hermes itself."""
    reason = unsupported_reason(install)
    if reason:
        return {"ok": False, "missing": ["Hermes with `hermes pm`"], "optional_missing": [], "error": reason}
    work = pending_work(install, home_root)
    if work:
        return {"ok": False, "missing": [], "optional_missing": [], "pending": work[0],
                "error": f"{work[1]}. Nothing was changed."}
    assert install.python is not None and install.source is not None
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")}
    env["HERMES_HOME"] = str(home_root)
    try:
        proc = subprocess.run([str(install.python), "-I", "-B", "-c", _SCRIPT, str(install.source)], env=env,
                              capture_output=True, text=True, timeout=CHECK_TIMEOUT * 2, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "missing": [], "optional_missing": [],
                "error": f"The capability check could not run in Hermes' Python ({exc}). Nothing was changed."}
    line = next((x for x in reversed(proc.stdout.splitlines()) if x.startswith(MARKER)), "")
    try:
        data = json.loads(line[len(MARKER):]) if line else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [f"exit status {proc.returncode}"]
        return {"ok": False, "missing": [], "optional_missing": [],
                "error": f"The capability check gave no answer ({detail[0][:200]}). Nothing was changed."}
    missing = [str(m) for m in data.get("missing") or []]
    return {"ok": not missing, "missing": missing, "optional_missing": [str(m) for m in data.get("optional_missing") or []],
            "error": _remedy(missing) if missing else None}
