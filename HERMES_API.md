# Hermes Agent hook APIs used by AgentsFence

This document records the **actual** Hermes Agent plugin/hook surface that
AgentsFence is built against, verified by reading the Hermes source rather than
assumed. Verified against `NousResearch/hermes-agent` commit `0e281b58e`
(2026-07-20). File references are relative to the Hermes repository root.

If you upgrade Hermes, re-check the items marked **(load-bearing)**: the
enforcement guarantee depends on them.

## Supported Hermes versions

AgentsFence supports Hermes with PM and the capabilities verified by `preflight.py`. The gate covers **two managed environments**: main `801a9022a742562a3c4578c0d8dd12cfd393fc47` and RC `64f2be353fd8bcf6badbe22f6da8b83398b25665` (`rc.14-v0.21.5`). Stable v2026.9.24 without PM is unsupported; run `hermes update` to move a source install to main. Capability checks decide compatibility, because build version strings alone are insufficient.

Required: all enforcement hooks, native block precedence, approval bypass/session APIs and gateway context, the configured hook timeout, `PluginLlm.complete(task=...)`, auxiliary task registration, live hook/middleware registry inspection and PM plugin dependencies. Optional model-listing/pricing APIs are required only by the profile test's model selection. CI also checks tip of main without blocking release and Windows process liveness.


## 1. Plugin discovery and registration

Source: `hermes_cli/plugins.py`

Hermes loads plugins from four sources (later wins on name collision):

| Source | Location | Notes |
|---|---|---|
| Bundled | `<hermes>/plugins/<name>/` | shipped with Hermes |
| User | `~/.hermes/plugins/<name>/` | where `hermes plugins install` clones to |
| Project | `./.hermes/plugins/<name>/` | only with `HERMES_ENABLE_PROJECT_PLUGINS=1` |
| Pip | entry-point group `hermes_agent.plugins` | `ENTRY_POINTS_GROUP = "hermes_agent.plugins"` |

A directory plugin needs `plugin.yaml` **and** `__init__.py` exposing
`register(ctx)`. A pip plugin's entry point must resolve to a module exposing
`register(ctx)`.

**Plugins are opt-in.** Nothing loads unless its name is in `plugins.enabled`
in `~/.hermes/config.yaml` (`_get_enabled_plugins()`); `plugins.disabled`
always wins. `hermes plugins enable <name>` edits that list.

`PluginManifest` fields read from `plugin.yaml`: `name`, `version`,
`description`, `author`, `requires_env`, `provides_tools`, `provides_hooks`
(written as `hooks:` in the YAML), `kind` (default `standalone`).

`PluginContext` (the `ctx` passed to `register`) methods we use:

```python
ctx.register_hook(hook_name: str, callback: Callable) -> None
ctx.register_command(name: str, handler: Callable[[str], str | None],
                     description: str = "", args_hint: str = "") -> None   # /slash command
ctx.register_cli_command(name, help, setup_fn, handler_fn=None, description="")  # `hermes <name>`
ctx.register_auxiliary_task(key, *, display_name, description, defaults=None)  # compiler model slot
ctx.llm  # agent.plugin_llm.PluginLlm — host-owned completions; complete(task=...) routes through the slot
```

## 2. Hook invocation semantics (load-bearing)

```python
PluginManager.invoke_hook(hook_name: str, **kwargs) -> list[Any]
```

* Callbacks are called with **keyword arguments only**. Hermes adds
  `telemetry_schema_version` to every call, and may add more kwargs over time,
  so callbacks must accept `**kwargs`.
* Each callback runs inside `try/except Exception`; **an exception is logged
  and swallowed, and the callback contributes no result.**
* Non-`None` return values are collected into a list.

> **Mismatch with a naive design:** a guardrail whose `pre_tool_call` raises is
> treated as "no directive" — i.e. the tool **runs**. Hermes hooks are
> fail-open. AgentsFence therefore wraps every hook body and converts any
> internal error into an explicit `block` directive (see `plugin.py`).

## 3. `pre_llm_call`

Call site: `agent/turn_context.py` (once per **user turn**, before the tool loop
— not once per model API call inside the loop).

```python
invoke_hook(
    "pre_llm_call",
    session_id=agent.session_id,
    task_id=effective_task_id,     # task_id or a fresh uuid4 per turn
    turn_id=turn_id,
    user_message=original_user_message,
    conversation_history=list(messages),
    is_first_turn=(not bool(conversation_history)),
    model=agent.model,
    platform=...,                  # "cli", "telegram", ...
    sender_id=...,
)
```

Return value: `{"context": "text"}` or a plain string. The text is appended to
the **current user message** (never the system prompt) and is ephemeral (not
persisted). It cannot block the turn.

Consequences for AgentsFence:

* `session_id` is the stable key across turns; `task_id` may be a new UUID each
  turn. Policies are keyed by `session_id` with `task_id` stored as an alias.
* `user_message` is the user's own input for top-level sessions. For
  **subagents** (see §7) the first "user message" is the goal text written by
  the parent *model* — it must never be compiled into authority.
* `conversation_history` contains tool output (e.g. email bodies) and is
  therefore attacker-influenced. The compiler only reads `user_message`.

## 4. `pre_tool_call` (load-bearing)

Call sites: `agent/tool_executor.py` (sequential and concurrent paths),
`agent/agent_runtime_helpers.py`, and `model_tools.handle_function_call` (for
callers that did not already fire it). All go through one function:

```python
hermes_cli.plugins.resolve_pre_tool_block(
    tool_name, args, task_id="", session_id="", tool_call_id="",
    turn_id="", api_request_id="", middleware_trace=None,
) -> Optional[str]        # block message, or None to proceed
```

which invokes the hook with:

```python
invoke_hook("pre_tool_call",
    tool_name=str, args=dict, task_id=str, session_id=str,
    tool_call_id=str, turn_id=str, api_request_id=str,
    middleware_trace=list)
```

Recognised return values (precedence depends on the Hermes revision, below; anything else is ignored):

```python
{"action": "block",   "message": "reason"}                  # veto; message becomes the tool result
{"action": "approve", "message": "reason", "rule_key": "k"}  # escalate to the human approval gate
None                                                          # no opinion → tool proceeds
```

* **(load-bearing) Any valid `block` outranks any `approve`**, whatever the
  plugin registration order (Hermes #87420); among approves the first valid one
  wins. The capability preflight checks this behaviourally before a profile is
  protected, and the competing-hook tests (an approve-all plugin loaded before
  AgentsFence, with `--yolo`) run on every CI revision. Hermes before this change
  acted on the first directive in registration order; AgentsFence 0.3.0 does
  not support those revisions.
* A `block` **without** a non-empty `message` is ignored (→ tool runs).
  AgentsFence always sets a message.
* There is **no explicit "allow" directive**. Returning `None` means "no
  objection". Another plugin can still block.
* The hook fires **before** the tool executes and before checkpointing. A
  blocked call never reaches the tool handler; `post_tool_call` then fires
  with `status="blocked"`, `error_type="plugin_block"`.
* `_AGENT_LOOP_TOOLS = {"todo", "memory", "session_search", "delegate_task"}`
  are handled inside the agent loop; they still pass through
  `resolve_pre_tool_block` on the tool-executor path.
* Per-thread tool whitelists and toolset scoping
  (`set_thread_tool_whitelist`, `_ts_scope_block`) run *before* plugin hooks.
  These are how Hermes enforces the user's enabled toolsets; AgentsFence
  narrows within them and never widens them.

### Argument-changing extensions

Hermes merges `pre_tool_call` modify directives after every callback saw the original arguments. Tool execution middleware can rewrite arguments even later. There is no final-argument veto on the pinned revisions. AgentsFence therefore refuses all tool calls while any other `pre_tool_call` callback or any `tool_execution` middleware is registered. This deliberately includes benign callbacks: a hook declaration does not certify whether it can return a modify directive. The live registry is checked on every call through `iter_hook_callbacks` and `has_middleware`; lookup failures block too. Doctor and lifecycle verification report the conflict. Restart Hermes after disabling the incompatible extension. Request middleware is supported because its resulting arguments are checked before authorization.

`test_native_final_argument_rewrites_never_execute` exercises both callback orders, execution middleware, and request middleware through native dispatch to a mock handler on both pins. Coexistence with argument-changing execution extensions requires a host final-argument enforcement contract.

## 5. Human approval (`ASK_USER`)

`resolve_pre_tool_block` handles an `approve` directive by calling:

```python
tools.approval.request_tool_approval(tool_name, reason, *, rule_key="", approval_callback=None) -> dict
# {"approved": bool, "message": str | None, ...}
```

which uses the same gate as dangerous shell commands (`_run_approval_gate`):

1. `--yolo` / session yolo → **approved without prompting.**
2. `is_approved(session_key, "plugin_rule:<rule_key>")` → approved from the
   session / permanent allowlist without prompting.
3. Interactive CLI → `[o]nce / [s]ession / [a]lways / [d]eny` prompt.
4. Gateway (Telegram, Slack, ...) → gateway approval callback.
5. Cron → `approvals.cron_mode`.
6. Any other non-interactive context → **blocked** (`fail_closed_when_no_human=True`).
7. Gate error, deny, or timeout → blocked (fail-closed in `resolve_pre_tool_block`).

The plugin does **not** get a return value from the gate. Outcomes are
observable through:

* `post_approval_response(command, description, pattern_key, pattern_keys,
  session_key, surface, choice, turn_id, tool_call_id)` with
  `choice ∈ {"once","session","always","deny","timeout","smart_approve","smart_deny"}`
  and `pattern_key == "plugin_rule:<rule_key>"`. For plugin-escalated approvals
  this fires **only on the gateway path** (`_await_gateway_decision`). It is
  **not** fired on paths 1–2 (yolo, allowlist), and the interactive CLI path
  (`prompt_dangerous_approval` inside `_run_approval_gate`) does not fire it
  either. (Hermes' dangerous-*command* path does fire it; the plugin path does
  not.)
* `post_tool_call(..., status=...)` — fired after execution, or with
  `status="blocked"` when the gate refused.

AgentsFence therefore: (a) uses a `rule_key` scoped to the task **and** the exact
capability delta, so an `[a]lways` answer can never blanket-approve other
recipients or other tasks; (b) records the user's choice from
`post_approval_response`; (c) reconciles via `post_tool_call`, so an approval that
was short-circuited by yolo or the allowlist is still recorded and consumed.

### Tool arguments that change what a tool does (load-bearing for classification)

* `browser_console(expression=...)` evaluates the expression as JavaScript in
  the page (`tools/browser_tool.py`). Without `expression`, the tool only reads
  console output. The optional expression denylist is off by default.
* `patch(mode="patch", patch=...)` applies a V4A multi-file patch. There is no
  top-level `path`; files are named by `*** Add File:`, `*** Update File:`,
  `*** Delete File:` and `*** Move File: src -> dst` headers
  (`tools/patch_parser.py`). The header regexes tolerate extra whitespace
  (`***Update  File:`), so a stricter matcher misses files Hermes will write.
  `parse_v4a_patch(text)` returns operations with `file_path` and, for moves,
  `new_path`; AgentsFence unions its own header scan with this parser's output.
* `write_file` / `patch` accept `cross_profile=True` to write into another
  profile's `HERMES_HOME`.
* `execute_code` runs Python that can call Hermes tools. Those nested calls go
  through `model_tools.handle_function_call(tool_name, tool_args, task_id=task_id)`,
  with **no `session_id` and no `tool_call_id`** (`tools/code_execution_tool.py`).

## 6. `post_tool_call`

```python
invoke_hook("post_tool_call",
    tool_name, args, result, task_id, session_id, tool_call_id, turn_id,
    api_request_id, duration_ms?, status?, error_type?, error_message?,
    middleware_trace)
```

Used to commit or release call-count reservations.

## 7. Session and subagent lifecycle

* `on_session_start(session_id, ...)`, `on_session_end`, `on_session_finalize`,
  `on_session_reset(session_id)` — observers. AgentsFence drops the session's
  policy on `on_session_reset` (`/new`) and `on_session_finalize`.
* `subagent_start(parent_session_id, parent_turn_id, parent_subagent_id,
  child_session_id, child_subagent_id, child_role, child_goal)` fires in
  `tools/delegate_tool.py` **before** the child agent runs. The child has its
  own `session_id` and `task_id` (`subagent-<n>-<hex>`). AgentsFence binds the
  child session to the parent's policy here, so the child's first
  `pre_llm_call` (whose "user message" is model-written) never compiles a new
  policy.

### More lifecycle facts

* `on_session_finalize(session_id, platform, reason)` fires with
  `reason="shutdown"` when the CLI exits, and with
  `reason="new_session" | "session_boundary"` on `/new` and other boundaries.
  A session ended by shutdown can be resumed with `--resume` / `--continue`.
* `pre_llm_call` passes `sender_id` (the gateway user id; empty in the CLI).
  Gateway `group_sessions_per_user` (default `true`) isolates group chats per
  participant *when the platform provides user ids*. Otherwise several people
  can share one session.
* `ctx.register_command(name, handler)`: the handler receives only
  `raw_args: str`, with no session or sender. In a gateway process, one handler
  serves every chat. `tools.approval._is_gateway_approval_context()` tells a
  gateway process from the CLI.
* `HERMES_SAFE_MODE=1` skips plugin discovery entirely
  (`hermes_cli/plugins.py`), so no plugin, including a guardrail, runs.
* Profiles: `hermes -p <name>` sets `HERMES_HOME` to
  `~/.hermes/profiles/<name>`. `plugins.enabled`, `.env`, and AgentsFence's
  state (`$HERMES_HOME/agentsfence`) are per profile.

## 8. Tool names

Hermes tool names are flat identifiers, not the dotted names used in design
sketches (`gmail.send`). Built-ins include `read_file`, `write_file`, `patch`,
`search_files`, `terminal`, `process`, `execute_code`, `web_search`,
`web_extract`, `browser_navigate`, `browser_click`, `browser_type`,
`send_message`, `cronjob`, `skill_manage`, `delegate_task`, `memory`, `todo`.
MCP tools are registered as `mcp_<server>_<tool>` in toolset `mcp-<server>`.

AgentsFence maps concrete names to **capabilities** (`email.send`,
`file.read`, ...) and **risk classes** via `policies/defaults.yaml`, with glob
patterns for MCP servers and a verb-based classifier for unmapped tools.

## 9. Hermes behaviour that differs from what a plugin might expect

| Expected | Actual Hermes behaviour | How AgentsFence adapts |
|---|---|---|
| Hook can return ALLOW / BLOCK / ASK_USER | Only `block`, `approve`, or `None` | `ALLOW → None`, `BLOCK → block`, `ASK_USER → approve` |
| Hook errors stop the tool | Hook errors are swallowed → tool runs | Every hook body catches all exceptions and returns `block` |
| Approval result returned to plugin | Not returned; `post_approval_response` fires only for gateway approvals | Record choice when it fires; otherwise infer a single-use grant from `post_tool_call(status != "blocked")` |
| Approval always prompts | yolo / allowlist / cron can auto-approve | Task-scoped `rule_key`; fallback and `strict_yolo` block a question when Hermes' bypass, exact `plugin_rule:` allowlist or unattended cron path would decide without a human |
| `pre_llm_call` fires once per task | Fires once per user turn | Compile on first turn; later turns *amend* from the user's new message only |
| Stable `task_id` | `task_id` may change per turn | Key by `session_id`, alias `task_id` |
| Dotted tool names (`gmail.send`) | Flat names, `mcp_<server>_<tool>` | Capability + risk mapping with globs |
| Subagents share the task | Child has new session/task ids | Bind child to parent policy on `subagent_start`; alias the child's task id on its first `pre_llm_call` |
| A plugin's `block` is final | Both pinned revisions give BLOCK precedence | Preflight verifies this; older first-directive hosts are unsupported |
| A plugin that fails to load is reported | Hermes logs the failure and continues without the plugin | Fail-closed loader installs a blocking hook; doctor asks Hermes what a new process loads |
| Every tool call carries session and call ids | `execute_code` nested dispatch passes only `task_id` | Resolve by task alias through subagent links; unknown task-only calls are blocked |
| Read tools only read | `browser_console(expression)` runs JS; `patch` mode names files inside the patch text | `arg_present_risk`, `patch_args` |
| Finalize means the session is over | Finalize also fires on CLI shutdown, and sessions can be resumed | Keep records on `reason="shutdown"`; drop on `/new` |
| Slash commands know the caller | Handlers get only `raw_args` | `/fence` refuses in gateway processes |

## Profile and desktop surfaces

`profiles.py` owns the files AgentsFence writes in a profile: `plugins.enabled`, the fail-closed loader and manifest, the `agentsfence_policy` route and the hook timeout. `lifecycle.py` wraps every change (install, protect, unprotect, settings, uninstall) in a journaled transaction with the capability preflight, `hermes pm install`, verification that a new Hermes process loads this version, and rollback. Core compilation uses `ctx.llm`; Hermes owns routing and credentials.

`diagnostics.py` supplies CLI and desktop snapshots. Doctor's enforcement result comes from two checks, each ok, problem or unverified, and compiler health and Hermes capabilities are reported beside it: (1) **new-process load**, asked of Hermes itself through `host_client.py`, which runs `hermes -p <profile> agentsfence status --json` with no `PYTHONPATH` from the caller, bounded, identity-checked, and left running (never killed) if Hermes outlives the timeout; (2) **running processes**: registrations checked against PID/start identity, version and the restart digest (`configuration_digest`, settings AgentsFence reads only at load), plus a scan of the user's Hermes processes, where an unavailable scan is unverified; compiler health (healthy, slow, failed, not verified) comes from **compiler evidence**: compile, amend and probe audit rows carry provenance captured when the operation starts (version, `evidence_digest` of the compiler route, grant and settings, actual model), and only evidence matching the current version, evidence digest and Hermes routing mode (reported by `hermes agentsfence status`) is current. Load-status records (`load_status/<profile>-<python>.json`) are history only. The authenticated Hermes dashboard mounts `desktop_api.router`; no separate public AgentsFence server is started.

`desktop/` and `dashboard/` are the canonical assets; the wheel build maps them into `agentsfence/surfaces`. Protect materializes wheel assets and preserves directory checkouts. Directory entry points import their own package under Hermes' namespace, and their dashboard API resolves that same package. Fallback state, sanitized errors and prohibition origins are persisted on policies and exposed in operator views. Audit context-injection events distinguish model-visible guidance from actual enforcement decisions. `agentsfence test` sessions carry the `agentsfence-test-` prefix; live test turns tag their audit rows with `details.test_run`.

Hermes Desktop expands `@url` and other references below `--- Attached Context ---` (or `--- Context Warnings ---`) before calling the hook. `split_instruction` excludes the entire footer from authorization. Desktop status and validation use the SDK's `focusedStoredSessionId` (the agent/audit ID), with owner backend/profile checks; runtime UI IDs are not audit IDs.

Newer Hermes bounds `pre_llm_call` with `plugins.hook_callback_timeout` and may proceed after abandoning its worker. AgentsFence blocks dispatch while that session (or its parent) is compiling. The compiler bounds queueing, execution and retry to the configured compiler timeout and 80% of the host callback budget. Invalid or failing private timeout lookups use a conservative 30-second host budget instead of aborting policy creation. Provider workers only return draft strings and cannot install late policies. A bounded pool allows four concurrent requests by default; each abandoned request retains its slot until it returns. Full capacity produces an explicit fallback, and same-chat amendments serialize within their original callback budgets. Runtime registration exposes compiling sessions to CLI and Desktop. The historical `policy_context_injected` event records context prepared by the hook, not an acknowledgement from the host that it was inserted into a model request.
