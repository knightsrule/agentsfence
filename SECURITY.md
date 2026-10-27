# Security

AgentsFence is a security control, so this document is deliberately specific about what it protects against and what it does not.

## Reporting a vulnerability

Please **do not open a public issue** for a bypass. Report it privately through GitHub Security Advisories on this repository ("Report a vulnerability"). Include:

- the user intent,
- the tool call(s) that got through,
- the compiler provider and model,
- the output of `agentsfence audit -n 50 --json` with anything sensitive removed.

We aim to acknowledge reports within 3 business days.

A **bypass** is any case where a tool call executes that the task policy should have blocked or sent for approval, or where authority reaches a policy from anywhere other than the user's own message. Both are in scope.

## Threat model

**Trusted**
- The user's own messages, as delivered by Hermes in `pre_llm_call.user_message` for top-level sessions.
- The Hermes runtime and its plugin dispatch: `resolve_pre_tool_block`, the approval gate, and the tool registry.
- The local machine, the AgentsFence configuration, and the user's approval answers.

**Untrusted**
- Everything the agent reads: email bodies, web pages, documents, file contents, tool results, MCP server responses.
- The agent model's reasoning and output, including arguments it chooses for tool calls and goals it writes for subagents.
- The compiler model's reading of the owner's message is the trust boundary. Structural validation only restricts its proposed grants and cannot verify meaning. No deterministic rule adds omitted authority. Interpretation text is display/audit only.

**Adversary capabilities assumed**
- Can place arbitrary text in content the agent reads (indirect prompt injection).
- Can cause the agent model to emit any sequence of tool calls with any arguments.
- Can influence the compiler model only through the user's message. Pasted and quoted content is stripped before compilation.

**Out of scope**
- A compromised Hermes installation or Python environment.
- A malicious user. AgentsFence protects users from their agent, not systems from their users.
- A local attacker with file-system access to `~/.hermes`.

## What AgentsFence guarantees

These properties hold for tool calls Hermes dispatches through `pre_tool_call`, under the assumptions in the threat model. "Holds" labels describe the previously recorded checks. The current beta patch is unverified; its required validation is recorded in [BETA_GATE.md](BETA_GATE.md). "Partial" means the property holds only within the stated scope.

External reviews have found counterexamples to G2, G4 and G10: a patch `Move File` into a forbidden directory, explanations counted as requests, send evidence authorizing other external writes, write actions of multiplexed "read" tools, and another plugin's `approve` winning on the first tool call. Each is fixed, and the regression tests listed below are named after them. See [CHANGELOG.md](CHANGELOG.md).

| # | Property | Status | How | Tests |
|---|----------|--------|-----|-------|
| G1 | **No authority from content.** Tool output, conversation history, subagent goals and model output never reach the compiler. In shared chats, only the task owner's messages can widen a policy. | Holds | The compiler receives only `user_message`. Subagent sessions and their task ids are bound to the parent's policy. Messages from non-owners only add prohibitions. | `test_policy_cannot_be_changed_by_tool_output`, `test_subagent_inherits_parent_policy_and_budget`, `test_nested_child_call_with_task_id_only_uses_parent_policy`, `test_group_chat_other_sender_cannot_widen_policy` |
| G2 | **Structurally bound authority.** Each grant names a classified capability, a verified instruction span, and its own literal recipient/destination targets. Negation, source/context roles, missing bindings, broad roots and unknown capabilities remove authority. Interpretation never authorizes. | Structural checks hold within tested scope; semantic correctness depends on the compiler model | Intent validation and per-grant constraints; deterministic restrict-only floor | Compiler intent unit tests, compiler evaluation corpus and attack suite |
| G3 | **Explicit prohibitions are absolute.** "Don't send / only read / don't buy / never delete" are extracted deterministically from your whole message (even when a long message is truncated for the compiler). They override the compiler and are checked before grants and approvals. BLOCK always beats ASK. | Holds for recognized phrasings | `extract_prohibitions()`; most-restrictive-wins in the evaluator | `test_prohibitions`, `test_prompt_injection_in_email_is_blocked`, `test_prohibition_beats_guard_question`, `test_trailing_prohibition_survives_truncation` |
| G4 | **Destructive, financial and permission changes default to BLOCK**; unknown tools default to ASK_USER. Arguments that change what a tool does are classified: `browser_console` with an expression is execution; multi-file patches are checked per file, including both sides of `Move File`, using Hermes' grammar and parser (`Delete File` is a delete); tools that multiplex reads and writes behind an `action` argument are reads only for declared read actions; "safe" shell commands with write or launcher options are not reads. | Holds for mapped tools and recognized commands | Class ceilings, `evaluation.unauthorized`, `arg_present_risk`, `patch_args`, `read_actions`, option-aware shell classifier | `test_read_only_policy_gates_consequential_actions`, `test_browser_console_expression_is_not_a_read`, `test_patch_headers_are_path_checked`, `test_patch_delete_header_is_a_delete`, `test_patch_move_into_forbidden_directory_is_blocked`, `test_patch_header_whitespace_variants_are_seen`, `test_read_mapped_tools_with_write_actions_are_not_reads`, `test_safe_command_names_with_mutating_forms_are_not_reads` |
| G5 | **Recipients are bound.** For an automatically allowed call under a compiled policy, every extracted recipient in `to`, `cc`, `bcc`, nested fields, or an unrecognized non-content key must match an address you named. A separate exact-action approval can authorize an unbound recipient. A domain listed for browsing does not authorize other addresses at that domain. Matching is exact after NFKC normalization. A manually written policy can deliberately allow a whole recipient domain when it lists no individual recipients. | Holds for recognized recipient fields and compiled policies | `extract_targets`, evaluator steps 6 and 8 | `test_recipient_binding_global`, `test_recipient_smuggled_under_unknown_key`, `test_authorized_communication_other_recipient_blocked_with_good_compiler`, `test_browsing_domain_does_not_widen_named_email_recipient`, `test_compiled_domain_is_not_recipient_authority`, `test_compiled_domain_still_asks_when_recipient_guard_disabled` |
| G6 | **Approvals cover exactly one action.** A grant is bound to the tool, capability, risk class and an action fingerprint (the command, code, recipients, paths, and so on; message content excluded). "Once" is single-use. Hermes' `[a]lways` is keyed to that action within that task. An auxiliary LLM's "smart" approval never mints a grant. | Holds | `Grant.fingerprint`, task-and-action-scoped `rule_key` | `test_session_grant_for_command_does_not_cover_other_commands`, `test_grant_for_one_code_snippet_only`, `test_grant_covers_only_exact_delta`, `test_unparseable_patch_asks_and_is_not_reusable`, `test_smart_llm_approval_mints_no_grant` |
| G7 | **Fail closed.** Internal errors → BLOCK. Startup failure → a hook that blocks every call. Compiler failure → read-only fallback (full-instruction prohibitions and only-domain bounds preserved). Under the fallback, questions become blocks for yolo, `approvals.mode: off`, exact allowlist hits and unattended cron runs. The same applies to ordinary policies with `strict_yolo`. A task-only call for an unknown task → BLOCK. ASK_USER with no human present → blocked by Hermes. | Holds for the verified Hermes approval API | `on_pre_tool_call` wrapper, `register()` stub, `compile()` fallback, exact `plugin_rule:` allowlist lookup | `test_internal_error_fails_closed`, `test_register_failure_installs_blocking_stub`, `test_failure_falls_back_read_only`, `test_fallback_policy_blocks_instead_of_asking_under_auto_approve`, `test_allowlisted_question_blocks_under_fallback_or_strict_mode`, `test_hermes_allowlist_lookup_uses_exact_plugin_rule_key`, `test_cron_has_no_human_approval_even_without_yolo`, `test_exact_hermes_allowlist_cannot_auto_approve_fallback_question`, `test_hermes_cron_approve_cannot_auto_approve_fallback_question`, `test_strict_yolo_blocks_exact_hermes_allowlist_hit`, `test_ask_user_fails_closed_without_a_human` |
| G8 | **No budget races.** Parallel calls can't exceed `max_calls`, including calls waiting on an approval (their counters are reserved until you answer). Subagents share the parent's counters. | Holds | Evaluation and reservation under one lock | `test_concurrent_calls_cannot_exceed_max_calls`, `test_pending_approval_reserves_budget`, `test_a_second_distinct_file_still_exceeds_the_limit`, `test_send_limits_still_count_every_call` |
| G9 | **The agent can't switch off its own fence.** Blocked regardless of policy: modifying AgentsFence state, the plugin directory, or any profile's Hermes `config.yaml`, `.env`, `auth.json` or `plugins/` (directly, through a patch, or via `$HERMES_HOME`); running `hermes plugins/config/hooks …` or `pip uninstall agentsfence`. Other state-changing shell commands inside the Hermes home, and `cross_profile` writes, need approval. | Holds for recognized paths and commands | `Guards` | `test_agent_cannot_disable_its_own_fence`, `test_hermes_home_via_variables_and_cd`, `test_patch_into_fence_state_is_blocked`, `test_sort_output_into_fence_state_is_blocked`, `test_cross_profile_and_other_profile_config` |
| G10 | **A BLOCK stops the tool**, verified against real Hermes dispatch. This includes the case where another plugin that approves everything is loaded first and Hermes runs in `--yolo`, on the first tool call of the process as well as later ones. | Holds on the two pinned revisions with native BLOCK precedence; incompatible post-inspection argument extensions block every call | Native BLOCK precedence; live extension compatibility check; Hermes `resolve_pre_tool_block` | `test_all_scenarios_through_real_hermes`, `test_other_plugins_approve_cannot_hide_block_on_first_call`, `test_other_plugins_approve_cannot_hide_block_later_in_task` |
| G11 | **Restrictions survive restarts.** Policies persist across Hermes restarts and `--resume`; only `/new` or policy expiry clears them. | Holds | Records kept on shutdown finalize, pruned on expiry | `test_shutdown_finalize_keeps_restrictions_for_resume`, `test_policy_persists_across_process_restart` |
| G12 | **A missing or broken AgentsFence blocks tools.** If Hermes runs the plugin but AgentsFence cannot import or start, a blocking hook vetoes every tool call ahead of other plugins, and doctor reports "Tools blocked; repair required". | Holds when Hermes discovers and runs the loader and honors its veto; not if Hermes skips or disables the plugin, which doctor reports as "Protection off" | Setup-written fail-closed loader (`failsafe.py`), enforcement-first `register()` with an explicit outcome | `test_missing_package_blocks_every_tool_ahead_of_an_earlier_approver`, `test_failure_after_partial_registration_still_blocks`, `test_required_hook_failure_after_enforcement_enters_recovery`, `test_missing_package_is_blocked_by_real_hermes_even_after_an_approver` |

**Trust boundary and validation.** The compiler model decides what the owner means. Span, polarity (English only), catalogue and target-binding checks only restrict its output; they cannot prove its semantic reading is correct. Each grant keeps its own target bindings and call budget. Source/context targets never authorize, and file saves never imply memory or skill writes. FINANCIAL and PERMISSION_CHANGE require approval by default. Interpretation statements and their selected quotes are retained for display and audit, never evaluated as permission.

**Owner turns and failure.** Every owner turn starts a pending revision. All tool calls, reads included, wait outside the store lock until the latest revision finishes or the hook deadline expires. A stale result cannot install, and its owner message is interpreted by the next revision: messages stay queued until a successful compile covers them; dropped/expired sessions wake waiters with BLOCK. Pending revisions and consequential suspension precede runtime grants. A failed amendment preserves deterministic restrictions and suspends consequential authority until a later successful update. Explicit prohibitions remain BLOCKs before that suspension. Execution counters and prohibition origins persist across revisions. Earlier permissions persist unless explicitly revoked, narrowed or replaced; references resolve only within prior authorized targets.

**Evaluation threshold.** Zero over-grants on the offline corpus is an acceptance threshold, not a guarantee about other messages or live models. Premium compiler models are recommended. Compilation retries once only for unparseable output, never for omitted authority; failure uses read-only fallback with full-instruction prohibitions and only-domain bounds intact.

**Call limits on files.** A limit on writes or deletes bounds how many files the task touches: rewriting or patching a file the task already wrote is not a new use. Limits on sending, external writes, execution and payments count every call.

## Additional heuristic defenses

These reduce risk, but they are heuristics, not guarantees:

- **Exfiltration-shaped URLs** anywhere in a call's non-content arguments (long query strings, long encoded tokens, email addresses in queries, embedded credentials) → ASK_USER.
- **Secret files** (`~/.ssh`, `~/.aws/credentials`, `~/.hermes/.env`, …) → ASK_USER even for reads.
- **Shell sub-classification**: `rm`, `git reset --hard`, `git branch -D`, `curl -d/-F/-X POST`, `scp`, `ssh`, `git push` and `sudo` are recognised inside `terminal` commands, including compound commands (`;`, `&&`, `|`). Commands treated as reads are checked option by option (`sort -o`, `rg --pre`, `find -fprintf`, `yq -i` are not reads). Environment-variable prefixes (`LD_PRELOAD=…`) and programs outside system directories (`./ls`) are always execution.
- **Pasted-content stripping**: code fences (``` and ~~~), inline code, `>` quotes, quoted strings, email header blocks, forwarded or replied messages, and `<pasted_content>`-style tags.
- **Verb inference** for unmapped MCP tools (first verb wins; strong verbs such as delete, send, pay and transfer escalate).
- **Memory and cron**: persistent memory writes and scheduled jobs require authority, because both can carry an injection beyond the current task.

## What AgentsFence does NOT protect against

- **Misreading your intent within your own words.** Validation ties permissions to spans and targets in your words. It cannot check that the model understood those words. For example, "remove the typo" could be read as permission to delete. For destructive or financial tasks, prefer explicit wording.
- **Other plugins and host internals.** Hermes must honor native block precedence; capability preflight verifies it. Protected profiles refuse tool calls when another `pre_tool_call` hook or any tool execution middleware is registered, since those can rewrite arguments after inspection. This includes benign hooks; disable them and restart Hermes. Request middleware runs before inspection and is supported. The registry is checked on every call and lookup errors block. Native mock dispatch tests cover both callback orders and both middleware paths (`test_native_final_argument_rewrites_never_execute`).
- **Group chats without sender ids.** Owner binding needs the platform to report who sent each message. Where it doesn't, any participant's message is treated as the owner's.
- **Safe mode.** `HERMES_SAFE_MODE=1` skips all plugins. AgentsFence is not running and can't warn you from inside Hermes; `agentsfence doctor` does.
- **Plugins Hermes skips or disables.** The fail-closed loader only runs if Hermes loads it. If Hermes disables AgentsFence (for example when `hermes update` cannot install its declared dependency) or skips it, no hook runs; `agentsfence doctor` reports "Protection off".
- **Hermes processes started before setup.** Hermes loads plugins only at startup, so a chat, gateway or backend that was already running when you enabled AgentsFence stays unprotected until it restarts. `agentsfence doctor` and setup name such processes by PID, but only processes on this machine running as your user.

- **Content manipulation inside authorized actions.** If sending to John is authorized, an injection can change what the email says, including pasting sensitive data into it. AgentsFence decides *whether* an action may happen and *to whom*, not *what it contains*.
- **Generated text.** AgentsFence asks the model to omit instructions found in retrieved content from ordinary summaries, but this is best-effort guidance. It does not deterministically sanitize the model's answer or a summary saved through an authorized write.
- **Side effects inside authorized execution.** A shell command or `execute_code` run that you authorized can do anything the OS allows. Use Hermes' container backends (docker, modal, …) or an OS or network sandbox for tasks that need execution.
- **Server-side effects of "read" tools.** An MCP tool named `get_…` that also mutates state is classified as READ. Tools that take an `action` argument are covered when the action isn't a declared read; a tool whose *name* is the only signal isn't. Map such tools explicitly in `config.yaml`.
- **Exfiltration through allowed reads** that don't look unusual. A short query string or a sequence of innocent-looking requests to an attacker's domain can leak small amounts of data. If a task doesn't need the open web, set `allowed_external_domains` or deny `web.*`.
- **Actions outside Hermes tool dispatch**, such as gateway-level features, other plugins that call APIs directly, or tools that bypass `pre_tool_call`.
- **Approval fatigue.** ASK_USER is only as good as the human answering it. `--yolo`, `approvals.mode: off`, allowlists and cron `approve` mode auto-approve ASK_USER (never BLOCK). Fallback policies and `strict_yolo: true` turn those questions into BLOCK; allowlist detection uses Hermes' exact `plugin_rule:` key.
- **Unparsed code under a domain bound.** An explicit only-domain bound checks URLs and the network programs listed above. Code AgentsFence does not parse (`python script.py`, `execute_code`, `bash -c …`) can open other connections; it is governed by execution authority, not by the domain bound. A persistent terminal session may also carry proxy settings from an earlier command, and `~/.curlrc` or `~/.wgetrc` can configure a proxy that the command line does not show.
- **Compiler errors in the permissive direction for READ.** Recognized explicit only-domain restrictions are enforced independently of the draft. Other read restrictions (for example "only read this one file") still depend on supported interpretation or explicit policy constraints.
- **Model and language coverage.** Paraphrases, multilingual messages and unfamiliar tools depend on the compiler model's interpretation. The deterministic prohibition floor, the span negation check and source-role heuristics recognize English only. In other languages, prohibitions and negations ("n'envoyez pas", "no borres nada") depend entirely on the compiler model's reading, with no deterministic backstop. These heuristics are additional defenses, not semantic verification.
- **Unmarked adversarial text inside the user's own message.** If you paste an attacker's text inline without quoting it, AgentsFence treats it as your words. Validation still requires a verified span and literal, role-bound recipients inside it, but those can come from pasted text.

## Hardening recommendations

```yaml
# ~/.hermes/agentsfence/config.yaml
evaluation:
  unauthorized: {UNKNOWN: BLOCK, EXECUTION: BLOCK}
  trust_inferred_reads: false      # unmapped "get_*" tools must be mapped explicitly
  missing_policy: block
  strict_yolo: true
guards:
  exfil_url: {max_query_chars: 100}
```

- Map every MCP tool you depend on in `tools:`, with `recipient_args`, `domain_args` and `path_args`.
- Select a local model through Hermes if task text must stay on your machine.
- Run execution-heavy tasks in a Hermes container backend.
- Review `agentsfence audit` after sensitive tasks.

## Data handling

- **Policy records**, under `~/.hermes/agentsfence/`, mode 0600: with persistence enabled, the `unresolved` queue stores each full owner instruction after quoted material is stripped, before compilation. Failed and superseded updates remain across restarts until a successful latest revision covers them and clears the saved queue. Records also retain the compiler's summary and interpretation for `/fence`. `/new` and non-shutdown session boundaries delete the record. Expiry blocks authority immediately (default 12 hours); expired files are pruned at store startup or replaced on a new owner turn, without a background deletion timer.
- **Audit log**, stored locally at mode 0600: requests are hashed rather than saved as a separate full-request field, and the unresolved queue is not copied to audit. Compiler summaries and argument values other than leaf recipients, URLs, paths and actions are hashed/redacted. Compilation audit rows do retain interpretation statements and selected instruction quotes, which may include an entire short request and sensitive text. Clearing the queue or deleting a policy does not clear these audit rows; audit rotation and retention apply separately.
- **Sent over the network**: your instruction text (with quoted material stripped) and the tool catalogue, sent to the configured compiler endpoint on every owner turn, and at most once more on invalid output. Nothing else, and no telemetry.
