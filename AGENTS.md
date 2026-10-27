# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

AgentsFence is a Hermes Agent plugin that compiles a user's request into a task-scoped authorization policy (`pre_llm_call`) and enforces it before every tool call (`pre_tool_call`). Read `ARCHITECTURE.md` and `HERMES_API.md` before changing enforcement code.

## Commands

```bash
.venv/bin/pytest                      # full suite; includes real-Hermes integration when Hermes is installed
AGENTSFENCE_HERMES_PYTHON=<hermes venv python> .venv/bin/pytest tests/test_hermes_integration.py  # a specific Hermes version
.venv/bin/ruff check . && .venv/bin/mypy
.venv/bin/agentsfence test --profile default --all --no-live --require-authorization  # disposable configured profile only
```

## Invariants: do not break

- `AgentsFence.on_pre_tool_call` must return `{"action": "block", ...}` on any internal exception. Hermes treats a raising hook as "no objection".
- The compiler only sees `user_message` after `split_instruction()`; tool output, history and subagent goals never authorize. Tests: `test_policy_cannot_be_changed_by_tool_output`, `test_subagent_inherits_parent_policy_and_budget`.
- The compiler model's reading is the trust boundary. Structural validation cannot verify meaning; heuristics only restrict. Interpretation is display/audit only. Tests: `test_interpretation_never_changes_evaluator_verdicts`, `test_attack_fixture_is_valid_intent_json`; semantic acceptance is measured by `tests/compiler_eval/`, where zero over-grants is a threshold, not a guarantee.
- Never restore omitted consequential grants with deterministic request patterns. Retry once only for unparseable output within the original budget; omissions follow approval/blocking. Tests: `test_retry_after_invalid_output`, `test_failure_falls_back_read_only`.
- The test-only read compiler and first-compile fallback grant READ only and retain full-instruction prohibitions and only-domain bounds after truncation or failure. Tests: `test_rules_compiler_never_grants_a_send`, `test_trailing_prohibition_survives_truncation`, `test_explicit_domain_narrows_even_when_compiler_fails_or_omits_it`.
- Each grant binds only its own literal recipient/destination targets inside a verified instruction span. Source/context never authorize; file saves never imply memory/skill writes, including aliases. Distinct grants cannot cross-combine target dimensions. Explicit only-domain bounds precede grants. Tests: `test_intent_alternatives_keep_target_dimensions_together`, `test_browsing_domain_does_not_widen_named_email_recipient`, `test_failed_path_narrowing_does_not_authorize_a_new_destination`.
- Every owner turn amends behind a revision barrier; earlier permissions persist unless revoked/narrowed/replaced. Narrowing is intersection/minimum only, references resolve within prior targets, and counters persist. Failed amendments suspend consequential authority before runtime grants. Tests: `test_every_owner_turn_reaches_amend_and_later_success_clears_suspension`, `test_failed_owner_amend_suspends_consequences_but_reads_flow`, `test_runtime_grant_cannot_bypass_suspension_or_prohibition`, `test_stale_result_cannot_restore_authority_and_counters_survive`.
- All tool calls, reads included, wait for pending revisions outside `store.locked()`; install only the latest live revision. Owner messages stay queued until a successful compile interprets them, so superseded or failed revisions never drop a revocation. Drop/expiry wakes waiters with BLOCK. Tests: `test_superseded_revocation_is_interpreted_by_the_next_revision`, `test_failed_revocation_is_interpreted_by_the_next_successful_revision`, `test_pending_revocation_waits_and_worker_can_install_outside_wait_lock`, `test_pending_reads_wait_and_timeout_requires_confirmation`, `test_drop_or_expiry_cancels_wait_and_rejects_worker`.
- Call limits on path-bound writes and deletes count distinct files; limits on every other class count calls. Tests: `test_rewriting_or_patching_the_authorized_file_is_not_a_new_use`, `test_a_second_distinct_file_still_exceeds_the_limit`, `test_send_limits_still_count_every_call`.
- Never start Hermes while it has update work pending (`hermes_env.pending_work`), or while a managed install's check cannot confirm it has none (`UNVERIFIED`): the start itself runs that work. `AGENTSFENCE_HERMES_PYTHON` selects an interpreter but never makes a managed environment unmanaged. Never install into an environment Hermes' package manager owns except through `hermes pm install`, and declare a `python_dependencies` pin only for a published release. Real-Hermes tests set `HERMES_DISABLE_LAZY_INSTALLS=1` and skip rather than let Hermes rebuild the developer's install.
- User prohibitions are checked before grants in the evaluator. Test: `test_runtime_grant_cannot_bypass_suspension_or_prohibition`.
- Evaluation and reservation happen under `store.locked()`.
- No network calls on the evaluation path. No telemetry.
- `register()` registers the enforcement `pre_tool_call` hook before anything optional; optional and diagnostic steps may fail but never remove or bypass enforcement. It records an explicit outcome (`enforcing` / `recovery_block`); returning is not proof of enforcement.
- `agentsfence/failsafe.py` stays standard-library only: it is copied into setup-written loaders and must run when the package is missing.
- Tests never start a real Hermes from the developer's machine: the autouse fixture points `AGENTSFENCE_HERMES` at a nonexistent path, and real-Hermes tests use `AGENTSFENCE_HERMES_PYTHON` pointing at a throwaway install.
- Beta validation covers two managed environments in `BETA_GATE.md`: pinned main `801a9022a742562a3c4578c0d8dd12cfd393fc47` and RC `64f2be353fd8bcf6badbe22f6da8b83398b25665`. Preflight validates required host capabilities before writes; CI also checks tip of main non-blocking and Windows runtime cleanup. Test stubs must use real Hermes signatures.

## Layout

`agentsfence/` package: `models`, `config`, `risk`, `compiler`, `guards`, `evaluator`, `policy_store`, `audit`, `plugin`, `render`, `cli`, `testkit/`, plus operator surfaces `profiles`, `diagnostics`, `desktop_api`, `host_probe`, `approvals`, `lifecycle`, `preflight` (see `ARCHITECTURE.md`). The default tool-risk mapping is in `agentsfence/policies/defaults.yaml`. The root `plugin.yaml` and `__init__.py` make the repo installable with `hermes plugins install`.

## Issue tracking

This repo uses `bd` (beads) locally: `bd ready`, `bd show <id>`, `bd close <id>`.

## Release automation

- A push to `main` with an unpublished version is a release decision. `.github/workflows/ci.yml` waits for every Python, Windows and real-Hermes job, then creates the normalized version tag and explicitly dispatches `publish-pypi.yml`. Published versions are skipped; tags are never moved.
- Keep `pyproject.toml`, `agentsfence/__init__.py` and `plugin.yaml` versions consistent and date the changelog before merging a release. Read `RELEASING.md` for setup and retries.
- Preserve OIDC trusted publishing, the tag-only `pypi` environment and the publication workflow's tag/main checks. Do not introduce PyPI tokens, PATs, application dependencies or cross-repo triggers for this automation.
- The website deploys independently with Vercel and checks its install pins against PyPI. Verify the plugin release before merging website pins.
- Changes to release decisions need coverage in `tests/test_release_automation.py`; the helper uses Python 3.11 on GitHub.
