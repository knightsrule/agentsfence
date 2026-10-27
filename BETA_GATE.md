# Finite beta gate

Status: **CLI and managed rollback diagnostic validation passed; Desktop and final clean-candidate validation pending**. Historical 0.2.0a7 results do not certify this branch.

## Required environments

These two managed environments are the gate. `HERMES_API.md`, `AGENTS.md` and the CI matrix use the same revisions. Tip of main is an early warning job and does not gate release; Windows tests cover process liveness without signals.

| Hermes environment | Fresh install | Upgrade from 0.2.0a7 | Doctor + real compiler | Scenario test + real compiler | Failed upgrade rollback | Desktop approvals |
|---|---|---|---|---|---|---|
| Managed install at `801a9022a742562a3c4578c0d8dd12cfd393fc47` (main) | diagnostic PASS | diagnostic PASS | diagnostic PASS | diagnostic PASS | diagnostic PASS | pending |
| Managed install at `64f2be353fd8bcf6badbe22f6da8b83398b25665` (rc) | diagnostic PASS | diagnostic PASS | diagnostic PASS | diagnostic PASS | diagnostic PASS | pending |

Diagnostic runs passed on both environments. Re-record the final clean candidate before release. Desktop has not been observed.

Use Hermes' real managed installer and `hermes pm install`, disposable homes and synthetic data. Test default and additional profiles; legacy rules settings migrate to inherit, old loaders and pins upgrade, the Desktop companion is recreated, and a pending update is reported without starting Hermes. Unsupported stable/venv installs must receive the `hermes update` remedy before profile changes.

## Accepted PM lifecycle under test

For 0.2.0a8, fresh `install` registers disabled surfaces without a PM build. First `protect` enables the requested profiles and installs their dependency. Protect/upgrade publishes guarded files before PM build, verifies all protected profiles and commits. Failed builds or verification restore prior files and rebuild from prior declarations; incomplete recovery retains its journal/backups and fails closed. Temporary tool blocking during the switch is accepted.

The managed fresh row must demonstrate disabled registration followed by successful protection/build. The upgrade and failed-upgrade rollback rows validate the guarded publication order and restoration. Persistent machine-only dependencies and build-before-activation staging are deferred enhancements, not release requirements. Desktop approval and real-compiler checks remain required.

## Authorization coverage matrix

The decision suites remain the enforcement gate: `test_evaluator`, `test_hooks`, `test_attack_scenarios`, `test_review_regressions`, `test_call_limits`, `test_scope_narrowing`, `test_beta_authorization`.

| Case | Required outcome |
|---|---|
| Source to output saves and configured aliases | Only the requested output gains authority; memory/skill writes remain separate. |
| Only-domain limits, prohibitions, truncation or compiler failure | Restrictions extracted from the full instruction survive every compiler and fallback. |
| Follow-up additions and explicit narrowing | Supported additions preserve earlier authority; narrowing bounds earlier and runtime grants. |
| Overbroad/omitted grants and retry | Every draft is hardened; one retry shares the deadline; omitted consequential authority is never restored. |
| Competing plugins, nested/delegated calls and approval bypass | BLOCK wins; exact-action grants require human approval; fallback questions fail closed. |
| Missing package or registration failure | A discovered loader blocks every tool; skipped/disabled plugins are reported by doctor. |

## Final recorded validation

```bash
.venv/bin/python scripts/beta_validate.py --dry-run
.venv/bin/python scripts/beta_validate.py --provider openrouter --model <model> --key-env OPENROUTER_API_KEY
```

The runner builds the candidate wheel, serves it through `UV_FIND_LINKS`, and installs both pinned Hermes revisions in disposable homes. Each revision first verifies disabled `install` registration without the dependency, then runs fresh setup and an upgrade over 0.2.0a7, verifies actual installed modules and pins, runs `doctor --all-profiles --probe-compiler --json` and `test --profile default --all --no-live --require-authorization --json`, and checks pending-update protection. A fallback or unverified authorization is FAIL.

The rollback row deliberately declares an unresolvable dependency pin and verifies that every previously protected profile remains on its previous version or fail closed with a repair message. Unit failure injection additionally covers profile writes, crashes, incomplete journals and failed rollback rebuilds.

The Desktop row is manual: start `hermes serve`, verify one BLOCK, approve one ASK_USER and deny another. Record exact session IDs, approval request IDs, audit grants and whether each mock tool executed. The gateway queue test alone does not prove the HTTP/Desktop dialog path. Record these rows as PASS only after observing them.

Keep exact commands, timestamps, revisions, wheel hash, outputs and failures under `release-evidence/<version>/`. Attach historical records to their GitHub releases before removing the only retained copy. Both automatic and manual publication enforce recorded evidence from 0.3.0a1 onward. Unobserved rollback/Desktop rows fail the release check. No known authorization escape may remain for beta.

### Attach observed manual rows

Keep the first run’s workspace (`--keep`) for the rollback and Desktop checks. Supply JSON with the exact `agentsfence_version`, `agentsfence_commit`, and `wheel_sha256` from that run’s summary. Under `environments`, key each entry by its full pinned Hermes revision. Each `failed_upgrade_rollback` or `desktop_approvals` row needs `verdict` (`PASS` or `FAIL`), `timestamp`, `commands`, and `observations` (profile/session/request IDs, grants and mock-tool outcomes). Then attach it without rebuilding:

```bash
.venv/bin/python scripts/beta_validate.py --record-manual /path/to/observations.json --out release-evidence/0.3.0a1
```

The recorder rejects a different candidate or wheel. Missing observations remain FAIL; this command never substitutes unit or gateway tests for the Desktop observation.
