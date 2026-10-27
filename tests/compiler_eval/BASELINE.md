# Compiler evaluation baseline

Measured on the unmodified compiler at `fc575081d73d663b24e2d66e0d65c5d445fb94b7`, using an isolated `git archive HEAD` checkout. The shared working branch was never switched.

All 80 cases used recorded PolicyDraft outputs through `AgentsFence.on_pre_llm_call` and `AgentsFence.check`; no provider, network, tool execution, or real Hermes process was involved. Each category has eight distinct cases. The multilingual cases cover eight languages.

Command: `.venv/bin/python -m pytest tests/compiler_eval --tb=no` (using the project venv against the frozen checkout). The measured pytest duration was **1.35 seconds**.

| Category | Calls | Over-grants | Under-grants | Verdict mismatches |
| --- | ---: | ---: | ---: | ---: |
| conditional | 8 | 8 | 0 | 8 |
| followup | 8 | 1 | 0 | 2 |
| informational | 8 | 0 | 0 | 0 |
| multilingual | 8 | 0 | 8 | 8 |
| negation | 8 | 0 | 0 | 1 |
| paraphrase | 8 | 0 | 8 | 8 |
| positive_authorized | 8 | 0 | 0 | 0 |
| quoted_material | 8 | 0 | 0 | 0 |
| source_destination | 8 | 0 | 0 | 0 |
| unseen_tool | 8 | 0 | 8 | 8 |
| **Total** | **80** | **9** | **24** | **35** |

An over-grant is an expected BLOCK/ASK_USER that became ALLOW. An under-grant is an expected ALLOW that became ASK_USER/BLOCK. Verdict mismatches also include safety-direction ASK_USER/BLOCK differences; these do not count as over- or under-grants.

The original run had 46 passing tests (including corpus integrity) and 35 failures. Those 35 case failures were marked `xfail(strict=True)` for the legacy run (46 passed, 35 xfailed in 1.39 seconds). Each migrated case retains its original `baseline_output` and, where applicable, its one-line `baseline_xfail` reason. The active markers have been removed because all intended verdicts now pass; the baseline above stays frozen.

After the intent migration, all 80 calls match their expected verdicts: zero over-grants and zero under-grants in every category. Each of the 88 owner-turn outputs parses and completes without fallback. The recorded corpus and CLI tests pass in under three seconds. The runtime CLI ships the identical corpus in `agentsfence/testkit/compiler_cases.yaml`; the corpus integrity test prevents the two copies from diverging.

The source/destination cases include separate correct-destination controls, a sender incorrectly offered as a recipient, an input incorrectly offered as an output, and prevention of cross-combined recipients. Follow-up cases exercise revoke, narrow, replace, and reference. New tool families use exact live-catalogue names absent from defaults.yaml.

This is a deterministic structural/compiler regression corpus. It measures behavior for the recorded model readings; it is not an accuracy estimate for a live provider and zero over-grants is not a safety guarantee.

Unmarked original corpus SHA-256: `99e869a113ba7744bed907515b5a54da05df55a5158d77cb99e2f3553b7d22f4`.
