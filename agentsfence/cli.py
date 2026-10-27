"""``agentsfence`` command-line tool.

    agentsfence setup                                  guided: install, protect, settings, test
    agentsfence install                                register with Hermes; upgrade protected profiles
    agentsfence protect --all-profiles [--include-new] (or --profile NAME / --profiles A B)
    agentsfence unprotect --profile NAME
    agentsfence settings [--compiler inherit | --model MODEL] [--compile-budget SECONDS]
    agentsfence test --profile NAME [--scenario KEY] [--all] [--no-live]
    agentsfence doctor [--profile NAME | --all-profiles] [--probe-compiler] [--jobs]
    agentsfence audit [--profile NAME] [--session ID] [-n 20]
    agentsfence classify TOOL_NAME ['{"arg": 1}']
    agentsfence uninstall [--purge]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import hermes_home, load_settings
from .profiles import available_profiles, resolve_profile
from .risk import RiskClassifier


def _print_report(report: dict[str, Any]) -> None:
    for line in report.get("lines") or []:
        print(line)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _confirm(question: str, default: bool = False) -> bool:
    answer = input(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not answer else answer in {"y", "yes"}


def _upkeep(protect_new: bool = True) -> None:
    from .lifecycle import sweep

    for line in sweep(protect_new=protect_new):
        print(line, file=sys.stderr)


# ---------------------------------------------------------------------------
# Lifecycle commands
# ---------------------------------------------------------------------------


def _cmd_install(args: argparse.Namespace) -> int:
    from .lifecycle import install

    _print_report(install(build=False if args.no_build else None))
    return 0


def _profile_names(args: argparse.Namespace) -> tuple[list[str], bool]:
    names = list(getattr(args, "profiles", None) or [])
    if getattr(args, "profile", None):
        names.insert(0, args.profile)
    return names, bool(getattr(args, "all_profiles", False))


def _cmd_protect(args: argparse.Namespace) -> int:
    from .lifecycle import protect

    names, every = _profile_names(args)
    _print_report(protect(names, all_profiles=every, include_new=args.include_new, build=False if args.no_build else None))
    return 0


def _cmd_unprotect(args: argparse.Namespace) -> int:
    from .lifecycle import unprotect

    names, every = _profile_names(args)
    _print_report(unprotect(names, all_profiles=every, build=False if args.no_build else None))
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    from .lifecycle import uninstall

    if not args.yes:
        if not _interactive():
            raise ValueError("Uninstall removes AgentsFence from every profile. Re-run with --yes to confirm.")
        if not _confirm("Remove AgentsFence from every Hermes profile?" + (" Also delete its audit logs and policies?" if args.purge else "")):
            print("Nothing was changed.")
            return 1
    _print_report(uninstall(purge=args.purge, build=False if args.no_build else None))
    return 0


def _cmd_settings(args: argparse.Namespace) -> int:
    from .lifecycle import update_settings

    change = {"mode": args.compiler, "model": args.model, "provider": args.provider, "compile_budget": args.compile_budget,
              "strict_yolo": args.strict_yolo, "retention_days": args.audit_retention_days}
    if any(v is not None for v in change.values()):
        _print_report(update_settings(**change, profile=args.profile))
        return 0
    homes = [resolve_profile(args.profile)] if args.profile else list(available_profiles().values())
    for home in homes:
        _show_settings(home)
    return 0


def _show_settings(home: Path) -> None:
    from .approvals import effective_approval_mode
    from .plugin import compile_budget
    from .profiles import compiler_route, is_protected, profile_name, read_config

    settings = load_settings(hermes_dir=home)
    cfg = read_config(home)
    route = compiler_route(cfg)
    budget = compile_budget(settings)
    print(f"{profile_name(home)}: {'protected' if is_protected(home) else 'not protected'}")
    print(f"  Compiler: {settings.compiler.mode} — {route.get('model') or 'unavailable (read-only fallback)'}"
          + (f" via {route['provider']}" if route.get("provider") not in (None, '', 'auto') else ""))
    print(f"  Compile budget: {settings.compiler.timeout_seconds:g}s (Hermes hook timeout "
          f"{(cfg.get('plugins') or {}).get('hook_callback_timeout', 30)}s; effective {budget['budget_seconds']:g}s)")
    print(f"  Monitoring: approvals {effective_approval_mode(home, cfg)}; strict_yolo {settings.evaluation.strict_yolo}; "
          f"audit {'on' if settings.audit.enabled else 'off'}, kept {settings.audit.retention_days} days after rotation")


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------


def _cmd_setup(args: argparse.Namespace) -> int:
    from .lifecycle import install, protect, update_settings
    from .profiles import model_choices

    interactive = _interactive() and not args.yes
    print(f"AgentsFence {__version__} setup")
    report = install(build=False if args.no_build else None)
    _print_report(report)
    profiles = available_profiles()
    names, every = _profile_names(args)
    if not names and not every:
        if interactive:
            print("\nHermes profiles: " + ", ".join(profiles))
            answer = input("Protect which profiles? (comma-separated, or all) [all]: ").strip()
            every = not answer or answer.lower() == "all"
            names = [] if every else [n.strip() for n in answer.split(",") if n.strip()]
            unknown = [n for n in names if n not in profiles]
            if unknown:
                raise ValueError(f"Unknown Hermes profile(s): {', '.join(unknown)}. Available: {', '.join(profiles)}. "
                                 "Nothing was protected.")
        else:
            every = True
            print("Protecting every profile (no terminal to ask; pass --profile NAME to choose).")
    model, provider = args.model, args.provider
    inherit = False
    if model is None and args.compiler is None and interactive:
        first = profiles[names[0]] if names else profiles["default"]
        choices = model_choices(first)
        print("\nWhich model should compile your requests into permissions?")
        for index, choice in enumerate(choices, 1):
            print(f"  {index}. {choice['label']}")
        print("  m. Another model (name it)")
        answer = input("Compiler [1]: ").strip() or "1"
        if answer.lower() == "m":
            model = input("Model identifier: ").strip()
            provider = input("Hermes provider [auto]: ").strip() or "auto"
            if not model:
                raise ValueError("Name the compiler model, or choose 1 for the profile's default model.")
        elif answer.isdigit() and 1 <= int(answer) <= len(choices):
            choice = choices[int(answer) - 1]
            if choice["id"] == "inherit":
                inherit = True
            else:
                model, provider = choice["model"], choice["provider"]
        else:
            raise ValueError(f"Choose 1-{len(choices)} or m. Nothing was changed after install.")
    else:
        inherit = args.compiler == "inherit"
    # Install already ran the capability check in this command.
    if model:
        _print_report(update_settings(model=model, provider=provider or "auto", preflight=False))
    elif inherit:
        _print_report(update_settings(mode="inherit", preflight=False))
    include_new = args.include_new
    if include_new is None:
        include_new = every if not interactive else _confirm("Protect new Hermes profiles automatically?", default=every)
    print()
    _print_report(protect(names, all_profiles=every, include_new=include_new, build=False if args.no_build else None,
                          preflight=False))
    target = names[0] if names else "default"
    print(f"\nNext: `agentsfence test --profile {target}` runs the six scenarios in that profile "
          "(a free model when available; otherwise it shows the projected cost first).")
    if interactive and _confirm(f"Run it now for {target}?"):
        return _run_test(resolve_profile(target), argparse.Namespace(scenario=[], all=False, model=None, provider=None,
                                                                     no_live=False, yes=False, json=False))
    return 0


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def _cmd_test(args: argparse.Namespace) -> int:
    return _run_test(hermes_home(), args)


def _run_test(home: Path, args: argparse.Namespace) -> int:
    if getattr(args, "compiler_eval", False):
        return _run_compiler_eval(home, args)
    from .testkit import harness
    from .testkit.live import run_test
    from .testkit.scenarios import select

    chosen = select(args.scenario or None, include_probes=args.all)
    options = {"live": not args.no_live, "model": args.model, "provider": args.provider, "all_probes": args.all,
               "selected": args.scenario}
    print("Running the scenarios in this profile (a live chat-model run first, unless --no-live).", file=sys.stderr)
    result = run_test(home, chosen, accept_cost=args.yes, **options)
    if result.get("needs_confirmation"):
        live = result["live"]
        estimate = (f"projected cost ${live['cost']:.4f}" if live.get("cost") is not None else "unknown cost")
        question = f"The live run uses {live['model']} with {estimate}. Continue?"
        if _interactive() and _confirm(question):
            result = run_test(home, chosen, accept_cost=True, **{**options, "model": live["model"],
                                                                  "provider": live.get("provider")})
        else:
            print(f"Live run skipped: {estimate} not accepted (pass --yes to accept).",
                  file=sys.stderr)
            result = run_test(home, chosen, **{**options, "live": False})
            result["live"] = {"skipped": f"{estimate} not accepted"}
    print(json.dumps(result, indent=2) if args.json else harness.format_report(result))
    return 0 if result.get("ok") else 1


def _run_compiler_eval(home: Path, args: argparse.Namespace) -> int:
    from .host_probe import run_probe
    from .testkit.compiler_eval import format_report, load_cases, run_offline

    if args.scenario or args.all or args.model or args.provider:
        raise ValueError("--compiler-eval uses the complete corpus and this profile's routed compiler model.")
    if args.no_live:
        result = run_offline(home)
    else:
        turns = sum(len(case["messages"]) for case in load_cases())
        warning = (f"Compiler evaluation makes live, potentially billable model calls on this profile's compiler route "
                   f"({turns} owner turns; retries and compiler.stages can add calls). No tools are executed.")
        print(warning, file=sys.stderr)
        if not args.yes and not (_interactive() and _confirm("Run the live compiler evaluation?")):
            print("Live compiler evaluation skipped. Use --yes to accept model calls, or --no-live for recorded fixtures.",
                  file=sys.stderr)
            return 2
        result = run_probe(home, "compiler-eval")
    print(json.dumps(result, indent=2) if args.json else format_report(result))
    return 0 if result.get("ok") else 1


# ---------------------------------------------------------------------------
# Doctor, audit, classify
# ---------------------------------------------------------------------------

_CAPABILITIES: dict[str, Any] = {}


def _capability_check() -> dict[str, str]:
    if "result" not in _CAPABILITIES:
        from .lifecycle import run_preflight

        _CAPABILITIES["result"] = run_preflight()
    result = _CAPABILITIES["result"]
    if result.get("ok"):
        optional = result.get("optional_missing") or []
        return {"status": "ok", "message": "Hermes provides every capability AgentsFence relies on"
                + (f" (without optional: {', '.join(optional)})" if optional else "") + "."}
    return {"status": "problem", "message": result.get("error") or "The capability check failed."}


def _cmd_doctor(args: argparse.Namespace) -> int:
    from .diagnostics import format_status, onboarding_steps, snapshot
    from .host_client import status as host_status
    from .host_probe import run_probe
    from .profiles import read_config

    home = hermes_home()
    enabled = (read_config(home).get("plugins") or {}).get("enabled") or []
    host = host_status(home) if "agentsfence" in enabled else None
    probe = run_probe(home) if args.probe_compiler else None
    data = snapshot(session=args.session, host=host)
    data["checks"]["capabilities"] = _capability_check()
    if data["checks"]["capabilities"]["status"] == "problem" and data["overall"] == "ok":
        data["overall"] = "unverified"
    if probe is not None:
        data["probe"] = probe
    jobs = run_probe(home, "jobs") if args.jobs and data["scheduled_jobs"] else None
    if jobs is not None:
        data["jobs_dry_run"] = jobs
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(format_status(data))
        if probe:
            state = ("OK" if probe.get("ok") else "FAILED") + (f" in {probe['seconds']}s" if probe.get("seconds") is not None else "")
            print(f"Compiler probe: {state} with {probe.get('model') or 'the policy model'}"
                  + (f" — {probe['error']}" if probe.get("error") else ""))
            if probe.get("warning"):
                print(probe["warning"])
        if jobs is not None:
            from .testkit.jobs import format_jobs

            print("\n" + format_jobs(jobs, data["cron_mode"]))
        if data["overall"] == "ok":
            command, purpose = onboarding_steps(data["profile"])[3]
            print(f"Next: {command}\n  ({purpose})")
    return 0 if data["overall"] == "ok" and (probe is None or probe["ok"]) else 1


def _test_event(row: dict[str, Any]) -> bool:
    return str(row.get("session_id") or "").startswith("agentsfence-test-") or bool((row.get("details") or {}).get("test_run"))


def _cmd_audit(args: argparse.Namespace) -> int:
    from .diagnostics import audit_rows
    from .render import local_time

    rows = audit_rows(hermes_home(), session=args.session, limit=max(args.n, 500) if args.exclude_tests or args.only_tests else args.n)
    rows = [row for row in rows if not args.exclude_tests or not _test_event(row)]
    rows = [row for row in rows if not args.only_tests or _test_event(row)]
    for row in rows[-args.n:] if args.n else []:
        if args.json:
            print(json.dumps(row))
            continue
        recorded = row.get("details")
        details: dict[str, Any] = recorded if isinstance(recorded, dict) else {}
        source = details.get("provenance")
        provenance: dict[str, Any] = source if isinstance(source, dict) else {}
        timing = " ".join(f"{k}={v}" for k, v in (("model", provenance.get("compiler_model")), ("seconds", provenance.get("seconds")),
                                                   ("wait_seconds", details.get("wait_seconds"))) if v is not None)
        print(f"{local_time(row.get('timestamp'))}  session={row.get('session_id', '—')}  {row.get('event', ''):<16} "
              f"{row.get('tool', ''):<28} {row.get('decision', ''):<9} {row.get('rule_id', '')}" + (f"  {timing}" if timing else ""))
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    s = load_settings()
    clf = RiskClassifier(s.risk_config)
    a = json.loads(args.args or "{}")
    p = clf.classify(args.tool, a)
    t = clf.extract_targets(p, a)
    exclude = None if args.verbose else {"recipient_args", "domain_args", "path_args"}
    print(json.dumps({**p.model_dump(mode="json", exclude=exclude), "targets": t.__dict__}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _profile_args(parser: argparse.ArgumentParser, *, many: bool) -> None:
    parser.add_argument("-p", "--profile", default=argparse.SUPPRESS, help="Hermes profile")
    parser.add_argument("--all-profiles", action="store_true", default=argparse.SUPPRESS, help="every current profile")
    if many:
        parser.add_argument("--profiles", nargs="+", help="several profiles")


def _include_new(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--include-new", dest="include_new", action="store_true", default=None,
                       help="also protect Hermes profiles created later")
    group.add_argument("--no-include-new", dest="include_new", action="store_false")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agentsfence", description="Task-scoped authorization for Hermes Agent")
    ap.add_argument("--version", action="version", version=f"agentsfence {__version__}")
    ap.add_argument("-p", "--profile", help="Hermes profile (uses its .env, config and audit)")
    ap.add_argument("--all-profiles", action="store_true", help="every current profile")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="guided setup: install, choose profiles and compiler, protect, test")
    _profile_args(s, many=True)
    s.add_argument("--compiler", choices=["inherit"], help="use each profile's default model to compile requests")
    s.add_argument("--model", help="a dedicated compiler model, routed and authenticated by Hermes")
    s.add_argument("--provider", help="Hermes provider for --model (default: auto)")
    _include_new(s)
    s.add_argument("--yes", action="store_true", help="accept defaults without asking")
    s.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    s.set_defaults(fn=_cmd_setup)

    i = sub.add_parser("install", help="check Hermes can run AgentsFence, register it, upgrade protected profiles")
    i.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    i.set_defaults(fn=_cmd_install)

    pr = sub.add_parser("protect", help="enable AgentsFence in profiles")
    _profile_args(pr, many=True)
    _include_new(pr)
    pr.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    pr.set_defaults(fn=_cmd_protect)

    un = sub.add_parser("unprotect", help="disable AgentsFence in profiles and remove its files there")
    _profile_args(un, many=True)
    un.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    un.set_defaults(fn=_cmd_unprotect)

    st = sub.add_parser("settings", help="show or change compiler and monitoring settings")
    st.add_argument("-p", "--profile", default=argparse.SUPPRESS, help="change or show only this profile (an override)")
    compiler = st.add_mutually_exclusive_group()
    compiler.add_argument("--compiler", choices=["inherit"], help="compile with each profile's default model")
    compiler.add_argument("--model", help="compile with this dedicated model")
    st.add_argument("--provider", help="Hermes provider for --model (default: auto)")
    st.add_argument("--compile-budget", type=float, metavar="SECONDS",
                    help="time a compile may take; raises Hermes' plugins.hook_callback_timeout to match")
    strict = st.add_mutually_exclusive_group()
    strict.add_argument("--strict-yolo", dest="strict_yolo", action="store_true", default=None,
                        help="in --yolo/approvals off, block what would be asked instead of auto-approving")
    strict.add_argument("--no-strict-yolo", dest="strict_yolo", action="store_false")
    st.add_argument("--audit-retention-days", type=int, metavar="DAYS", help="how long rotated audit logs are kept")
    st.set_defaults(fn=_cmd_settings)

    t = sub.add_parser("test", help="run the six scenarios in a profile, with a free or cheapest chat model")
    t.add_argument("-p", "--profile", default=argparse.SUPPRESS)
    t.add_argument("--scenario", action="append", default=[], help="run only this scenario (repeatable)")
    t.add_argument("--all", action="store_true", help="also run the injection probes")
    t.add_argument("--model", help="chat model for the live run (default: a free one, else the cheapest)")
    t.add_argument("--provider", help="Hermes provider for --model")
    t.add_argument("--no-live", action="store_true", help="skip the live chat-model run")
    t.add_argument("--compiler-eval", action="store_true", help="measure compiler authority, latency and call counts against the semantic corpus")
    t.add_argument("--yes", action="store_true", help="accept the projected cost of a paid model")
    t.add_argument("--require-authorization", action="store_true", help="require verified authorization (also the default)")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=_cmd_test)

    d = sub.add_parser("doctor", help="check enforcement, compiler health and Hermes capabilities")
    _profile_args(d, many=False)
    d.add_argument("--json", action="store_true")
    d.add_argument("--session", help="validate this session's policy")
    d.add_argument("--probe-compiler", action="store_true", help="make one real (possibly billable) compiler call through Hermes")
    d.add_argument("--jobs", action="store_true", help="dry-run each scheduled job's prompt through the policy compiler")
    d.set_defaults(fn=_cmd_doctor)

    a = sub.add_parser("audit", help="show recent audit events")
    _profile_args(a, many=False)
    a.add_argument("-n", type=int, default=20)
    a.add_argument("--json", action="store_true")
    a.add_argument("--session", help="show evidence from this session only")
    filters = a.add_mutually_exclusive_group()
    filters.add_argument("--exclude-tests", action="store_true")
    filters.add_argument("--only-tests", action="store_true")
    a.set_defaults(fn=_cmd_audit)

    u = sub.add_parser("uninstall", help="remove AgentsFence from every profile")
    u.add_argument("--purge", action="store_true", help="also delete audit logs and policies")
    u.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    u.add_argument("--no-build", action="store_true", help=argparse.SUPPRESS)
    u.set_defaults(fn=_cmd_uninstall)

    cl = sub.add_parser("classify", help="show how a tool call is classified")
    cl.add_argument("tool")
    cl.add_argument("args", nargs="?")
    cl.add_argument("--verbose", action="store_true", help="also show which argument names are inspected")
    cl.set_defaults(fn=_cmd_classify)
    return ap


#: Commands that act on the whole Hermes root rather than one profile at a time.
_ROOT_COMMANDS = {"setup", "install", "protect", "unprotect", "uninstall", "settings"}
_PER_PROFILE = {"doctor", "audit", "test", "classify"}


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    _CAPABILITIES.clear()  # one capability check per invocation, shared by --all-profiles
    try:
        from .lifecycle import LifecycleError
    except ImportError:  # pragma: no cover
        LifecycleError = ValueError  # type: ignore[misc,assignment]
    try:
        if ns.cmd in _ROOT_COMMANDS:
            code = int(ns.fn(ns))
            if code == 0 and ns.cmd != "uninstall":
                _upkeep()
            return code
        if ns.all_profiles and ns.cmd not in {"doctor", "audit"}:
            raise ValueError("--all-profiles works with doctor and audit; run test once per profile.")
        _upkeep()
        homes = list(available_profiles().values()) if ns.all_profiles else [resolve_profile(ns.profile)]
        original = dict(os.environ)
        code = 0
        from .config import profile_environment

        try:
            for home in homes:
                os.environ.clear()
                os.environ.update(original)
                env = profile_environment(home)
                env["HERMES_HOME"] = str(home)
                os.environ.update(env)
                if ns.all_profiles and not getattr(ns, "json", False):
                    print(f"\nProfile: {home.name if home.parent.name == 'profiles' else 'default'}")
                try:
                    code = max(code, int(ns.fn(ns)))
                except Exception as exc:  # one unreadable profile must not hide the others
                    if not ns.all_profiles:
                        raise
                    detail = str(exc) if isinstance(exc, (ValueError, OSError)) else f"{type(exc).__name__}: {exc}"
                    print(f"AgentsFence: {detail}", file=sys.stderr)
                    code = 2
        finally:
            os.environ.clear()
            os.environ.update(original)
        return code
    except (LifecycleError, ValueError, OSError, IndexError) as exc:
        print(f"AgentsFence: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nAgentsFence: interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
