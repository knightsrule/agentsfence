#!/usr/bin/env python3
"""Beta-gate validation: disposable Hermes installs, the real user commands, one evidence record.

Each environment row of BETA_GATE.md is a managed Hermes install (Hermes' own
`scripts/install.sh` at the pinned revision, so every install runs the real
`hermes pm install`) and runs twice in its own throwaway workspace:

* fresh: install Hermes, then the candidate's `agentsfence setup --all-profiles`;
* upgrade: install Hermes and AgentsFence 0.2.0a7 as that release documented, then
  the candidate's setup over it (which must migrate its settings and pins).

After each path it runs `agentsfence doctor --all-profiles --probe-compiler --json` and
`agentsfence test --profile default --all --no-live --json` (the six scenarios and the
injection probes with the real compiler), and checks that a pending update is reported
without starting Hermes.

The candidate is the wheel built from this checkout. It is served from a local find-links
directory (`UV_FIND_LINKS`, which `hermes pm` forwards to uv), so every install resolves it the
way a published release resolves. Nothing touches the developer's own Hermes, shell files or
uv tool directory: each workspace has its own HOME and HERMES_HOME.

A fallback or unverified compile is a FAIL for the doctor and test rows.
Results go to release-evidence/<version>/<env>.json plus summary.json and SUMMARY.md; the
release job refuses a beta or later version without a complete PASS record (see
.github/scripts/prepare_release.py).

Run it from the checkout's dev environment:

    .venv/bin/python scripts/beta_validate.py --dry-run
    .venv/bin/python scripts/beta_validate.py --env main --provider openrouter \\
        --model <model> --key-env OPENROUTER_API_KEY
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentsfence.failsafe import _SECRET  # noqa: E402

UPGRADE_FROM = "0.2.0a7"
PASS, FAIL = "PASS", "FAIL"
PHASES = ("fresh", "upgrade", "pending_update", "doctor", "test")
#: Environment variables a workspace inherits; everything else (HOME, HERMES_*, UV_*, VIRTUAL_ENV) is replaced.
_INHERITED = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
              "REQUESTS_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")


@dataclass(frozen=True)
class Environment:
    name: str
    ref: str
    python: str
    managed: bool


def environments() -> list[Environment]:
    """BETA_GATE.md's rows (the single source), with each row's Python from the CI hermes matrix."""
    import yaml

    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    pythons = {row["ref"]: str(row["python"]) for row in ci["jobs"]["hermes"]["strategy"]["matrix"]["include"]}
    table = (ROOT / "BETA_GATE.md").read_text(encoding="utf-8").split("## Required environments", 1)[1].split("\n## ", 1)[0]
    found: list[Environment] = []
    for line in table.splitlines():
        if m := re.match(r"\|\s*Managed install at `([0-9a-f]{40})`\s*\(([\w.-]+)\)\s*\|", line):
            found.append(Environment(m.group(2), m.group(1), pythons[m.group(1)], managed=True))
    return found


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


class Recorder:
    """Runs commands and records each one, redacted, into a phase."""

    def __init__(self, secrets: list[str], *, dry_run: bool) -> None:
        self.secrets = [s for s in secrets if s]
        self.dry_run = dry_run

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "[redacted]")
        # Evidence is committed: keep the operator's home directory out of it.
        text = text.replace(str(Path.home()), "~")
        return _SECRET.sub("[redacted]", text)

    def run(self, phase: dict[str, Any], command: list[str], *, env: dict[str, str], cwd: Path | None = None,
            timeout: float = 1800) -> tuple[int | None, str]:
        shown = " ".join(shlex.quote(c) for c in command)
        where = (cwd or Path.cwd()).resolve()
        if where == ROOT or ROOT in where.parents:
            # `python -m agentsfence` there would import the checkout, not the package under test.
            raise RuntimeError(f"refusing to run {shown!r} from inside the checkout ({where})")
        if self.dry_run:
            print(f"    $ {self.redact(shown)}")
            phase["steps"].append({"command": self.redact(shown), "dry_run": True})
            return 0, ""
        started, began = now(), time.monotonic()
        try:
            proc = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL)
            code: int | None = proc.returncode
            output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        except subprocess.TimeoutExpired as exc:
            code, output = None, f"timed out after {timeout:.0f}s\n{_text(exc.stdout)}{_text(exc.stderr)}"
        except OSError as exc:
            code, output = None, f"could not run: {exc}"
        phase["steps"].append({"command": self.redact(shown), "started": started,
                               "seconds": round(time.monotonic() - began, 1), "exit": code,
                               "output": self.redact(output[-8000:])})
        return code, output


def _text(value: str | bytes | None) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")


def new_phase() -> dict[str, Any]:
    return {"verdict": None, "steps": [], "notes": []}


def settle(phase: dict[str, Any], ok: bool, note: str = "") -> bool:
    if note:
        phase["notes"].append(note)
    phase["verdict"] = PASS if ok and phase["verdict"] != FAIL else FAIL
    return bool(phase["verdict"] == PASS)


class Workspace:
    """One throwaway Hermes install with its own HOME and HERMES_HOME."""

    def __init__(self, root: Path, env_spec: Environment, args: argparse.Namespace, wheels: Path, shared: Path) -> None:
        self.root, self.spec, self.args = root, env_spec, args
        self.home = root / "home"
        self.hermes_home = root / "hermes-home"
        self.source = root / "hermes-agent"
        self.launcher: Path | None = None
        self.env = {k: v for k, v in os.environ.items() if k in _INHERITED}
        if args.key_env:
            self.env[args.key_env] = os.environ.get(args.key_env, "")
        self.env.update({
            "HOME": str(self.home), "HERMES_HOME": str(self.hermes_home), "UV_FIND_LINKS": str(wheels),
            # One cache per candidate build: every build carries the same version string, and uv
            # reuses a cached build of `agentsfence==<version>` from an earlier run otherwise.
            "UV_CACHE_DIR": str(shared / f"uv-cache-{args.cache_key}"), "UV_PYTHON_INSTALL_DIR": str(shared / "uv-python"),
            "UV_TOOL_DIR": str(root / "uv-tools"), "UV_TOOL_BIN_DIR": str(root / "uv-bin"), "CI": "1",
        })

    def run(self, rec: Recorder, phase: dict[str, Any], command: list[str], *, env: dict[str, str],
            timeout: float = 1800) -> tuple[int | None, str]:
        """Run from this workspace, never from the checkout."""
        self.root.mkdir(parents=True, exist_ok=True)
        return rec.run(phase, command, env=env, cwd=self.root, timeout=timeout)

    def with_launcher(self) -> dict[str, str]:
        env = dict(self.env)
        if self.launcher is not None:
            env["AGENTSFENCE_HERMES"] = str(self.launcher)
            env["PATH"] = f"{self.launcher.parent}{os.pathsep}{env.get('PATH', '')}"
        return env

    # -- Hermes --------------------------------------------------------------

    def install_hermes(self, rec: Recorder, phase: dict[str, Any]) -> bool:
        """Hermes' own installer at the pinned revision: a real managed install with `hermes pm`."""
        for d in (self.home, self.hermes_home):
            d.mkdir(parents=True, exist_ok=True)
        repo = str(self.args.hermes_repo)
        installer = self.root / "install.sh"
        code, _ = self.run(rec, phase, ["sh", "-c", f"git -C {shlex.quote(repo)} show {self.spec.ref}:scripts/install.sh "
                                              f"> {shlex.quote(str(installer))}"], env=self.env)
        code2, _ = self.run(rec, phase, ["bash", str(installer), "--commit", self.spec.ref, "--dir", str(self.source),
                                   "--hermes-home", str(self.hermes_home), "--non-interactive", "--skip-browser"],
                           env={**self.env, "HERMES_REPO_URL": repo}, timeout=3600)
        candidates = [self.source / ".hermes/bin/hermes", self.home / ".local/bin/hermes"]
        self.launcher = next((c for c in candidates if rec.dry_run or c.exists()), None)
        return code == 0 and code2 == 0 and self.launcher is not None

    def python(self) -> Path | None:
        """Hermes' interpreter, as AgentsFence itself finds it."""
        code = ("import os,sys; sys.path.insert(0, sys.argv[1]); from agentsfence import hermes_env; "
                "from pathlib import Path; i = hermes_env.detect(Path(os.environ['HERMES_HOME'])); print(i.python or '')")
        proc = subprocess.run([sys.executable, "-c", code, str(ROOT)], env=self.with_launcher(), capture_output=True, text=True)
        return Path(proc.stdout.strip()) if proc.stdout.strip() else None

    def write_profiles(self) -> list[str]:
        """The default profile and one additional profile, both with the configured chat model."""
        import yaml

        model = {"provider": self.args.provider or "auto", "default": self.args.model or "unset"}
        profiles = {"default": self.hermes_home, "extra": self.hermes_home / "profiles" / "extra"}
        for home in profiles.values():
            home.mkdir(parents=True, exist_ok=True)
            config = home / "config.yaml"
            data = (yaml.safe_load(config.read_text(encoding="utf-8")) if config.exists() else None) or {}
            data["model"] = {**(data.get("model") or {}), **model}
            config.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return list(profiles)

    # -- AgentsFence ----------------------------------------------------------

    def agentsfence(self, version: str, *args: str) -> list[str]:
        return ["uvx", "--from", f"agentsfence=={version}", "agentsfence", *args]

    def compiler_args(self) -> list[str]:
        return ["--compiler", "inherit"]

    def candidate_setup_args(self) -> list[str]:
        """The candidate's non-interactive setup: every profile, each profile's default model."""
        return ["--all-profiles", "--compiler", "inherit", "--include-new", "--yes"]

    def installed_version(self) -> str | None:
        python = self.python()
        if python is None or not python.exists():
            return None
        proc = subprocess.run([str(python), "-I", "-c", "import importlib.metadata as m; print(m.version('agentsfence'))"],
                              capture_output=True, text=True, env=self.env)
        return proc.stdout.strip() or None

    def runs_candidate(self, wheel: Path) -> list[str]:
        """Modules in Hermes' environment whose contents differ from the candidate wheel (RECORD hashes)."""
        import zipfile

        with zipfile.ZipFile(wheel) as archive:
            record = next(n for n in archive.namelist() if n.endswith(".dist-info/RECORD"))
            expected = {path: digest for path, digest, *_ in
                        (line.split(",") for line in archive.read(record).decode().splitlines() if line.count(",") >= 2)
                        if path.startswith("agentsfence/") and path.endswith(".py")}
        python = self.python()
        if python is None or not python.exists():
            return ["(Hermes' Python not found)"]
        code = ("import base64, hashlib, importlib.util, json, pathlib, sys\n"
                "root = pathlib.Path(importlib.util.find_spec('agentsfence').origin).parent.parent\n"
                "out = {}\n"
                "for p in json.loads(sys.argv[1]):\n"
                "    f = root / p\n"
                "    out[p] = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(f.read_bytes()).digest()).rstrip(b'=').decode() "
                "if f.exists() else None\n"
                "print(json.dumps(out))")
        proc = subprocess.run([str(python), "-I", "-c", code, json.dumps(sorted(expected))], capture_output=True, text=True,
                              env=self.env)
        try:
            actual = json.loads(proc.stdout)
        except ValueError:
            return [f"(could not read the installed package: {proc.stderr.strip()[-200:]})"]
        return sorted(p for p, digest in expected.items() if actual.get(p) != digest)

    def pins(self) -> dict[str, str | None]:
        """Each profile's declared plugin dependency (protect writes one only for a published release)."""
        found: dict[str, str | None] = {}
        for name, home in (("default", self.hermes_home), ("extra", self.hermes_home / "profiles" / "extra")):
            manifest = home / "plugins" / "agentsfence" / "plugin.yaml"
            text = manifest.read_text(encoding="utf-8") if manifest.exists() else ""
            m = re.search(r"agentsfence==([\w.]+)", text)
            found[name] = m.group(1) if m else None
        return found


def check_install(ws: Workspace, rec: Recorder, phase: dict[str, Any], version: str) -> bool:
    if rec.dry_run:
        return settle(phase, True)
    installed, pins = ws.installed_version(), ws.pins()
    phase["installed_version"], phase["pins"] = installed, pins
    ok = installed == version and all(pin == version for pin in pins.values())  # hermes pm builds from the declared pins
    differing = ws.runs_candidate(ws.args.wheel)
    phase["modules_differing_from_candidate"] = differing
    ok = ok and not differing  # the version string alone cannot tell two builds apart
    return settle(phase, ok, f"installed {installed}, pins {pins}, modules differing from the candidate: {len(differing)}")


def run_path(ws: Workspace, rec: Recorder, version: str, path: str) -> dict[str, Any]:
    """One install path (fresh or upgrade), then doctor and the scenario test in that workspace."""
    phases = {name: new_phase() for name in ("install", "doctor", "test", "pending_update")}
    install = phases["install"]
    if not settle(install, ws.install_hermes(rec, install), "Hermes installed" if not rec.dry_run else ""):
        return phases
    ws.write_profiles()
    env = ws.with_launcher()
    if path == "fresh":
        code, _ = ws.run(rec, install, ws.agentsfence(version, "install"), env=env)
        if code != 0:
            settle(install, False, f"disabled registration exited {code}")
            return phases
        if not rec.dry_run:
            import yaml

            enabled = {home.name: "agentsfence" in ((yaml.safe_load(config.read_text()) or {})
                       .get("plugins", {}).get("enabled") or [])
                       for home in (ws.hermes_home, ws.hermes_home / "profiles" / "extra")
                       if (config := home / "config.yaml").exists()}
            installed = ws.installed_version()
            install["disabled_registration"] = {"enabled": enabled, "installed_version": installed}
            if not settle(install, not any(enabled.values()) and installed is None,
                          "fresh install registered disabled surfaces without installing the dependency"):
                return phases
    if path == "upgrade":
        # The earlier release as its users installed it: from PyPI alone. With the candidate
        # visible, the old release's own setup would already upgrade itself.
        before = {k: v for k, v in env.items() if k != "UV_FIND_LINKS"}
        steps = [(ws.agentsfence(UPGRADE_FROM, "setup", "--all-profiles", *ws.compiler_args()), 1800),
                 ([str(ws.launcher), "pm", "install"], 3600)]
        for command, timeout in steps:
            code, _ = ws.run(rec, install, command, env=before, timeout=timeout)
            if code != 0:
                settle(install, False, f"preparing the {UPGRADE_FROM} baseline failed (exit {code}): {command[0]}")
                return phases
        if not rec.dry_run:
            # The baseline must be what the old release itself installs and writes: its package in
            # Hermes' environment and its dependency pin in every profile's manifest.
            installed, pins = ws.installed_version(), ws.pins()
            install["baseline"] = {"installed_version": installed, "pins": pins}
            if installed != UPGRADE_FROM or any(pin != UPGRADE_FROM for pin in pins.values()):
                settle(install, False, f"the {UPGRADE_FROM} baseline is not {UPGRADE_FROM}: installed {installed}, pins {pins}")
                return phases
    code, _ = ws.run(rec, install, ws.agentsfence(version, "setup", *ws.candidate_setup_args()), env=env, timeout=3600)
    settle(install, code == 0, "" if code == 0 else f"setup exited {code}")
    if ws.args.compile_budget and code == 0:
        code, _ = ws.run(rec, install, ws.agentsfence(version, "settings", "--compile-budget", str(ws.args.compile_budget)),
                         env=env)
        settle(install, code == 0, "" if code == 0 else f"settings exited {code}")
    check_install(ws, rec, install, version)
    pending_update_check(ws, rec, phases["pending_update"], version)

    doctor = phases["doctor"]
    code, out = ws.run(rec, doctor, ws.agentsfence(version, "doctor", "--all-profiles", "--probe-compiler", "--json"), env=env)
    settle(doctor, code == 0, "" if code == 0 else f"doctor exited {code}")
    if not rec.dry_run:
        for data in _json_objects(out):
            probe = data.get("probe") or {}
            doctor.setdefault("profiles", {})[data.get("profile")] = {
                "overall": data.get("overall"),
                "checks": {k: v.get("status") for k, v in (data.get("checks") or {}).items() if isinstance(v, dict)},
                "compiler_model": probe.get("model"), "fell_back": probe.get("fell_back"),
                "probe_ok": probe.get("ok"), "seconds": probe.get("seconds")}
            real = probe.get("ok") and not probe.get("fell_back") and probe.get("model") not in (None, "")
            settle(doctor, bool(real) and data.get("overall") == "ok",
                   f"{data.get('profile')}: overall {data.get('overall')}, compiler {probe.get('model')}")
        if not doctor.get("profiles"):
            settle(doctor, False, "doctor printed no JSON result")

    test = phases["test"]
    code, out = ws.run(rec, test, ws.agentsfence(version, "test", "--profile", "default", "--all", "--no-live", "--require-authorization", "--json"),
                       env=env)
    result = next(iter(_json_objects(out)), {}) if not rec.dry_run else {}
    if not rec.dry_run:
        test["result"] = {"containment_ok": result.get("containment_ok"), "authorization": result.get("authorization"),
                          "steps": [(s.get("key"), st.get("label"), st.get("verdict"), st.get("rule_id"))
                                    for s in result.get("scenarios", []) for st in s.get("steps", [])],
                          "models": sorted({str(s.get("compiler_model")) for s in result.get("scenarios", [])})}
    settle(test, code == 0 and (rec.dry_run or (result.get("ok") and result.get("authorization") == "verified")),
           "" if rec.dry_run else f"containment {result.get('containment_ok')}, authorization {result.get('authorization')}")
    return phases


def pending_update_check(ws: Workspace, rec: Recorder, phase: dict[str, Any], version: str) -> None:
    """A pending update is reported, and doctor does not start Hermes (which would run it)."""
    if rec.dry_run:
        ws.run(rec, phase, ["touch", "<hermes-home>/installs/<key>/source-completion-pending"], env=ws.env)
        ws.run(rec, phase, ws.agentsfence(version, "doctor", "--json"), env=ws.env)
        settle(phase, True)
        return
    code = ("import os,sys; sys.path.insert(0, sys.argv[1]); from agentsfence import hermes_env; from pathlib import Path; "
            "print(hermes_env.detect(Path(os.environ['HERMES_HOME'])).state_dir or '')")
    state = subprocess.run([sys.executable, "-c", code, str(ROOT)], env=ws.with_launcher(), capture_output=True, text=True).stdout.strip()
    if not state:
        settle(phase, False, "no install record to mark")
        return
    marker = Path(state) / "source-completion-pending"
    marker.write_text("beta gate\n", encoding="utf-8")
    try:
        _, out = ws.run(rec, phase, ws.agentsfence(version, "doctor", "--json"), env=ws.with_launcher())
        data = next(iter(_json_objects(out)), {})
        # Hermes would have completed (and removed) the marker had doctor started it.
        settle(phase, bool(data.get("pending_update")) and marker.exists(),
               f"pending_update {data.get('pending_update')!r}, marker kept: {marker.exists()}")
    finally:
        marker.unlink(missing_ok=True)


def _json_objects(text: str) -> list[dict[str, Any]]:
    """Top-level JSON objects printed one after another (doctor --all-profiles prints one per profile)."""
    decoder, found, i = json.JSONDecoder(), [], 0
    while (start := text.find("{", i)) != -1:
        try:
            obj, end = decoder.raw_decode(text, start)
        except ValueError:
            i = start + 1
            continue
        if isinstance(obj, dict):
            found.append(obj)
        i = end
    return found


def build_wheel(out: Path, rec: Recorder) -> tuple[Path | None, str]:
    phase = new_phase()
    rec.run(phase, ["uv", "build", "--wheel", "--out-dir", str(out), str(ROOT)], env=dict(os.environ), cwd=out)
    wheels = sorted(out.glob("agentsfence-*.whl"))
    if rec.dry_run or not wheels:
        return None, ""
    return wheels[-1], hashlib.sha256(wheels[-1].read_bytes()).hexdigest()


def package_version() -> str:
    import tomllib

    return str(tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])


def validate(spec: Environment, args: argparse.Namespace, *, version: str, wheels: Path, shared: Path,
             workdir: Path, rec: Recorder, base: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {**base, "environment": spec.name, "hermes_ref": spec.ref, "managed": spec.managed,
                              "python": spec.python, "started": now(), "paths": {}}
    try:
        record["hermes_commit"] = git("rev-parse", f"{spec.ref}^{{commit}}", cwd=args.hermes_repo)
    except (subprocess.CalledProcessError, OSError):
        record["hermes_commit"] = None
    for path in ("fresh", "upgrade"):
        print(f"  {spec.name}: {path}", flush=True)
        ws = Workspace(workdir / f"{spec.name}-{path}", spec, args, wheels, shared)
        record["paths"][path] = run_path(ws, rec, version, path)
    paths = record["paths"]
    record["rows"] = gate_rows(paths, managed=spec.managed)
    record["verdict"] = _all(record["rows"].values())
    record["finished"] = now()
    return record


def gate_rows(paths: dict[str, Any], *, managed: bool) -> dict[str, str]:
    """BETA_GATE.md's columns for one environment; .github/scripts/prepare_release.py requires every one."""
    rows = {
        "fresh_install": _all([paths["fresh"]["install"]["verdict"]]),
        "upgrade_from_" + UPGRADE_FROM: _all([paths["upgrade"]["install"]["verdict"]]),
        "doctor_real_compiler": _all(paths[p]["doctor"]["verdict"] for p in paths),
        "scenario_test_real_compiler": _all(paths[p]["test"]["verdict"] for p in paths),
    }
    if managed:
        rows["pending_update_protection"] = _all(paths[p].get("pending_update", {}).get("verdict") for p in paths)
        # Manual observations are never inferred from unit tests or a dry run.
        rows["failed_upgrade_rollback"] = _all(paths[p].get("rollback", {}).get("verdict") for p in paths)
        rows["desktop_approvals"] = _all(paths[p].get("desktop", {}).get("verdict") for p in paths)
    return rows


def _all(verdicts: Any) -> str:
    values = list(verdicts)
    return PASS if values and all(v == PASS for v in values) else FAIL


def write_evidence(out: Path, version: str, records: list[dict[str, Any]], base: dict[str, Any]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for record in records:
        (out / f"{record['environment']}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    summary_path = out / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    if any(summary.get(key) not in (None, base[key]) for key in
           ("agentsfence_commit", "agentsfence_version", "wheel_sha256", "compiler")):
        summary = {}  # evidence from another candidate, wheel or compiler never mixes with this run
    environments = dict(summary.get("environments") or {})
    for record in records:
        environments[record["hermes_ref"]] = {"name": record["environment"], "verdict": record["verdict"],
                                              "rows": record["rows"], "file": f"{record['environment']}.json"}
    summary = {**base, "version": version, "updated": now(), "environments": environments}
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [f"# Beta gate evidence: AgentsFence {version}", "",
             f"Commit `{base['agentsfence_commit']}`{' (dirty)' if base['dirty'] else ''}, wheel sha256 "
             f"`{base['wheel_sha256']}`, compiler {base['compiler']}. Updated {summary['updated']}.", "",
             "| Hermes environment | Fresh install | Upgrade from " + UPGRADE_FROM + " | Doctor + real compiler | "
             "Scenario test + real compiler | Pending-update protection | Failed upgrade rollback | Desktop approvals | Verdict |",
             "|---|---|---|---|---|---|---|---|---|"]
    for ref, row in sorted(environments.items(), key=lambda kv: kv[1]["name"]):
        r = row["rows"]
        lines.append(f"| {row['name']} (`{ref[:12]}`) | {r.get('fresh_install')} | {r.get('upgrade_from_' + UPGRADE_FROM)} | "
                     f"{r.get('doctor_real_compiler')} | {r.get('scenario_test_real_compiler')} | "
                     f"{r.get('pending_update_protection', 'n/a')} | {r.get('failed_upgrade_rollback', 'n/a')} | "
                     f"{r.get('desktop_approvals', 'n/a')} | **{row['verdict']}** |")
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def record_manual(out: Path, source: Path) -> None:
    """Attach observed rollback/Desktop results to this exact already-built candidate."""
    manual = json.loads(source.read_text(encoding="utf-8"))
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    for key in ("agentsfence_version", "agentsfence_commit", "wheel_sha256"):
        if not summary.get(key) or manual.get(key) != summary[key]:
            raise ValueError(f"Manual evidence {key} does not match the recorded candidate")
    records = []
    refs = summary["environments"]
    unknown = set(manual.get("environments") or {}) - set(refs)
    if unknown:
        raise ValueError(f"Unknown Hermes revision in manual evidence: {sorted(unknown)}")
    if not manual.get("environments"):
        raise ValueError("Manual evidence contains no observed environment")
    for ref, row in refs.items():
        record = json.loads((out / row["file"]).read_text(encoding="utf-8"))
        for name, observed in (manual["environments"].get(ref) or {}).items():
            if name not in {"failed_upgrade_rollback", "desktop_approvals"}:
                raise ValueError(f"Unknown manual row: {name}")
            if (observed.get("verdict") not in {PASS, FAIL} or not observed.get("timestamp")
                    or not observed.get("commands") or not observed.get("observations")):
                raise ValueError(f"{name} needs verdict, timestamp, commands and observations")
            record.setdefault("manual", {})[name] = observed
            record["rows"][name] = observed["verdict"]
        record["verdict"] = _all(record["rows"].values())
        records.append(record)
    base = {key: value for key, value in summary.items() if key not in {"version", "environments"}}
    write_evidence(out, summary["version"], records, base)
    (out / "manual-observations.json").write_text(json.dumps(manual, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--record-manual", type=Path, help="attach observed rollback/Desktop rows to --out without rebuilding")
    ap.add_argument("--env", action="append", help="environment name from BETA_GATE.md (repeatable); default: all")
    ap.add_argument("--dry-run", action="store_true", help="print the planned commands; install and record nothing")
    ap.add_argument("--hermes-repo", type=Path, default=Path.home() / ".hermes" / "hermes-agent",
                    help="a local hermes-agent clone containing every gated ref (read with git archive/show only)")
    ap.add_argument("--workdir", type=Path, help="where to create workspaces (default: a new temporary directory)")
    ap.add_argument("--keep", action="store_true", help="keep workspaces after the run")
    ap.add_argument("--provider", help="Hermes provider for the chat and compiler model")
    ap.add_argument("--model", help="model for the chat and compiler")
    ap.add_argument("--key-env", help="name of the environment variable holding the provider key (never recorded)")
    ap.add_argument("--compile-budget", type=float, metavar="SECONDS",
                    help="set with the candidate's `settings --compile-budget` after setup")
    ap.add_argument("--out", type=Path, help="evidence directory (default: release-evidence/<version>)")
    args = ap.parse_args(argv)
    if args.record_manual:
        try:
            record_manual(args.out or ROOT / "release-evidence" / package_version(), args.record_manual)
        except (OSError, ValueError, KeyError) as exc:
            ap.error(str(exc))
        return 0

    specs = environments()
    names = [s.name for s in specs]
    wanted = args.env or names
    if unknown := [n for n in wanted if n not in names]:
        ap.error(f"unknown environment {unknown}; choose from {names}")
    if not (args.provider and args.model) and not args.dry_run:
        ap.error("a real compiler needs --provider and --model (and usually --key-env)")
    if args.key_env and not os.environ.get(args.key_env) and not args.dry_run:
        ap.error(f"{args.key_env} is not set")
    for tool in ("git", "uv", "uvx"):
        if shutil.which(tool) is None:
            ap.error(f"{tool} is required")

    version = package_version()
    rec = Recorder([os.environ.get(args.key_env or "", "")], dry_run=args.dry_run)
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="agentsfence-beta-"))
    shared, wheels = workdir / "shared", workdir / "wheels"
    for d in (shared, wheels):
        d.mkdir(parents=True, exist_ok=True)
    print(f"AgentsFence {version}: workspaces in {workdir}", flush=True)
    for old_wheel in wheels.glob("agentsfence-*.whl"):
        old_wheel.unlink()
    wheel, digest = build_wheel(wheels, rec)
    if wheel is None and not args.dry_run:
        print("The candidate wheel could not be built.", file=sys.stderr)
        return 2
    args.wheel, args.cache_key = wheel, (digest[:16] or "dry-run")
    base = {"agentsfence_version": version, "agentsfence_commit": git("rev-parse", "HEAD"),
            "dirty": bool(git("status", "--porcelain", "--", ".", ":!release-evidence")), "wheel_sha256": digest,
            "compiler": {"mode": "inherit", "provider": args.provider, "model": args.model,
                         "compile_budget": args.compile_budget},
            "runner": "scripts/beta_validate.py", "platform": sys.platform}
    records = []
    for spec in (s for s in specs if s.name in wanted):
        print(f"== {spec.name} ({spec.ref})", flush=True)
        records.append(validate(spec, args, version=version, wheels=wheels, shared=shared, workdir=workdir, rec=rec, base=base))
    if args.dry_run:
        if args.workdir is None:
            shutil.rmtree(workdir, ignore_errors=True)
        return 0
    out = args.out or ROOT / "release-evidence" / version
    write_evidence(out, version, records, base)
    for record in records:
        print(f"{record['environment']}: {record['verdict']} {record['rows']}")
    print(f"Evidence: {out}")
    if not args.keep and args.workdir is None:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if all(r["verdict"] == PASS for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
