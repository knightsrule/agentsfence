"""Release decisions must fail closed and preserve published versions and tags."""

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

pytest.importorskip("tomllib")  # The release job uses Python 3.11, unlike the package.
helper = Path(__file__).resolve().parents[1] / ".github/scripts/prepare_release.py"
if not helper.exists():
    pytest.skip("Release workflow tooling is only present in a Git checkout, not the sdist", allow_module_level=True)
spec = importlib.util.spec_from_file_location("prepare_release", helper)
assert spec is not None and spec.loader is not None
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "agentsfence").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0a5"\n')
    (tmp_path / "agentsfence/__init__.py").write_text('__version__ = "0.2.0a5"\n')
    (tmp_path / "plugin.yaml").write_text('version: "0.2.0a5"\n')
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run([
        "git", "-C", str(tmp_path), "-c", "user.name=Test", "-c", "user.email=test@example.com",
        "commit", "--quiet", "-m", "Initial version",
    ], check=True)
    sha = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    return tmp_path, sha


def test_unpublished_and_retry_tag(repo, monkeypatch):
    root, sha = repo
    monkeypatch.setattr(release, "published", lambda _: False)
    assert release.plan(root, sha) == {"release": "true", "tag": "v0.2.0a5", "create_tag": "true"}
    subprocess.run(["git", "-C", str(root), "tag", "v0.2.0a5"], check=True)
    assert release.plan(root, sha)["create_tag"] == "false"
    with pytest.raises(ValueError, match="another commit"):
        release.plan(root, "0" * 40)


def test_published_version_skips_later_docs_commit(repo, monkeypatch):
    root, sha = repo
    subprocess.run(["git", "-C", str(root), "tag", "v0.2.0a5"], check=True)
    monkeypatch.setattr(release, "published", lambda _: True)
    assert release.plan(root, "0" * 40)["release"] == "false"


def test_inconsistent_version_fails(repo):
    root, _ = repo
    (root / "plugin.yaml").write_text('version: "0.2.0a4"\n')
    with pytest.raises(ValueError, match="must agree"):
        release.package_version(root)


@pytest.mark.parametrize("error,absent", [(404, True), (403, False), (500, False)])
def test_only_pypi_404_means_unpublished(monkeypatch, error, absent):
    def unavailable(*args, **kwargs):
        raise HTTPError("https://pypi.org", error, "Unavailable", {}, None)

    monkeypatch.setattr(release, "urlopen", unavailable)
    if absent:
        assert not release.published("0.2.0a5")
    else:
        with pytest.raises(HTTPError):
            release.published("0.2.0a5")


def test_pypi_network_error_stops_release(monkeypatch):
    def unavailable(*args, **kwargs):
        raise URLError("Timed out")

    monkeypatch.setattr(release, "urlopen", unavailable)
    with pytest.raises(URLError):
        release.published("0.2.0a5")


@pytest.mark.parametrize("wheel_yanked", [False, True])
def test_pypi_requires_both_unyanked_distributions(monkeypatch, wheel_yanked):
    response = {"urls": [
        {"packagetype": "bdist_wheel", "yanked": wheel_yanked}, {"packagetype": "sdist", "yanked": False},
    ]}
    monkeypatch.setattr(release, "urlopen", lambda *args, **kwargs: io.BytesIO(json.dumps(response).encode()))
    if wheel_yanked:
        with pytest.raises(ValueError, match="unyanked wheel and sdist"):
            release.published("0.2.0a5")
    else:
        assert release.published("0.2.0a5")


# --- the recorded beta gate ------------------------------------------------------

_GATE = """# Finite beta gate

## Required environments

| Hermes environment | Fresh install | Upgrade from 0.2.0a7 | Doctor + real compiler | Quick replay + real compiler |
|---|---|---|---|---|
| Managed install at `801a9022a742562a3c4578c0d8dd12cfd393fc47` (main) | pending | pending | pending | pending |
| Managed install at `64f2be353fd8bcf6badbe22f6da8b83398b25665` (rc) | pending | pending | pending | pending |

## Authorization coverage matrix
"""
_REFS = ("801a9022a742562a3c4578c0d8dd12cfd393fc47", "64f2be353fd8bcf6badbe22f6da8b83398b25665")


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _commit(root, message):
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _evidence(root, version, commit, **overrides):
    rows = {"fresh_install": "PASS", "upgrade_from_0.2.0a7": "PASS", "doctor_real_compiler": "PASS",
            "scenario_test_real_compiler": "PASS"}
    managed_rows = {**rows, "pending_update_protection": "PASS", "failed_upgrade_rollback": "PASS", "desktop_approvals": "PASS"}
    data = {"version": version, "agentsfence_version": version, "agentsfence_commit": commit, "dirty": False,
            "compiler": {"mode": "inherit", "provider": "p", "model": "m"},
            "environments": {ref: {"name": ref, "verdict": "PASS", "rows": dict(managed_rows if len(ref) == 40 else rows)}
                             for ref in _REFS}}
    data.update(overrides)
    path = root / "release-evidence" / version / "summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return data


@pytest.fixture
def beta_repo(repo, monkeypatch):
    root, _ = repo
    for name, text in (("pyproject.toml", '[project]\nversion = "0.3.0b1"\n'),
                       ("agentsfence/__init__.py", '__version__ = "0.3.0b1"\n'),
                       ("plugin.yaml", 'version: "0.3.0b1"\n'), ("BETA_GATE.md", _GATE)):
        (root / name).write_text(text)
    recorded = _commit(root, "Beta candidate")
    monkeypatch.setattr(release, "published", lambda _: False)
    return root, recorded


def test_alpha_needs_no_recorded_gate(repo, monkeypatch):
    root, sha = repo
    monkeypatch.setattr(release, "published", lambda _: False)
    assert release.plan(root, sha)["release"] == "true"


@pytest.mark.parametrize("version,needed", [("0.2.0a7", False), ("0.2.0a8", False), ("0.3.0a1", True), ("0.3.0b1", True), ("0.3.0rc1", True), ("0.3.0", True)])
def test_beta_and_later_need_the_recorded_gate(version, needed):
    assert release.requires_evidence(version) is needed


def test_beta_without_evidence_is_refused(beta_repo):
    root, recorded = beta_repo
    with pytest.raises(ValueError, match="needs the recorded beta gate"):
        release.plan(root, recorded)


def test_complete_evidence_from_the_candidate_commit_releases(beta_repo):
    root, recorded = beta_repo
    _evidence(root, "0.3.0b1", recorded)
    (root / "CHANGELOG.md").write_text("## 0.3.0b1 — 2026-10-01\n")  # dating the changelog is allowed afterwards
    release_sha = _commit(root, "Record the beta gate")
    assert release.plan(root, release_sha) == {"release": "true", "tag": "v0.3.0b1", "create_tag": "true"}


@pytest.mark.parametrize("change,message", [
    (lambda d: d["environments"]["801a9022a742562a3c4578c0d8dd12cfd393fc47"]["rows"].update(scenario_test_real_compiler="FAIL"), "failed row"),
    (lambda d: d["environments"]["801a9022a742562a3c4578c0d8dd12cfd393fc47"].update(verdict="FAIL"), "failed row"),
    (lambda d: d["environments"].pop("64f2be353fd8bcf6badbe22f6da8b83398b25665"), "no result for"),
    (lambda d: d.update(compiler={"mode": "rules"}), "real compiler"),
    (lambda d: d.update(dirty=True), "uncommitted"),
    (lambda d: d.update(version="0.3.0b0", agentsfence_version="0.3.0b0"), "records version"),
    (lambda d: d.update(agentsfence_commit="0" * 40), "not an ancestor"),
])
def test_incomplete_or_foreign_evidence_is_refused(beta_repo, change, message):
    root, recorded = beta_repo
    data = _evidence(root, "0.3.0b1", recorded)
    change(data)
    (root / "release-evidence/0.3.0b1/summary.json").write_text(json.dumps(data))
    release_sha = _commit(root, "Record the beta gate")
    with pytest.raises(ValueError, match=message):
        release.plan(root, release_sha)


def test_code_changed_after_the_recorded_gate_is_refused(beta_repo):
    root, recorded = beta_repo
    _evidence(root, "0.3.0b1", recorded)
    (root / "agentsfence/evaluator.py").write_text("# changed after validation\n")
    release_sha = _commit(root, "Record the gate and change code")
    with pytest.raises(ValueError, match="changed after the beta gate was recorded"):
        release.plan(root, release_sha)


def _runner():
    path = Path(__file__).resolve().parents[1] / "scripts/beta_validate.py"
    spec = importlib.util.spec_from_file_location("beta_validate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def test_runner_covers_exactly_the_gate_rows():
    runner = _runner()
    rows = runner.environments()
    assert {row.ref for row in rows} == release.gate_refs(Path(__file__).resolve().parents[1])
    assert [row.name for row in rows if row.managed] == ["main", "rc"] and all(row.python for row in rows)


@pytest.mark.parametrize("verdict,releases", [("PASS", True), ("FAIL", False)])
def test_runner_evidence_is_what_the_release_check_reads(beta_repo, verdict, releases):
    root, recorded = beta_repo
    runner = _runner()
    base = {"agentsfence_version": "0.3.0b1", "agentsfence_commit": recorded, "dirty": False, "wheel_sha256": "0" * 64,
            "compiler": {"mode": "inherit", "provider": "p", "model": "m"}}
    phase = {"verdict": "PASS"}
    paths = {p: {"install": dict(phase), "doctor": dict(phase), "test": {"verdict": verdict},
                 "pending_update": dict(phase), "rollback": dict(phase), "desktop": dict(phase)} for p in ("fresh", "upgrade")}
    records = [{"environment": ref[:7], "hermes_ref": ref, "verdict": verdict,
                "rows": runner.gate_rows(paths, managed=len(ref) == 40)} for ref in _REFS]
    runner.write_evidence(root / "release-evidence/0.3.0b1", "0.3.0b1", records, base)
    assert "| **" + verdict + "** |" in (root / "release-evidence/0.3.0b1/SUMMARY.md").read_text()
    release_sha = _commit(root, "Record the beta gate")
    if releases:
        assert release.plan(root, release_sha)["release"] == "true"
    else:
        with pytest.raises(ValueError, match="failed row"):
            release.plan(root, release_sha)


def test_runner_reads_one_json_result_per_profile():
    runner = _runner()
    text = 'noise {"profile": "default", "checks": {"load": {"status": "ok"}}}\n{"profile": "extra"} trailing {bad'
    assert [obj["profile"] for obj in runner._json_objects(text)] == ["default", "extra"]


def _check_evidence_cli(root, sha):
    import os
    import sys as _sys

    return subprocess.run([_sys.executable, str(helper), "--check-evidence"], cwd=root, capture_output=True, text=True,
                          env={**os.environ, "GITHUB_SHA": sha})


def test_manual_publication_runs_the_evidence_check_before_building():
    import yaml

    workflow = yaml.safe_load((helper.parents[1] / "workflows/publish-pypi.yml").read_text())
    runs = [step.get("run", "") for step in workflow["jobs"]["build"]["steps"]]
    check = next(i for i, run in enumerate(runs) if "prepare_release.py --check-evidence" in run)
    build = next(i for i, run in enumerate(runs) if "python -m build" in run)
    assert check < build


def test_evidence_cli_refuses_a_beta_without_its_record(beta_repo):
    root, recorded = beta_repo
    result = _check_evidence_cli(root, recorded)
    assert result.returncode != 0 and "needs the recorded beta gate" in result.stderr


def test_evidence_cli_needs_no_record_for_an_alpha(repo):
    root, sha = repo
    result = _check_evidence_cli(root, sha)
    assert result.returncode == 0 and "not required for 0.2.0a5" in result.stdout


def test_evidence_cli_accepts_a_recorded_beta(beta_repo):
    root, recorded = beta_repo
    _evidence(root, "0.3.0b1", recorded)
    sha = _commit(root, "Record the beta gate")
    result = _check_evidence_cli(root, sha)
    assert result.returncode == 0 and "verified for 0.3.0b1" in result.stdout


@pytest.mark.parametrize("drop,managed_ref", [
    ("upgrade_from_0.2.0a7", False), ("doctor_real_compiler", False), ("scenario_test_real_compiler", False),
    ("fresh_install", False), ("pending_update_protection", True), ("failed_upgrade_rollback", True), ("desktop_approvals", True),
])
def test_evidence_missing_a_required_row_is_refused(beta_repo, drop, managed_ref):
    root, recorded = beta_repo
    data = _evidence(root, "0.3.0b1", recorded)
    ref = _REFS[int(managed_ref)]
    data["environments"][ref]["rows"].pop(drop)
    (root / "release-evidence/0.3.0b1/summary.json").write_text(json.dumps(data))
    sha = _commit(root, "Record partial evidence")
    with pytest.raises(ValueError, match="lacks required rows"):
        release.plan(root, sha)


def test_runner_rows_are_exactly_what_the_release_check_requires():
    runner = _runner()
    phase = {"verdict": "PASS"}
    paths = {p: {"install": dict(phase), "doctor": dict(phase), "test": dict(phase), "pending_update": dict(phase), "rollback": dict(phase), "desktop": dict(phase)}
             for p in ("fresh", "upgrade")}
    for managed in (False, True):
        assert release.missing_rows(runner.gate_rows(paths, managed=managed), managed=managed) == []


def _runner_args(tmp_path, **overrides):
    import argparse

    values = dict(key_env=None, provider="p", model="m", compiler="inherit", compile_budget=None, cache_key="t",
                  hermes_repo=tmp_path / "hermes-repo", wheel=None)
    values.update(overrides)
    return argparse.Namespace(**values)


def test_runner_never_runs_a_command_from_inside_the_checkout(tmp_path):
    runner = _runner()
    rec = runner.Recorder([], dry_run=False)
    phase = runner.new_phase()
    with pytest.raises(RuntimeError, match="inside the checkout"):
        rec.run(phase, ["true"], env={}, cwd=runner.ROOT)
    with pytest.raises(RuntimeError, match="inside the checkout"):
        rec.run(phase, ["true"], env={}, cwd=runner.ROOT / "agentsfence")
    assert rec.run(phase, ["true"], env={}, cwd=tmp_path)[0] == 0


def test_runner_redacts_the_operator_home_from_evidence():
    runner = _runner()
    rec = runner.Recorder(["s3cret"], dry_run=False)
    text = rec.redact(f"git -C {Path.home()}/.hermes/hermes-agent show s3cret")
    assert str(Path.home()) not in text and "s3cret" not in text
    assert "~/.hermes/hermes-agent" in text


def test_runner_runs_the_old_release_isolated_from_any_checkout(tmp_path):
    """Review finding: `python -m agentsfence` from the checkout imported 0.2.0a7 instead of 0.2.0a7."""
    runner = _runner()
    venv = runner.environments()[0]
    ws = runner.Workspace(tmp_path / "ws", venv, _runner_args(tmp_path), tmp_path / "wheels", tmp_path / "shared")
    phases = runner.run_path(ws, runner.Recorder([], dry_run=True), "9.9.9", "upgrade")
    commands = [step["command"] for step in phases["install"]["steps"]]
    baseline = next(c for c in commands if "agentsfence==0.2.0a7" in c and " setup" in c)
    assert "uvx" in baseline and "--all-profiles" in baseline


@pytest.mark.parametrize("enabled,installed", [(True, None), (False, "9.9.9")])
def test_fresh_registration_must_stay_disabled_without_installing_dependency(tmp_path, monkeypatch, enabled, installed):
    runner = _runner()
    ws = runner.Workspace(tmp_path / "ws", runner.environments()[0], _runner_args(tmp_path),
                          tmp_path / "wheels", tmp_path / "shared")
    monkeypatch.setattr(ws, "install_hermes", lambda rec, phase: True)
    monkeypatch.setattr(ws, "write_profiles", lambda: ["default"])
    monkeypatch.setattr(ws, "installed_version", lambda: installed)
    ws.hermes_home.mkdir(parents=True)
    (ws.hermes_home / "config.yaml").write_text("plugins:\n  enabled: " + ("[agentsfence]" if enabled else "[]"))
    commands = []
    rec = runner.Recorder([], dry_run=False)

    def run(phase, command, **kwargs):
        commands.append(command)
        return 0, ""

    monkeypatch.setattr(rec, "run", run)
    phases = runner.run_path(ws, rec, "9.9.9", "fresh")
    assert phases["install"]["verdict"] == "FAIL"
    assert len(commands) == 1 and commands[0][-1] == "install"


@pytest.mark.parametrize("failing", ["agentsfence==0.2.0a7", "agentsfence setup"])
def test_a_failed_baseline_step_fails_the_upgrade_row(tmp_path, monkeypatch, failing):
    runner = _runner()
    venv = runner.environments()[0]
    ws = runner.Workspace(tmp_path / "ws", venv, _runner_args(tmp_path), tmp_path / "wheels", tmp_path / "shared")
    monkeypatch.setattr(ws, "install_hermes", lambda rec, phase: True)
    monkeypatch.setattr(ws, "write_profiles", lambda: ["default"])
    ran = []

    def run(phase, command, *, env, cwd=None, timeout=1800):
        ran.append(" ".join(command))
        return (1 if failing in " ".join(command) else 0), ""

    rec = runner.Recorder([], dry_run=False)
    monkeypatch.setattr(rec, "run", run)
    phases = runner.run_path(ws, rec, "9.9.9", "upgrade")
    assert phases["install"]["verdict"] == "FAIL" and "baseline failed" in " ".join(phases["install"]["notes"])
    assert not any("agentsfence==9.9.9" in command for command in ran)  # the candidate never ran over a broken baseline


def test_a_baseline_not_written_by_the_old_release_fails_the_upgrade_row(tmp_path, monkeypatch):
    runner = _runner()
    venv = runner.environments()[0]
    ws = runner.Workspace(tmp_path / "ws", venv, _runner_args(tmp_path), tmp_path / "wheels", tmp_path / "shared")
    monkeypatch.setattr(ws, "install_hermes", lambda rec, phase: True)
    monkeypatch.setattr(ws, "write_profiles", lambda: ["default"])
    monkeypatch.setattr(ws, "installed_version", lambda: "0.2.0a7")
    monkeypatch.setattr(ws, "pins", lambda: {"default": "9.9.9", "extra": "9.9.9"})  # the candidate wrote them
    rec = runner.Recorder([], dry_run=False)
    monkeypatch.setattr(rec, "run", lambda phase, command, *, env, cwd=None, timeout=1800: (0, ""))
    phases = runner.run_path(ws, rec, "9.9.9", "upgrade")
    assert phases["install"]["verdict"] == "FAIL" and "baseline is not 0.2.0a7" in " ".join(phases["install"]["notes"])


def test_manual_observations_attach_only_to_the_exact_candidate(tmp_path):
    runner = _runner()
    base = {"agentsfence_version": "0.3.0a1", "agentsfence_commit": "a" * 40,
            "wheel_sha256": "b" * 64, "dirty": False, "compiler": {"mode": "inherit"}}
    record = {"environment": "main", "hermes_ref": _REFS[0], "rows": {"desktop_approvals": "FAIL"}, "verdict": "FAIL"}
    out = tmp_path / "evidence"
    runner.write_evidence(out, "0.3.0a1", [record], base)
    manual = {**base, "environments": {_REFS[0]: {"desktop_approvals": {
        "verdict": "PASS", "timestamp": "2026-09-28T00:00:00Z", "commands": ["hermes serve"],
        "observations": [{"request": "req1", "choice": "once", "executed": True},
                         {"request": "req2", "choice": "deny", "executed": False}]}}}}
    source = tmp_path / "manual.json"
    source.write_text(json.dumps(manual))
    runner.record_manual(out, source)
    saved = json.loads((out / "summary.json").read_text())
    assert saved["environments"][_REFS[0]]["rows"]["desktop_approvals"] == "PASS"
    assert (out / "manual-observations.json").is_file()
    manual["wheel_sha256"] = "c" * 64
    source.write_text(json.dumps(manual))
    with pytest.raises(ValueError, match="wheel_sha256"):
        runner.record_manual(out, source)


def test_manual_pass_without_observations_is_refused(tmp_path):
    runner = _runner()
    base = {"agentsfence_version": "0.3.0a1", "agentsfence_commit": "a" * 40, "wheel_sha256": "b" * 64, "dirty": False, "compiler": {"mode": "inherit"}}
    out = tmp_path / "evidence"
    runner.write_evidence(out, "0.3.0a1", [{"environment": "main", "hermes_ref": _REFS[0],
                          "rows": {"desktop_approvals": "FAIL"}, "verdict": "FAIL"}], base)
    source = tmp_path / "manual.json"
    source.write_text(json.dumps({**base, "environments": {_REFS[0]: {"desktop_approvals": {"verdict": "PASS"}}}}))
    with pytest.raises(ValueError, match="needs verdict"):
        runner.record_manual(out, source)
