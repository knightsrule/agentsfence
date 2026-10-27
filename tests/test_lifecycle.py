"""Lifecycle transactions restore previous profiles on failure or retain fail-closed recovery evidence.

Hermes steps (``build_environment``, ``verify_loads``, ``run_preflight``) are substituted,
so each failure can be injected exactly where the plan requires: the package build,
the verification of a new Hermes process, a profile write half-way, a crash with the
journal left behind, and the rollback's own rebuild. A profile that was protected must
end protected by the previous version, or blocking every tool call with a repair
message; never unprotected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsfence import __version__, lifecycle
from agentsfence.cli import main
from agentsfence.profiles import read_state, write_state


@pytest.fixture
def hermes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    root = tmp_path / "hermes"
    work = root / "profiles" / "work"
    for home in (root, work):
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "chat-model"},
                                                        "plugins": {"enabled": ["other-plugin"]}}))
    monkeypatch.setenv("HERMES_HOME", str(root))
    for name in ("AGENTSFENCE_HOME", "AGENTSFENCE_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("agentsfence.profiles.published_release", lambda: True)
    monkeypatch.setattr("agentsfence.lifecycle.published_release", lambda: True)
    calls: dict[str, Any] = {"build": [], "verify": [], "build_ok": [True], "verify_ok": [True]}

    def build() -> tuple[bool, str]:
        ok = calls["build_ok"][min(len(calls["build"]), len(calls["build_ok"]) - 1)]
        calls["build"].append(ok)
        return ok, "Hermes' environment is built." if ok else "`hermes pm install` failed (exit 1)."

    def verify(home: Path, version: str | None) -> tuple[bool, str]:
        ok = calls["verify_ok"][min(len(calls["verify"]), len(calls["verify_ok"]) - 1)]
        calls["verify"].append((home.name if home.parent.name == "profiles" else "default", version, ok))
        return ok, "enforces" if ok else f"Hermes loads AgentsFence 0.0.1, not {version}."

    monkeypatch.setattr(lifecycle, "build_environment", build)
    monkeypatch.setattr(lifecycle, "verify_loads", verify)
    monkeypatch.setattr(lifecycle, "run_preflight", lambda: {"ok": True, "missing": [], "optional_missing": []})
    monkeypatch.setattr("agentsfence.diagnostics.unregistered_hermes", lambda home, processes: [])
    return {"root": root, "work": work, "calls": calls}


def snapshot_files(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and "backups" not in p.parts and p.name not in {"audit.jsonl", "lifecycle.lock"}}


def enabled(home: Path) -> list[str]:
    return yaml.safe_load((home / "config.yaml").read_text())["plugins"]["enabled"]  # type: ignore[no-any-return]


def test_protect_builds_verifies_and_leaves_no_journal(hermes: dict[str, Any]) -> None:
    report = lifecycle.protect(all_profiles=True, include_new=True)
    root, work = hermes["root"], hermes["work"]
    assert enabled(root) == enabled(work) == ["other-plugin", "agentsfence"]
    assert hermes["calls"]["build"] == [True] and hermes["calls"]["verify"] == [("default", __version__, True), ("work", __version__, True)]
    assert read_state() == {"protected": ["default", "work"], "excluded": [], "include_new": True, "version": __version__}
    assert not lifecycle.journal_path().exists() and not list((root / "agentsfence" / "backups").glob("*"))
    assert any("enforces" in line for line in report["lines"])
    events = [json.loads(line)["event"] for line in (root / "agentsfence" / "audit.jsonl").read_text().splitlines()]
    assert events.count("protected") == 2  # lifecycle events are audited


def test_fresh_install_registers_without_build_until_first_protect(hermes: dict[str, Any]) -> None:
    report = lifecycle.install()
    assert report["profiles"] == [] and read_state()["protected"] == []
    assert "agentsfence" not in enabled(hermes["root"])
    assert "agentsfence" not in enabled(hermes["work"])
    assert hermes["calls"]["build"] == [] and hermes["calls"]["verify"] == []
    assert any("dependency when you protect the first profile" in line for line in report["lines"])
    lifecycle.protect(["work"])
    assert "agentsfence" not in enabled(hermes["root"])
    assert "agentsfence" in enabled(hermes["work"])
    assert hermes["calls"]["build"] == [True]
    assert hermes["calls"]["verify"] == [("work", __version__, True)]


def test_a_failed_build_restores_every_file(hermes: dict[str, Any]) -> None:
    before = snapshot_files(hermes["root"])
    hermes["calls"]["build_ok"] = [False, True]
    with pytest.raises(lifecycle.LifecycleError, match="pm install` failed.*Rolled back"):
        lifecycle.protect(all_profiles=True)
    assert snapshot_files(hermes["root"]) == before  # byte for byte, no loader left behind
    assert hermes["calls"]["build"] == [False, True]  # a failed build may have switched the environment; restore it
    assert not lifecycle.journal_path().exists()
    events = [json.loads(line)["event"] for line in (hermes["root"] / "agentsfence" / "audit.jsonl").read_text().splitlines()]
    assert "rolled_back" in events and "failed" in events


def test_a_failed_verification_rebuilds_the_previous_version(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    write_state({**read_state(), "version": "0.2.0a7"})  # as if installed by the previous release
    before = snapshot_files(hermes["root"])
    hermes["calls"]["build"].clear()
    hermes["calls"]["verify"].clear()
    hermes["calls"]["verify_ok"] = [False, True]
    with pytest.raises(lifecycle.LifecycleError, match="not .*Rolled back"):
        lifecycle.install()  # the upgrade
    assert snapshot_files(hermes["root"]) == before
    assert hermes["calls"]["build"] == [True, True]  # the build that switched Hermes, then the rebuild from restored pins
    assert hermes["calls"]["verify"] == [("default", __version__, False), ("default", "0.2.0a7", True)]
    assert "agentsfence" in enabled(hermes["root"]) and "agentsfence" not in enabled(hermes["work"])


def loader(home: Path) -> str:
    return (home / "plugins" / "agentsfence" / "__init__.py").read_text()


@pytest.mark.parametrize("operation", [
    lambda: lifecycle.update_settings(compile_budget=60),
    lambda: lifecycle.unprotect(["work"]),
    lambda: lifecycle.protect(["work"]),
])
def test_a_command_from_another_version_changes_nothing(hermes: dict[str, Any], operation: Any) -> None:
    """Review finding: settings/unprotect from another version pinned loaders to a version Hermes lacked."""
    lifecycle.protect(all_profiles=True)
    write_state({**read_state(), "version": "0.2.0a7"})  # Hermes runs another AgentsFence than this command
    hermes["calls"]["build"].clear()
    before = snapshot_files(hermes["root"])
    with pytest.raises(lifecycle.LifecycleError, match="Hermes runs AgentsFence 0.2.0a7.*agentsfence==0.2.0a7"):
        operation()
    assert snapshot_files(hermes["root"]) == before and hermes["calls"]["build"] == []


def test_loaders_accept_only_this_version_once_hermes_runs_it(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    write_state({**read_state(), "version": "0.2.0a7"})
    lifecycle.install(build=False)  # no environment switch: both versions stay accepted
    assert f"ACCEPTED_VERSIONS: tuple[str, ...] = ('0.2.0a7', {__version__!r})" in loader(hermes["root"])
    write_state({**read_state(), "version": "0.2.0a7"})
    lifecycle.install()  # built and verified: this version only
    assert "ACCEPTED_VERSIONS: tuple[str, ...] = ()" in loader(hermes["root"])
    assert f"EXPECTED_VERSION: str | None = {__version__!r}" in loader(hermes["root"])


def test_upkeep_from_another_version_does_not_protect_new_profiles(hermes: dict[str, Any]) -> None:
    """Review finding: an older `agentsfence` on PATH moved every profile to its own version."""
    lifecycle.protect(["default"], include_new=True)
    write_state({**read_state(), "version": "0.2.0a7"})
    hermes["calls"]["build"].clear()
    lines = lifecycle.sweep()
    assert any("Not protecting new profile(s) work" in line for line in lines), lines
    assert "agentsfence" not in enabled(hermes["work"]) and hermes["calls"]["build"] == []


def test_a_write_failing_half_way_restores_the_profiles_already_written(hermes: dict[str, Any],
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    before = snapshot_files(hermes["root"])
    from agentsfence import profiles

    real = profiles.protect_profile
    written: list[str] = []

    def flaky(home: Path, settings: Any = None) -> dict[str, Any]:
        if written:
            raise OSError(28, "No space left on device")
        written.append(home.name)
        return real(home, settings)

    monkeypatch.setattr("agentsfence.lifecycle.protect_profile", flaky)
    with pytest.raises(lifecycle.LifecycleError, match="No space left on device.*Rolled back"):
        lifecycle.protect(all_profiles=True)
    assert written and snapshot_files(hermes["root"]) == before
    assert hermes["calls"]["build"] == []  # nothing was built from a half-written state


def test_a_crash_leaves_a_journal_that_the_next_command_rolls_back(hermes: dict[str, Any],
                                                                   capsys: pytest.CaptureFixture[str]) -> None:
    lifecycle.protect(["default"])
    before = snapshot_files(hermes["root"])
    # Simulate a crash mid-transaction: snapshot and journal written, files half changed, process gone.
    journal = {"id": "crashed", "operation": "protect", "started": 0, "previous_version": __version__, "built": True,
               "backup": str(hermes["root"] / "agentsfence" / "backups" / "crashed")}
    journal["entries"] = lifecycle._snapshot(Path(journal["backup"]))
    lifecycle._write_journal(journal)
    (hermes["work"] / "config.yaml").write_text("plugins: {enabled: [agentsfence]}\n")
    (hermes["root"] / "config.yaml").write_text("half written")
    hermes["calls"]["build"].clear()
    assert main(["doctor"]) in (0, 1)
    assert "Rolling back an interrupted AgentsFence protect" in capsys.readouterr().err
    assert snapshot_files(hermes["root"]) == before
    assert hermes["calls"]["build"] == [True]  # the interrupted build may have switched Hermes: rebuilt from restored pins
    assert not lifecycle.journal_path().exists()


def test_a_failed_rollback_rebuild_keeps_protected_profiles_fail_closed(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    hermes["calls"]["build"].clear()
    hermes["calls"]["build_ok"] = [True, False]  # the upgrade builds, verification fails, the rollback build fails too
    hermes["calls"]["verify_ok"] = [False]
    with pytest.raises(lifecycle.LifecycleError) as failure:
        lifecycle.protect(["work"])
    assert "block every tool call until `agentsfence install` succeeds" in str(failure.value)
    root = hermes["root"]
    assert "agentsfence" in enabled(root)  # still protected: its loader blocks tools rather than run unguarded
    assert (root / "plugins" / "agentsfence" / "__init__.py").is_file()
    assert "guarded_register" in (root / "plugins" / "agentsfence" / "__init__.py").read_text()


def test_preflight_failure_changes_nothing(hermes: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    before = snapshot_files(hermes["root"])
    monkeypatch.setattr(lifecycle, "run_preflight",
                        lambda: {"ok": False, "error": "This Hermes lacks what AgentsFence needs: block precedence. Nothing was changed."})
    with pytest.raises(lifecycle.LifecycleError, match="block precedence"):
        lifecycle.protect(all_profiles=True)
    assert snapshot_files(hermes["root"]) == before and hermes["calls"]["build"] == []


def test_another_operation_in_progress_is_refused(hermes: dict[str, Any]) -> None:
    import os

    with lifecycle._lock():
        with pytest.raises(lifecycle.LockBusy, match=f"PID {os.getpid()}"):
            lifecycle.protect(["default"])
        assert lifecycle.sweep() == []  # upkeep leaves it to the running operation
    lock = hermes["root"] / "agentsfence" / "lifecycle.lock"
    lock.write_text("4242")  # left by a crashed process: no OS lock holds it
    lifecycle.protect(["default"])


def test_include_new_switch_is_audited_and_kept(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    lifecycle.set_include_new(True)
    assert read_state()["include_new"] is True and read_state()["protected"] == ["default"]
    events = [json.loads(line)["event"] for line in (hermes["root"] / "agentsfence" / "audit.jsonl").read_text().splitlines()]
    assert "settings_changed" in events


def answers(monkeypatch: pytest.MonkeyPatch, *replies: str) -> None:
    queue = list(replies)
    monkeypatch.setattr("agentsfence.cli._interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": queue.pop(0))


def test_setup_choice_one_returns_to_the_profile_default(hermes: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Review finding: choosing 1 after a dedicated model kept the dedicated model."""
    from agentsfence.config import load_settings

    lifecycle.install()
    lifecycle.update_settings(model="compiler-model")
    answers(monkeypatch, "", "1", "", "n")  # all profiles, compiler 1, protect new: default, run test: no
    assert main(["setup"]) == 0
    assert load_settings(hermes_dir=hermes["root"]).compiler.mode == "inherit"
    cfg = yaml.safe_load((hermes["work"] / "config.yaml").read_text())
    assert cfg["auxiliary"]["agentsfence_policy"]["model"] == "chat-model"


@pytest.mark.parametrize("replies,error", [(["nosuch"], "Unknown Hermes profile"), (["", "0"], "Choose 1-"),
                                           (["", "x"], "Choose 1-")])
def test_setup_rejects_bad_answers(hermes: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
                                   capsys: pytest.CaptureFixture[str], replies: list[str], error: str) -> None:
    answers(monkeypatch, *replies)
    assert main(["setup"]) == 2
    assert error in capsys.readouterr().err
    assert "agentsfence" not in enabled(hermes["root"])


def test_upgrade_reapplies_to_every_protected_profile_even_one_hermes_disabled(hermes: dict[str, Any]) -> None:
    """Early-user report: after an upgrade, one profile was left NOT PROTECTED."""
    lifecycle.protect(all_profiles=True)
    manifest = hermes["work"] / "plugins" / "agentsfence" / "plugin.yaml"
    stale = yaml.safe_load(manifest.read_text())
    stale["python_dependencies"] = ["agentsfence==0.0.1"]
    manifest.write_text(yaml.safe_dump(stale))
    cfg = yaml.safe_load((hermes["work"] / "config.yaml").read_text())
    cfg["plugins"]["enabled"] = ["other-plugin"]  # e.g. `hermes update` disabled it
    (hermes["work"] / "config.yaml").write_text(yaml.safe_dump(cfg))
    lifecycle.install()
    assert "agentsfence" in enabled(hermes["work"])
    assert yaml.safe_load(manifest.read_text())["python_dependencies"] == [f"agentsfence=={__version__}"]


def test_unprotect_removes_what_protect_wrote_and_is_remembered(hermes: dict[str, Any]) -> None:
    lifecycle.protect(all_profiles=True, include_new=True)
    lifecycle.unprotect(["work"])
    cfg = yaml.safe_load((hermes["work"] / "config.yaml").read_text())
    assert cfg["plugins"]["enabled"] == ["other-plugin"] and "agentsfence" not in (cfg["plugins"].get("entries") or {})
    assert "auxiliary" not in cfg and not (hermes["work"] / "plugins" / "agentsfence").exists()
    state = read_state()
    assert state["protected"] == ["default"] and state["excluded"] == ["work"]
    assert lifecycle.sweep() == []  # protect-new-profiles leaves a profile the user unprotected alone


def test_new_profiles_are_protected_when_the_user_asked_for_it(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"], include_new=True)
    new = hermes["root"] / "profiles" / "research"
    new.mkdir()
    (new / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "m"}}))
    lines = lifecycle.sweep()
    assert any("Protected new profile(s) automatically: work, research" in line or
               "Protected new profile(s) automatically: research, work" in line for line in lines), lines
    assert "agentsfence" in enabled(new) and "agentsfence" in enabled(hermes["work"])


def test_without_protect_new_profiles_a_new_profile_is_reported_not_changed(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    assert lifecycle.sweep() == []
    assert "agentsfence" not in enabled(hermes["work"])
    from agentsfence.diagnostics import snapshot

    assert snapshot(hermes["root"])["unprotected_profiles"] == ["work"]


def test_uninstall_leaves_no_entries_for_the_next_setup_to_pick_up(hermes: dict[str, Any],
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Early-user report: the documented uninstall left AgentsFence entries in config.yaml."""
    gc: list[bool] = []
    monkeypatch.setattr(lifecycle, "collect_garbage", lambda: gc.append(True) or "gc ran")
    lifecycle.protect(all_profiles=True)
    lifecycle.update_settings(compile_budget=45)
    audit = hermes["root"] / "agentsfence" / "audit.jsonl"
    assert audit.is_file()
    report = lifecycle.uninstall()
    for home in (hermes["root"], hermes["work"]):
        cfg = yaml.safe_load((home / "config.yaml").read_text())
        assert "agentsfence" not in json.dumps(cfg["plugins"]) and "agentsfence_policy" not in json.dumps(cfg)
        assert not (home / "plugins" / "agentsfence").exists()
    assert not (hermes["root"] / "agentsfence" / "settings.yaml").exists() and read_state()["protected"] == []
    assert audit.is_file() and gc == [True] and "gc ran" in report["lines"]
    lifecycle.uninstall(purge=True)
    assert not audit.exists()


def test_settings_apply_one_budget_to_every_protected_profile(hermes: dict[str, Any]) -> None:
    """Early-user report: the compile budget differed per profile."""
    lifecycle.protect(all_profiles=True)
    lifecycle.update_settings(compile_budget=45)
    for home in (hermes["root"], hermes["work"]):
        assert yaml.safe_load((home / "config.yaml").read_text())["plugins"]["hook_callback_timeout"] == 57
    from agentsfence.config import load_settings

    assert {load_settings(hermes_dir=h).compiler.timeout_seconds for h in (hermes["root"], hermes["work"])} == {45}
    with pytest.raises(lifecycle.LifecycleError, match="between 1 and 480"):
        lifecycle.update_settings(compile_budget=900)
    lifecycle.update_settings(profile="work", strict_yolo=True, retention_days=30)  # a per-profile override
    assert load_settings(hermes_dir=hermes["work"]).evaluation.strict_yolo
    assert not load_settings(hermes_dir=hermes["root"]).evaluation.strict_yolo
    assert load_settings(hermes_dir=hermes["work"]).audit.retention_days == 30


def test_desktop_every_profile_settings_replace_only_the_fields_saved(hermes: dict[str, Any]) -> None:
    from agentsfence.config import load_settings
    from agentsfence.profiles import override_path

    lifecycle.protect(all_profiles=True)
    lifecycle.update_settings(profile="work", compile_budget=60, strict_yolo=False, retention_days=7,
                              model="old", provider="old-provider")
    override = override_path(hermes["work"])
    data = yaml.safe_load(override.read_text())
    data["audit"]["max_bytes"] = 777777
    override.write_text(yaml.safe_dump(data))
    lifecycle.update_settings(strict_yolo=True)  # Shared CLI defaults retain override precedence.
    assert not load_settings(hermes_dir=hermes["work"]).evaluation.strict_yolo
    lifecycle.update_settings(apply_to_all_profiles=True, strict_yolo=True, compile_budget=45,
                              retention_days=30, model="new", provider="new-provider")
    for home in (hermes["root"], hermes["work"]):
        settings = load_settings(hermes_dir=home)
        assert settings.evaluation.strict_yolo and settings.compiler.timeout_seconds == 45
        assert settings.audit.retention_days == 30
        assert settings.compiler.selected_model == "new" and settings.compiler.selected_provider == "new-provider"
        assert yaml.safe_load((home / "config.yaml").read_text())["plugins"]["hook_callback_timeout"] == 57
    assert load_settings(hermes_dir=hermes["work"]).audit.max_bytes == 777777


def test_failed_every_profile_save_restores_overrides(hermes: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    lifecycle.protect(all_profiles=True)
    lifecycle.update_settings(profile="work", strict_yolo=False)
    before = snapshot_files(hermes["root"])
    def fail_after_writes(home: Path) -> None:
        raise OSError("cannot sync compiler route")

    monkeypatch.setattr(lifecycle, "sync_compiler_route", fail_after_writes)
    with pytest.raises(lifecycle.LifecycleError, match="Rolled back"):
        lifecycle.update_settings(apply_to_all_profiles=True, strict_yolo=True)
    assert snapshot_files(hermes["root"]) == before


def test_every_profile_save_preserves_unprotected_profile_settings(hermes: dict[str, Any]) -> None:
    from agentsfence.config import load_settings

    lifecycle.protect(["default"])
    lifecycle.update_settings(profile="work", strict_yolo=False)
    lifecycle.update_settings(apply_to_all_profiles=True, strict_yolo=True)
    assert load_settings(hermes_dir=hermes["root"]).evaluation.strict_yolo
    assert not load_settings(hermes_dir=hermes["work"]).evaluation.strict_yolo


def test_every_profile_save_handles_shared_file_as_override(hermes: dict[str, Any]) -> None:
    from agentsfence.config import load_settings, shared_settings_path

    lifecycle.protect(["default"])
    (hermes["root"] / ".env").write_text(f"AGENTSFENCE_CONFIG={shared_settings_path(hermes['root'])}\n")
    lifecycle.update_settings(apply_to_all_profiles=True, strict_yolo=True)
    assert load_settings(hermes_dir=hermes["root"]).evaluation.strict_yolo


@pytest.mark.parametrize("withdraw", ["toggle", "exclude"])
def test_sweep_rechecks_user_choices_under_the_transaction_lock(hermes: dict[str, Any],
                                                               monkeypatch: pytest.MonkeyPatch, withdraw: str) -> None:
    lifecycle.protect(["default"], include_new=True)
    hermes["calls"]["build"].clear()

    def candidates() -> list[str]:
        if withdraw == "toggle":
            lifecycle.set_include_new(False)
        else:
            lifecycle.unprotect(["work"])
        hermes["calls"]["build"].clear()
        return ["work"]  # Stale candidate from before the user's change.

    monkeypatch.setattr(lifecycle, "unprotected_profiles", candidates)
    assert lifecycle.sweep() == []
    assert hermes["calls"]["build"] == [] and "agentsfence" not in enabled(hermes["work"])
    assert not read_state()["include_new"] if withdraw == "toggle" else "work" in read_state()["excluded"]


def test_cli_lifecycle_commands(hermes: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["install"]) == 0
    assert "No profile is protected yet" in capsys.readouterr().out
    assert main(["protect", "--profiles", "default", "work", "--include-new"]) == 0
    out = capsys.readouterr().out
    assert "default: protected; compiler chat-model via p." in out and "protected automatically" in out
    assert main(["settings", "--model", "compiler-model"]) == 0
    assert "compiler compiler-model" in capsys.readouterr().out
    assert main(["settings"]) == 0
    shown = capsys.readouterr().out
    assert "Compiler: selected — compiler-model" in shown and "Monitoring: approvals" in shown
    assert main(["unprotect", "--profile", "work"]) == 0
    assert main(["uninstall"]) == 2  # no terminal: confirmation is required
    assert "--yes" in capsys.readouterr().err


def test_include_new_repairs_a_clone_with_config_but_no_loader(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"], include_new=True)
    clone = hermes["root"] / "profiles" / "clone"
    clone.mkdir()
    (clone / "config.yaml").write_bytes((hermes["root"] / "config.yaml").read_bytes())
    assert "clone" in lifecycle.unprotected_profiles()
    lifecycle.sweep()
    assert (clone / "plugins" / "agentsfence" / "__init__.py").is_file()
    assert "clone" not in lifecycle.unprotected_profiles()


def test_uninstall_rebuilds_after_removing_the_last_declaration(hermes: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    lifecycle.protect(["default"])
    hermes["calls"]["build"].clear()
    monkeypatch.setattr(lifecycle, "collect_garbage", lambda: None)
    lifecycle.uninstall()
    assert hermes["calls"]["build"] == [True]


def test_failed_rollback_retains_recovery_evidence(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    hermes["calls"]["build"].clear()
    hermes["calls"]["build_ok"] = [False, False]
    with pytest.raises(lifecycle.LifecycleError, match="Rollback incomplete"):
        lifecycle.install()
    journal = json.loads(lifecycle.journal_path().read_text())
    assert journal["recovery_errors"] and Path(journal["backup"]).is_dir()
    assert "agentsfence" in enabled(hermes["root"])


def test_first_upgrade_reads_the_pre_state_loader_version(hermes: dict[str, Any]) -> None:
    lifecycle.protect(["default"])
    (hermes["root"] / "agentsfence" / "state.json").unlink()
    manifest = hermes["root"] / "plugins" / "agentsfence" / "plugin.yaml"
    data = yaml.safe_load(manifest.read_text())
    data["version"] = "0.2.0a7"
    manifest.write_text(yaml.safe_dump(data))
    assert lifecycle._previous_version() == "0.2.0a7"


def test_incomplete_json_journal_is_retained_for_repair(hermes: dict[str, Any]) -> None:
    lifecycle._write_journal({"operation": "install"})
    before = lifecycle.journal_path().read_bytes()
    with pytest.raises(lifecycle.LifecycleError, match="Incomplete transaction journal"):
        lifecycle.recover()
    assert lifecycle.journal_path().read_bytes() == before
