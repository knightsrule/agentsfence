"""Hermes' environment manager: find its interpreter, never start it mid-update, install through it.

Early-user report (0.2.0a6 on Hermes main, ``hermes --version`` 0.21.5+…): following the
upgrade guidance (`uv pip install` into the managed environment, then setup) made the
environment differ from Hermes' lock; setup's own check started Hermes, which rebuilt it,
and every chat failed for about two minutes. Setup meanwhile named the legacy interpreter.
These tests use stand-in executables with Hermes' real file layout; nothing here runs Hermes.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from agentsfence import hermes_env, host_client
from agentsfence.cli import main

pytestmark = pytest.mark.skipif(os.name == "nt", reason="stand-in executables are POSIX scripts")


def executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def fake_python(path: Path, log: Path) -> Path:
    """Answers Hermes' currency check ($FAKE_STATE), the capability preflight ($FAKE_PREFLIGHT) and the version probe."""
    return executable(path, f"""echo "$@" >> {log}
case "$*" in
  *AGENTSFENCE_HERMES_ENV*) echo "AGENTSFENCE_HERMES_ENV=$FAKE_STATE" ;;
  *AGENTSFENCE_PREFLIGHT*) echo "AGENTSFENCE_PREFLIGHT=$FAKE_PREFLIGHT" ;;
  *importlib.metadata*) [ -n "$FAKE_VERSION" ] && echo "$FAKE_VERSION" ;;
esac
""")


@pytest.fixture
def hermes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A self-managed Hermes: source checkout, launcher script, facts.json and a managed generation."""
    root = tmp_path / "home"
    source = tmp_path / "hermes-agent"
    (source / "pm").mkdir(parents=True)
    (source / "pyproject.toml").write_text("[project]\nname='hermes-agent'\n")
    (source / "install-stamp.json").write_text(json.dumps({"updateMechanism": "self", "baseVersion": "0.21.5"}))
    log = tmp_path / "calls.log"
    legacy = fake_python(source / "venv/bin/python", log)
    key = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:16]
    state = root / "installs" / key
    managed = fake_python(state / "environments/gen1/venv/bin/python", log)
    (state / "facts.json").write_text(json.dumps({"packages": {"venv": {"environment": str(managed.parent.parent)}}}))
    launcher = executable(tmp_path / "bin/hermes", f'echo "launcher $@" >> {log}\nexec "{source}/venv/bin/hermes" "$@"\n')
    (root / "config.yaml").parent.mkdir(parents=True, exist_ok=True)
    (root / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "m"}}))
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(launcher))
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.delenv("AGENTSFENCE_HERMES_PYTHON", raising=False)
    monkeypatch.delenv("HERMES_DISABLE_LAZY_INSTALLS", raising=False)
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": True}))
    monkeypatch.setenv("FAKE_PREFLIGHT", json.dumps({"missing": [], "optional_missing": []}))
    return {"root": root, "source": source, "state": state, "managed": managed, "legacy": legacy,
            "launcher": launcher, "log": log}


def test_the_interpreter_comes_from_hermes_own_record(hermes: dict[str, Path]) -> None:
    install = hermes_env.detect(hermes["root"])
    assert install.managed and install.python == hermes["managed"] and install.source == hermes["source"]
    assert "hermes pm" in install.describe()


@pytest.mark.parametrize("mismatched", [False, True])
def test_desktop_managed_console_launcher_uses_source_bound_record(hermes, monkeypatch, mismatched):
    console = executable(hermes["managed"].parent / "hermes", "# generated console launcher\n")
    stamps = hermes["state"] / "inputs"
    stamps.mkdir()
    source = hermes["source"]
    if mismatched:
        source = source.parent / "other-hermes"
        source.mkdir()
        (source / "pyproject.toml").write_text("[project]\nname='hermes-agent'\n")
    (stamps / ".project-root").write_text(str(source))
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(console))
    install = hermes_env.detect(hermes["root"])
    if mismatched:
        assert install.source is None
        assert hermes_env.pending_work(install, hermes["root"])[0] == hermes_env.UNVERIFIED
    else:
        assert install.source == source and install.python == hermes["managed"] and install.managed
        assert hermes_env.pending_work(install, hermes["root"]) is None
        (hermes["state"] / "source-completion-pending").touch()
        assert hermes_env.pending_work(install, hermes["root"])[0] == hermes_env.UPDATE


def test_a_first_start_without_a_record_is_still_the_managers(hermes: dict[str, Path]) -> None:
    (hermes["state"] / "facts.json").unlink()
    install = hermes_env.detect(hermes["root"])
    assert install.managed and install.python == hermes["legacy"]


def test_desktop_console_commands_use_the_owning_install_launcher(hermes, monkeypatch):
    console = executable(hermes["managed"].parent / "hermes", "exit 99\n")
    stamps = hermes["state"] / "inputs"
    stamps.mkdir()
    (stamps / ".project-root").write_text(str(hermes["source"]))
    native = executable(hermes["source"] / ".hermes/bin/hermes", f'echo "native $@" >> {hermes["log"]}\n')
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(console))
    assert hermes_env.launcher() == host_client.launcher() == str(native)
    result, _ = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    assert result == hermes_env.INSTALLED
    assert "native pm install" in hermes["log"].read_text()
    monkeypatch.setenv("HERMES_HOME", str(hermes["root"] / "profiles/worker"))
    assert host_client.launcher() == str(native)


def test_a_venv_release_is_not_managed(hermes: dict[str, Path]) -> None:
    (hermes["state"] / "facts.json").unlink()
    (hermes["source"] / "install-stamp.json").unlink()
    install = hermes_env.detect(hermes["root"])
    assert not install.managed and install.python == hermes["legacy"]


def test_a_launcher_that_names_no_install_is_never_guessed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(tmp_path / "missing"))
    assert hermes_env.source_root() is None


@pytest.mark.parametrize(("state", "kind"), [
    ({"self_managed": True, "current": False}, hermes_env.REBUILD),
    ({"self_managed": True, "current": True, "update_running": True}, hermes_env.UPDATE),
    ({"self_managed": True, "current": True}, None),
    ({"self_managed": False, "current": False}, None),  # a developer checkout never self-updates
    ({"error": "ImportError"}, hermes_env.UNVERIFIED),   # a managed install's check failed: not "nothing pending"
    ({"self_managed": True}, hermes_env.UNVERIFIED),      # no currency answer
])
def test_pending_work_is_hermes_own_verdict(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                            state: dict[str, object], kind: str | None) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps(state))
    work = hermes_env.pending_work(hermes_env.detect(hermes["root"]), hermes["root"])
    assert (work[0] if work else None) == kind


def test_an_unfinished_update_is_pending_without_asking(hermes: dict[str, Path]) -> None:
    (hermes["state"] / "source-completion-pending").write_text("owed\n")
    work = hermes_env.pending_work(hermes_env.detect(hermes["root"]), hermes["root"])
    assert work is not None and work[0] == hermes_env.UPDATE and "hermes update" in work[1]


def test_doctor_never_starts_hermes_while_an_update_is_pending(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    answer = host_client.status(hermes["root"])
    assert not answer["reachable"] and "hermes pm install" in answer["pending_update"]
    assert "launcher" not in hermes["log"].read_text()  # the launcher never ran


def test_managed_install_goes_through_the_package_manager(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    executable(hermes["source"] / "venv/bin/hermes", f'echo "hermes $@" >> {hermes["log"]}\n')
    result, message = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    assert result == hermes_env.INSTALLED, message
    log = hermes["log"].read_text()
    assert "hermes pm install" in log and "pip install" not in log


def test_the_package_manager_is_never_run_during_an_update(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "update_running": True}))
    result, message = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    assert result == hermes_env.FAILED and "update is running" in message
    assert "hermes pm" not in hermes["log"].read_text()


def test_a_venv_hermes_is_told_to_update_and_nothing_is_written(hermes: dict[str, Path],
                                                                 capsys: pytest.CaptureFixture[str]) -> None:
    (hermes["state"] / "facts.json").unlink()
    (hermes["source"] / "install-stamp.json").unlink()
    install = hermes_env.detect(hermes["root"])
    reason = hermes_env.unsupported_reason(install)
    assert reason and "hermes update" in reason and str(hermes["legacy"]) in reason
    result, _ = hermes_env.run_pm_install(install, hermes["root"])
    assert result == hermes_env.FAILED
    before = (hermes["root"] / "config.yaml").read_text()
    assert main(["protect", "--profile", "default"]) == 2
    assert "hermes update" in capsys.readouterr().err
    assert (hermes["root"] / "config.yaml").read_text() == before and not (hermes["root"] / "plugins").exists()


def test_a_missing_capability_stops_protect_before_anything_is_written(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                                                      capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("FAKE_PREFLIGHT", json.dumps({"missing": ["block precedence (a plugin's block wins over another plugin's approve)"],
                                                     "optional_missing": []}))
    before = (hermes["root"] / "config.yaml").read_text()
    assert main(["protect", "--profile", "default"]) == 2
    err = capsys.readouterr().err
    assert "block precedence" in err and "Nothing was changed" in err
    assert (hermes["root"] / "config.yaml").read_text() == before and not (hermes["root"] / "plugins").exists()
    assert "launcher" not in hermes["log"].read_text()  # the check never starts Hermes


def test_doctor_names_hermes_environment(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                        capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["protect", "--profile", "default", "--no-build"]) == 0
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    capsys.readouterr()
    main(["doctor"])
    out = capsys.readouterr().out
    assert f"Hermes environment: {hermes['managed']} (managed by Hermes" in out
    assert "Hermes update pending:" in out and "UNVERIFIED" in out


# An interpreter override names the Python, never who owns it -------------------------


def test_an_override_naming_the_managed_interpreter_keeps_the_manager(hermes: dict[str, Path],
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(hermes["managed"]))
    install = hermes_env.detect(hermes["root"])
    assert install.managed and install.python == hermes["managed"]
    assert install.source == hermes["source"] and install.state_dir == hermes["state"]


def test_an_override_naming_a_self_managed_checkouts_bootstrap_venv_keeps_the_manager(
        hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(hermes["legacy"]))
    install = hermes_env.detect(hermes["root"])
    assert install.managed and install.source == hermes["source"]


def test_an_override_into_a_managed_generation_is_managed_without_a_launcher(
        hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(tmp_path / "missing"))
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(hermes["managed"]))
    install = hermes_env.detect(hermes["root"])
    assert install.managed and install.state_dir == hermes["state"]


def test_an_override_of_a_venv_release_stays_a_venv(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    (hermes["state"] / "facts.json").unlink()
    (hermes["source"] / "install-stamp.json").unlink()
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(hermes["legacy"]))
    install = hermes_env.detect(hermes["root"])
    assert not install.managed and install.python == hermes["legacy"] and install.source == hermes["source"]


def test_a_managed_override_installs_through_the_package_manager(
        hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(hermes["managed"]))
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    executable(hermes["source"] / "venv/bin/hermes", f'echo "hermes $@" >> {hermes["log"]}\n')
    result, message = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    assert result == hermes_env.INSTALLED, message
    log = hermes["log"].read_text()
    assert "hermes pm install" in log and "pip install" not in log


# A check that cannot report is not "nothing pending" --------------------------------


def _broken_check(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    if mode == "no-answer":
        executable(hermes["managed"], "exit 3\n")
    elif mode == "bad-json":
        monkeypatch.setenv("FAKE_STATE", "{not json")
    elif mode == "timeout":
        executable(hermes["managed"], "sleep 5\n")
        monkeypatch.setattr(hermes_env, "CHECK_TIMEOUT", 0.2)
    elif mode == "cannot-run":
        hermes["managed"].chmod(0o644)
    elif mode == "error":
        monkeypatch.setenv("FAKE_STATE", json.dumps({"error": "ModuleNotFoundError"}))


def _log(hermes: dict[str, Path]) -> str:
    return hermes["log"].read_text() if hermes["log"].exists() else ""


_BROKEN = ["no-answer", "bad-json", "timeout", "cannot-run", "error"]


@pytest.mark.parametrize("mode", _BROKEN)
def test_a_failed_check_of_a_managed_install_is_unverified(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                                           mode: str) -> None:
    _broken_check(hermes, monkeypatch, mode)
    work = hermes_env.pending_work(hermes_env.detect(hermes["root"]), hermes["root"])
    assert work is not None and work[0] == hermes_env.UNVERIFIED and "hermes pm status" in work[1]


@pytest.mark.parametrize("mode", _BROKEN)
def test_a_failed_check_of_a_venv_install_changes_nothing(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                                          mode: str) -> None:
    (hermes["state"] / "facts.json").unlink()
    (hermes["source"] / "install-stamp.json").unlink()
    hermes["managed"] = hermes["legacy"]  # the venv's Python is the one checked
    _broken_check(hermes, monkeypatch, mode)
    assert hermes_env.pending_work(hermes_env.detect(hermes["root"]), hermes["root"]) is None


def test_lazy_installs_disabled_is_still_nothing_pending(hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    _broken_check(hermes, monkeypatch, "no-answer")
    monkeypatch.setenv("HERMES_DISABLE_LAZY_INSTALLS", "1")
    assert hermes_env.pending_work(hermes_env.detect(hermes["root"]), hermes["root"]) is None


@pytest.mark.parametrize("mode", ["no-answer", "error"])
def test_doctor_never_starts_hermes_when_its_update_state_is_unverified(
        hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    _broken_check(hermes, monkeypatch, mode)
    answer = host_client.status(hermes["root"])
    assert not answer["reachable"] and answer["pending_kind"] == hermes_env.UNVERIFIED
    assert "cannot confirm" in answer["error"]
    assert "launcher" not in _log(hermes)  # the launcher never ran


@pytest.mark.parametrize("mode", ["no-answer", "error"])
def test_nothing_installs_when_update_state_is_unverified(
        hermes: dict[str, Path], monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    _broken_check(hermes, monkeypatch, mode)
    executable(hermes["source"] / "venv/bin/hermes", f'echo "hermes $@" >> {hermes["log"]}\n')
    result, message = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    assert result == hermes_env.FAILED and "could not be verified" in message
    assert "hermes pm" not in _log(hermes)


def test_doctor_text_names_an_unverified_update_state() -> None:
    from agentsfence.diagnostics import format_status

    base = {"version": "x", "profile": "default", "home": "/h", "compiler": {"model": "m", "routing": "r"},
            "pending_update": "reason", "approval_mode": "manual", "human_approval": True}
    assert "Hermes update state unverified: reason" in format_status({**base, "pending_kind": hermes_env.UNVERIFIED})
    assert "Hermes update pending: reason" in format_status({**base, "pending_kind": hermes_env.REBUILD})


# The layout Hermes' own installer (scripts/install.sh) produces ---------------------------
# Copied from a real install of the pinned main revision (2026-09-27): no <source>/venv;
# ~/.local/bin/hermes execs <source>/.hermes/bin/hermes, a sh script that runs the store
# Python with `sys.path.insert(0, '<source>')` inside a shell-quoted -c program.


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    root = tmp_path / "hermes-home"
    source = tmp_path / "hermes-agent"
    (source / "pm").mkdir(parents=True)
    (source / "pyproject.toml").write_text('[project]\nname = "hermes-agent"\n')
    (source / "install-stamp.json").write_text(json.dumps({"updateMechanism": "self", "payload": "bootstrap"}))
    log = tmp_path / "calls.log"
    store = fake_python(root / "tools/python-3.14.7/bin/python3", log)
    bootstrap = (f"exec {store} -I -c 'import os, re, sys\n"
                 f"sys.path.insert(0, '\"'\"'{source}'\"'\"')\n"
                 f"from hermes_cli.main import main\nmain()' \"$@\"\n")
    local = executable(source / ".hermes/bin/hermes", f'echo "launcher $@" >> {log}\n' + bootstrap)
    wrapper = executable(tmp_path / "home/.local/bin/hermes", f'exec {local} "$@"\n')
    key = hashlib.sha256(str(source.resolve()).encode()).hexdigest()[:16]
    state = root / "installs" / key
    managed = fake_python(state / "environments/gen1/venv/bin/python", log)
    (state / "facts.json").write_text(json.dumps({"packages": {"venv": {"environment": str(managed.parent.parent)}}}))
    (root / "config.yaml").write_text(yaml.safe_dump({"model": {"provider": "p", "default": "m"}}))
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(wrapper))
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.delenv("AGENTSFENCE_HERMES_PYTHON", raising=False)
    monkeypatch.delenv("HERMES_DISABLE_LAZY_INSTALLS", raising=False)
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": True}))
    monkeypatch.setenv("FAKE_PREFLIGHT", json.dumps({"missing": [], "optional_missing": []}))
    return {"root": root, "source": source, "state": state, "managed": managed, "local": local, "wrapper": wrapper,
            "log": log}


@pytest.mark.parametrize("which", ["wrapper", "local"])
def test_the_installers_layout_is_a_managed_install(installed: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                                     which: str) -> None:
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(installed[which]))
    install = hermes_env.detect(installed["root"])
    assert install.source == installed["source"] and install.managed
    assert install.python == installed["managed"] and install.state_dir == installed["state"]


def test_a_launcher_found_only_through_its_bootstrap_line(installed: dict[str, Path], monkeypatch: pytest.MonkeyPatch,
                                                          tmp_path: Path) -> None:
    """A copied launcher (no .hermes/bin path) still names its checkout in the bootstrap line."""
    copy = executable(tmp_path / "elsewhere/hermes", installed["local"].read_text().split("\n", 1)[1])
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(copy))
    assert hermes_env.detect(installed["root"]).source == installed["source"]


def test_the_installers_layout_builds_through_the_package_manager(installed: dict[str, Path],
                                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    result, message = hermes_env.run_pm_install(hermes_env.detect(installed["root"]), installed["root"])
    assert result == hermes_env.INSTALLED, message
    log = installed["log"].read_text()
    assert "launcher pm install" in log and "pip install" not in log


def test_doctor_checks_pending_work_on_the_installers_layout(installed: dict[str, Path],
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_STATE", json.dumps({"self_managed": True, "current": False}))
    answer = host_client.status(installed["root"])
    assert not answer["reachable"] and answer["pending_kind"] == hermes_env.REBUILD
    assert "launcher" not in _log(installed)


def _unknown_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log = tmp_path / "unknown.log"
    exe = executable(tmp_path / "custom/hermes", f'echo "launcher $@" >> {log}\nexec some-runtime "$@"\n')
    monkeypatch.setenv("AGENTSFENCE_HERMES", str(exe))
    return log


def test_an_existing_launcher_whose_install_is_unknown_is_unverified(hermes: dict[str, Path], tmp_path: Path,
                                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    log = _unknown_launcher(tmp_path, monkeypatch)
    install = hermes_env.detect(hermes["root"])
    assert install.source is None and install.launcher is not None
    work = hermes_env.pending_work(install, hermes["root"])
    assert work is not None and work[0] == hermes_env.UNVERIFIED and "AGENTSFENCE_HERMES_PYTHON" in work[1]
    answer = host_client.status(hermes["root"])
    assert not answer["reachable"] and not log.exists()  # never started
    reason = hermes_env.unsupported_reason(install)
    assert reason and "cannot tell which Python" in reason


def test_a_plain_interpreter_named_explicitly_is_trusted_with_an_unknown_launcher(
        hermes: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _unknown_launcher(tmp_path, monkeypatch)
    plain = fake_python(tmp_path / "pipx/venvs/hermes-agent/bin/python", tmp_path / "plain.log")
    monkeypatch.setenv("AGENTSFENCE_HERMES_PYTHON", str(plain))
    install = hermes_env.detect(hermes["root"])
    assert not install.managed and hermes_env.pending_work(install, hermes["root"]) is None


def test_another_projects_venv_is_not_a_hermes_checkout(tmp_path: Path) -> None:
    other = tmp_path / "project"
    (other / ".venv/bin").mkdir(parents=True)
    (other / "pyproject.toml").write_text('[project]\nname = "agentsfence"\n')
    (other / "venv/bin").mkdir(parents=True)
    assert hermes_env._checkout_of(other / "venv/bin/hermes") is None


def test_build_output_goes_to_stderr(hermes: dict[str, Path], capfd: pytest.CaptureFixture[str]) -> None:
    """Review finding: `hermes pm install` output on stdout corrupted `doctor --json`."""
    executable(hermes["source"] / "venv/bin/hermes", 'echo "resolving packages"\n')
    result, _ = hermes_env.run_pm_install(hermes_env.detect(hermes["root"]), hermes["root"])
    out, err = capfd.readouterr()
    assert result == hermes_env.INSTALLED
    assert "resolving packages" not in out and "Building Hermes" not in out
    assert "resolving packages" in err
