"""Plan an automatic release after CI; never move a tag or reuse a PyPI version."""

import ast
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import tomllib
from packaging.version import Version


def package_version(root: Path) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    module = ast.parse((root / "agentsfence/__init__.py").read_text())
    public = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
    )
    manifest = re.search(r'^version:\s*[\"\']?([^\"\'\s]+)', (root / "plugin.yaml").read_text(), re.MULTILINE)
    if manifest is None or not (Version(project) == Version(public) == Version(manifest[1])):
        raise ValueError("pyproject.toml, __version__ and plugin.yaml versions must agree")
    version = Version(project)
    if version.local is not None:
        raise ValueError("PyPI releases cannot use a local version identifier")
    return str(version)


def published(version: str) -> bool:
    try:
        with urlopen(f"https://pypi.org/pypi/agentsfence/{version}/json", timeout=30) as response:
            data = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    artifacts = {item["packagetype"] for item in data["urls"] if not item.get("yanked", False)}
    if not {"bdist_wheel", "sdist"}.issubset(artifacts):
        raise ValueError(f"PyPI version {version} exists without an unyanked wheel and sdist; inspect it before retrying")
    return True


#: The rows scripts/beta_validate.py records for every environment (the upgrade row names the
#: release it upgrades from). A managed install must also prove pending-update protection.
REQUIRED_ROWS = ("fresh_install", "upgrade_from_", "doctor_real_compiler", "scenario_test_real_compiler")
MANAGED_ROWS = ("pending_update_protection", "failed_upgrade_rollback", "desktop_approvals")


def _gate_table(root: Path) -> str:
    text = (root / "BETA_GATE.md").read_text()
    return text.split("## Required environments", 1)[1].split("\n## ", 1)[0]


def managed_refs(root: Path) -> set[str]:
    return set(re.findall(r"^\|\s*Managed install at `([0-9a-f]{40})`(?:\s*\([^)|]*\))?\s*\|", _gate_table(root), re.MULTILINE))


def gate_refs(root: Path) -> set[str]:
    """The Hermes revisions BETA_GATE.md's required-environments table names."""
    refs = set(re.findall(r"^\|\s*\d+\.\d+\.\d+ \(`(v[\d.]+)`\)\s*\|", _gate_table(root), re.MULTILINE))
    refs |= managed_refs(root)
    if not refs:
        raise ValueError("BETA_GATE.md names no required environments")
    return refs


def missing_rows(rows: dict[str, str], *, managed: bool) -> list[str]:
    """Required rows an environment's record lacks (a present row must also say PASS)."""
    required = REQUIRED_ROWS + (MANAGED_ROWS if managed else ())
    return [name for name in required
            if not any(key == name or (name.endswith("_") and key.startswith(name)) for key in rows)]


def requires_evidence(version: str) -> bool:
    """Onboarding releases from 0.3.0a1 and all betas/finals need recorded validation."""
    pre = Version(version).pre
    return Version(version) >= Version("0.3.0a1") or pre is None or pre[0] in ("b", "rc")


def _after_evidence(path: str) -> bool:
    """Files that may change between the recorded run and the release commit: evidence and prose."""
    return path.startswith(("release-evidence/", ".beads/")) or (path.endswith(".md") and "/" not in path)


def check_evidence(root: Path, version: str, sha: str) -> None:
    """Refuse a beta or later release without a complete PASS record from scripts/beta_validate.py."""
    if not requires_evidence(version):
        return
    where = f"release-evidence/{version}/summary.json"
    try:
        data = json.loads((root / where).read_text())
    except (OSError, ValueError) as error:
        raise ValueError(f"{version} needs the recorded beta gate ({where} from scripts/beta_validate.py): {error}") from error
    if data.get("version") != version or data.get("agentsfence_version") != version:
        raise ValueError(f"{where} records version {data.get('version')}, not {version}")
    if data.get("dirty"):
        raise ValueError(f"{where} was recorded from a tree with uncommitted changes")
    if (data.get("compiler") or {}).get("mode") != "inherit":
        raise ValueError(f"{where} was not recorded with a real compiler")
    environments = data.get("environments") or {}
    missing = sorted(gate_refs(root) - set(environments))
    if missing:
        raise ValueError(f"{where} has no result for {', '.join(missing)}")
    managed = managed_refs(root)
    incomplete = sorted(f"{ref} ({', '.join(missing)})" for ref, row in environments.items()
                        if (missing := missing_rows(row.get("rows") or {}, managed=ref in managed)))
    if incomplete:
        raise ValueError(f"{where} lacks required rows for {'; '.join(incomplete)}")
    failed = sorted(ref for ref, row in environments.items()
                    if row.get("verdict") != "PASS" or any(value != "PASS" for value in row["rows"].values()))
    if failed:
        raise ValueError(f"{where} records a failed row for {', '.join(failed)}")
    commit = str(data.get("agentsfence_commit") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, sha], cwd=root, capture_output=True).returncode != 0:
        raise ValueError(f"{where} was recorded at {commit or 'no commit'}, which is not an ancestor of {sha}")
    changed = subprocess.run(["git", "diff", "--name-only", commit, sha], cwd=root, capture_output=True, text=True,
                             check=True).stdout.split()
    code = [path for path in changed if not _after_evidence(path)]
    if code:
        raise ValueError(f"these files changed after the beta gate was recorded; rerun it: {', '.join(code[:10])}")


def plan(root: Path, sha: str) -> dict[str, str]:
    version = package_version(root)
    tag = f"v{version}"
    if published(version):
        return {"release": "false", "tag": tag, "create_tag": "false"}
    check_evidence(root, version, sha)
    existing = subprocess.run(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        cwd=root, capture_output=True, text=True, check=False,
    )
    if existing.returncode == 0 and existing.stdout.strip() != sha:
        raise ValueError(f"{tag} already points to another commit; never move a release tag")
    return {"release": "true", "tag": tag, "create_tag": str(existing.returncode != 0).lower()}


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["--check-evidence"]:
        # publish-pypi.yml: a manually pushed tag or a manual dispatch must meet the same gate.
        version = package_version(Path.cwd())
        check_evidence(Path.cwd(), version, os.environ["GITHUB_SHA"])
        print(f"Beta gate evidence {'verified' if requires_evidence(version) else 'not required'} for {version}")
        sys.exit(0)
    outputs = plan(Path.cwd(), os.environ["GITHUB_SHA"])
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for key, value in outputs.items():
            output.write(f"{key}={value}\n")
    print(f"Release plan: {outputs}")
