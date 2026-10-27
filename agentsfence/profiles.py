"""Profile discovery and the per-profile files AgentsFence owns, shared by CLI and desktop.

Protecting a profile means four things in that profile, and nothing else:

* ``plugins.enabled`` lists ``agentsfence`` (and ``plugins.disabled`` does not);
* ``plugins/agentsfence/`` holds the fail-closed loader and a manifest that declares
  AgentsFence as the plugin's Python dependency, so ``hermes pm install`` builds it;
* ``auxiliary.agentsfence_policy`` routes Hermes' compiler slot to the profile's
  default model (inherit) or the selected model;
* ``plugins.hook_callback_timeout`` leaves room for the shared compile budget.

Everything else about AgentsFence lives in its own files: settings shared by every
profile (``<root>/agentsfence/settings.yaml``), optional per-profile overrides, and
``<root>/agentsfence/state.json`` (which profiles the user protected).
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .config import (
    INHERIT,
    LEGACY_OFFLINE_PROVIDERS,
    SELECTED,
    Settings,
    hermes_home,
    load_settings,
    profile_environment,
    read_yaml,
    root_of,
    shared_settings_path,
)

AUX_TASK = "agentsfence_policy"
PLUGIN = "agentsfence"
ASSETS = Path(__file__).parent / "surfaces"
if not (ASSETS / "desktop" / "plugin.js").is_file():
    ASSETS = Path(__file__).resolve().parent.parent  # canonical assets in a checkout/sdist
HOOKS = ["pre_llm_call", "pre_tool_call", "post_tool_call", "post_approval_response",
         "subagent_start", "on_session_reset", "on_session_finalize"]
#: Hermes clamps plugins.hook_callback_timeout to 600s; AgentsFence compiles within 80% of it.
MAX_COMPILE_BUDGET = 480.0
#: Plugin-model override grants written by AgentsFence before 0.3.0; removed on protect.
_LEGACY_GRANT = ("allow_provider_override", "allowed_providers", "allow_model_override", "allowed_models")


def root_home() -> Path:
    try:
        from hermes_constants import get_default_hermes_root

        return Path(get_default_hermes_root())
    except ImportError:
        return root_of(hermes_home())


def profile_name(home: Path) -> str:
    return home.name if home.parent.name == "profiles" else "default"


def available_profiles() -> dict[str, Path]:
    root = root_home()
    found = {"default": root}
    for path in sorted((root / "profiles").glob("*")):
        if path.is_dir() and (path / "config.yaml").is_file():
            found[path.name] = path
    return found


def resolve_profile(name: str | None) -> Path:
    if name is None:
        return hermes_home()
    if not re.fullmatch(r"[\w-]+", name):
        raise ValueError("Use a profile name, not a filesystem path.")
    profiles = available_profiles()
    if name not in profiles:
        raise ValueError(f"Unknown Hermes profile {name!r}. Available: {', '.join(profiles)}")
    return profiles[name]


def read_config(home: Path) -> dict[str, Any]:
    path = home / "config.yaml"
    if not path.exists():
        return {}
    value = read_yaml(path) or {}
    if not isinstance(value, dict):
        raise ValueError(f"Expected a YAML mapping in {path}")
    return value


def write_config(path: Path, value: dict[str, Any]) -> None:
    """Write YAML atomically: a temporary file in the same directory, then a rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".agentsfence-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(value, stream, sort_keys=False, allow_unicode=True)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".agentsfence-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".agentsfence-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AgentsFence's own state: shared settings, per-profile overrides, protected set
# ---------------------------------------------------------------------------


def agentsfence_root() -> Path:
    return shared_settings_path(root_home()).parent


def state_path() -> Path:
    return agentsfence_root() / "state.json"


def read_state() -> dict[str, Any]:
    """What the user asked for; empty when AgentsFence was never set up.

    ``protected``: profiles to keep protected; ``excluded``: profiles the user
    unprotected, which "protect new profiles" leaves alone; ``include_new``;
    ``version``: the AgentsFence version last installed.
    """
    try:
        data = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    def names(key: str) -> list[str]:
        value = data.get(key)
        return [str(p) for p in value] if isinstance(value, list) else []

    return {"protected": names("protected"), "excluded": names("excluded"),
            "include_new": bool(data.get("include_new")), "version": data.get("version")}


def write_state(state: dict[str, Any]) -> None:
    protected = sorted(dict.fromkeys(state.get("protected") or []))
    write_json(state_path(), {"protected": protected,
                              "excluded": sorted(n for n in dict.fromkeys(state.get("excluded") or []) if n not in protected),
                              "include_new": bool(state.get("include_new")), "version": state.get("version")})


def read_settings_file(path: Path) -> dict[str, Any]:
    value = read_yaml(path) if path.is_file() else {}
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return value


def override_path(home: Path) -> Path:
    """A profile's own AgentsFence overrides (``$AGENTSFENCE_HOME/config.yaml``)."""
    env = profile_environment(home)
    if env.get("AGENTSFENCE_CONFIG"):
        return Path(env["AGENTSFENCE_CONFIG"]).expanduser()
    return load_settings(hermes_dir=home).home / "config.yaml"


# ---------------------------------------------------------------------------
# Compiler route
# ---------------------------------------------------------------------------


def _main_model(cfg: dict[str, Any]) -> dict[str, Any] | None:
    main = cfg.get("model")
    if isinstance(main, str):
        main = {"default": main}
    return main if isinstance(main, dict) else None


def profile_default_route(cfg: dict[str, Any]) -> dict[str, str] | None:
    """The profile's configured default model (provider and name); None when unset."""
    main = _main_model(cfg)
    name = str((main or {}).get("default") or (main or {}).get("model") or "").strip()
    if not main or not name:
        return None
    return {"provider": str(main.get("provider") or "auto").strip() or "auto", "model": name}


def profile_compiler_route(cfg: dict[str, Any]) -> tuple[dict[str, str] | None, str | None]:
    """The route that makes Hermes run the profile default for the compiler, or (None, why not).

    Hermes resolves an empty route to each chat's live model (including ``-m``), so
    inherit mode writes the default explicitly and keeps it in sync. Hermes' resolver
    drops a base_url on provider "auto" and gives a keyless "custom" route no
    credentials, so an endpoint is written only where Hermes keeps its credentials: a
    named provider, or a key referenced by ``model.key_env`` (copied by name). A key
    stored inline in ``model.api_key`` is never copied.
    """
    main = _main_model(cfg)
    identity = profile_default_route(cfg)
    if not main or identity is None:
        return None, "This profile has no default model. Set one with `hermes model` or choose a dedicated compiler; read-only fallback is active."
    route = dict(identity)
    anonymous = identity["provider"] in {"auto", "custom"}
    base_url = str(main.get("base_url") or "").strip()
    key_env = str(main.get("key_env") or main.get("api_key_env") or "").strip()
    unpinned = "Read-only fallback is active until then; a dedicated compiler model also works."
    if not base_url:
        return ({**route, "provider": "auto"} if anonymous else route), None
    if key_env:
        return {**route, "provider": "custom" if anonymous else route["provider"], "base_url": base_url, "key_env": key_env}, None
    if main.get("api_key"):
        return None, ("This profile's endpoint key is stored in `model.api_key`, which AgentsFence never copies. Reference "
                      "it with `model.key_env` (an environment variable name) so the compiler can use it. " + unpinned)
    if anonymous:
        return None, ("This profile's custom endpoint has no key reference, so Hermes could not give the compiler its "
                      "credentials. Set `model.key_env`. " + unpinned)
    return {**route, "base_url": base_url}, None  # a named provider keeps its own credentials


def desired_route(cfg: dict[str, Any], settings: Settings) -> tuple[dict[str, str], str | None]:
    """The compiler route this profile should have, and a note when inherit cannot be honoured."""
    compiler = settings.compiler
    if compiler.mode == SELECTED and compiler.selected_model.strip():
        return {"provider": compiler.selected_provider.strip() or "auto", "model": compiler.selected_model.strip()}, None
    route, note = profile_compiler_route(cfg)
    return (route or {"provider": "auto", "model": ""}), note


def compiler_route(cfg: dict[str, Any]) -> dict[str, Any]:
    route = (cfg.get("auxiliary") or {}).get(AUX_TASK)
    return dict(route) if isinstance(route, dict) else {}


def sync_compiler_route(home: Path, settings: Settings | None = None) -> dict[str, Any] | None:
    """Point Hermes' compiler slot at the model this profile should use; returns the change, if any.

    Called by protect, doctor, every AgentsFence command's sweep, plugin load and
    before each compile, so changing the profile's default model (`hermes model`)
    moves the compiler with it, while a per-chat ``-m`` never does.
    """
    cfg = read_config(home)
    if PLUGIN not in ((cfg.get("plugins") or {}).get("enabled") or []):
        return None
    settings = settings or load_settings(hermes_dir=home)
    want, _note = desired_route(cfg, settings)
    have = compiler_route(cfg)
    if {k: str(v) for k, v in have.items()} == want:
        return None
    cfg.setdefault("auxiliary", {})[AUX_TASK] = want
    write_config(home / "config.yaml", cfg)
    return {"profile": profile_name(home), "from": have, "to": want}


def model_choices(home: Path) -> list[dict[str, str]]:
    """Compiler choices for a profile: its default model, then models its other slots use."""
    cfg = read_config(home)
    default = profile_default_route(cfg)
    label = (f"This profile's default model ({default['model']})" if default
             else "Each chat's model (this profile has no default model)")
    choices = [{"id": INHERIT, "label": label, "provider": default["provider"] if default else "auto",
                "model": default["model"] if default else ""}]
    for name, route in (cfg.get("auxiliary") or {}).items():
        if isinstance(route, dict) and route.get("model") and name != AUX_TASK:
            choice = {"id": name, "label": f"Same model as {name}", "provider": str(route.get("provider") or "auto"),
                      "model": str(route["model"])}
            if all((c["provider"], c["model"]) != (choice["provider"], choice["model"]) for c in choices):
                choices.append(choice)
    return choices


# ---------------------------------------------------------------------------
# Loader and manifest
# ---------------------------------------------------------------------------

_LOADER_ENTRY = '''

def register(ctx: Any) -> None:
    """Hermes entry point for this profile's AgentsFence (written by `agentsfence protect`)."""
    import importlib

    guarded_register(ctx, lambda: importlib.import_module("agentsfence.plugin"))
'''


def loader_source(version: str = __version__, *, accepted_versions: tuple[str, ...] = ()) -> str:
    """The fail-closed loader for a wheel install: the standard-library failsafe plus an entry point.

    It embeds its own copy of failsafe.py, because it must still block tools when
    the agentsfence package is missing from Hermes' environment.
    """
    from . import failsafe

    source = Path(failsafe.__file__).read_text(encoding="utf-8")
    pinned = source.replace("EXPECTED_VERSION: str | None = None", f"EXPECTED_VERSION: str | None = {version!r}", 1)
    if pinned == source:
        raise RuntimeError("failsafe.py no longer declares EXPECTED_VERSION")
    pinned = pinned.replace("ACCEPTED_VERSIONS: tuple[str, ...] = ()",
                            f"ACCEPTED_VERSIONS: tuple[str, ...] = {accepted_versions!r}", 1)
    return pinned + _LOADER_ENTRY


def published_release() -> bool:
    """Whether this AgentsFence came from a package index, so its exact version pin resolves.

    Editable, local-path, wheel-file and VCS installs record a direct URL. Declaring
    such a version as a plugin dependency would fail Hermes' resolver, and Hermes
    then disables the plugin in every profile.
    """
    from importlib.metadata import PackageNotFoundError, distribution

    try:
        return not distribution("agentsfence").read_text("direct_url.json")
    except PackageNotFoundError:
        return False


def plugin_dir(home: Path) -> Path:
    return home / "plugins" / PLUGIN


def is_checkout(home: Path) -> bool:
    """A git or directory install of AgentsFence, which ships its own loader and assets."""
    target = plugin_dir(home)
    return (target / "agentsfence").is_dir() or (target / ".git").exists()


def has_written_loader(home: Path) -> bool:
    return (plugin_dir(home) / ".agentsfence-install.json").is_file()


def install_surfaces(home: Path, *, declare_dependency: bool | None = None, version: str = __version__) -> None:
    """Write the fail-closed loader, the manifest and the desktop assets for Hermes discovery."""
    target = plugin_dir(home)
    manifest = target / "plugin.yaml"
    if manifest.exists() and ((read_yaml(manifest) or {}) if manifest.is_file() else {}).get("name") != PLUGIN:
        raise ValueError(f"Refusing to replace another plugin at {target}")
    if is_checkout(home):
        return  # a checkout already ships its shim, manifest and UI/API assets
    target.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        transaction = json.loads((agentsfence_root() / "transaction.json").read_text(encoding="utf-8"))
        previous = transaction.get("previous_version")
    except (OSError, ValueError):
        pass
    accepted = (previous, version) if isinstance(previous, str) and previous != version else ()
    write_text_atomic(target / "__init__.py", loader_source(version, accepted_versions=accepted))
    # Hermes' package manager builds its environment from every enabled plugin's
    # declared dependencies and disables a plugin whose pin does not resolve, so only
    # a published version can be declared.
    declare = published_release() if declare_dependency is None else declare_dependency
    write_config(manifest, {"name": PLUGIN, "version": version,
                            "description": "Task authorization, setup and protection status for Hermes.",
                            "hooks": HOOKS, **({"python_dependencies": [f"agentsfence=={version}"]} if declare else {})})
    for folder in ("desktop", "dashboard"):
        shutil.copytree(ASSETS / folder, target / folder, dirs_exist_ok=True)
    write_json(target / ".agentsfence-install.json", {"version": version})


def remove_surfaces(home: Path) -> bool:
    """Remove a loader AgentsFence wrote (never a checkout or another plugin)."""
    target = plugin_dir(home)
    if not has_written_loader(home) or is_checkout(home):
        return False
    shutil.rmtree(target)
    return True


def refresh_installed_surfaces(skip: set[Path] | None = None, *, version: str = __version__) -> list[str]:
    """Rewrite the loader and manifest in every profile that has a written one.

    All profiles share one Hermes environment, so they run one AgentsFence version;
    their manifests must declare the same pin, or Hermes' resolver cannot satisfy them
    all. Configuration is never touched.
    """
    refreshed = []
    for name, home in available_profiles().items():
        if (skip and home in skip) or not has_written_loader(home):
            continue
        install_surfaces(home, version=version)
        refreshed.append(name)
    return refreshed


# ---------------------------------------------------------------------------
# Protect / unprotect
# ---------------------------------------------------------------------------


def validate_profile(home: Path) -> None:
    """Parse every file protect rewrites, so a bad one fails before anything is written."""
    if not (home / "config.yaml").is_file():
        raise ValueError(f"No Hermes configuration at {home}; complete Hermes setup first.")
    read_config(home)
    load_settings(hermes_dir=home)


def is_protected(home: Path) -> bool:
    try:
        plugins = read_config(home).get("plugins") or {}
    except ValueError:
        return False
    return PLUGIN in (plugins.get("enabled") or []) and PLUGIN not in (plugins.get("disabled") or [])


def hook_timeout_for(budget: float) -> int:
    return math.ceil(budget / 0.8)


def migrate_legacy(home: Path) -> list[str]:
    """Remove settings older AgentsFence versions wrote that 0.3.0 no longer has."""
    notes = []
    for path in dict.fromkeys([override_path(home), shared_settings_path(home)]):
        data = read_settings_file(path)
        compiler = data.get("compiler")
        if not isinstance(compiler, dict):
            continue
        changed = False
        if str(compiler.get("provider") or "hermes").lower() != "hermes":
            if str(compiler["provider"]).lower() in LEGACY_OFFLINE_PROVIDERS:
                notes.append("Offline rules are no longer a compiler choice; this profile now uses its default model.")
            compiler.pop("provider")
            changed = True
        for key in ("route_source", "profile_model_at_setup", "model", "base_url"):
            if key in compiler:
                compiler.pop(key)
                changed = True
        if changed:
            write_config(path, data)
    env_path = home / ".env"
    if env_path.is_file():
        from dotenv import dotenv_values, unset_key

        values = dotenv_values(env_path)
        for key in ("AGENTSFENCE_COMPILER_PROVIDER", "AGENTSFENCE_COMPILER_MODEL", "AGENTSFENCE_COMPILER_BASE_URL"):
            if key in values:
                unset_key(str(env_path), key)
                notes.append(f"Removed {key} from {env_path}; the compiler is set with `agentsfence settings`.")
    return notes


def protect_profile(home: Path, settings: Settings | None = None) -> dict[str, Any]:
    """Enable AgentsFence in one profile and write its loader and compiler route. Idempotent."""
    validate_profile(home)
    notes = migrate_legacy(home)
    settings = settings or load_settings(hermes_dir=home)
    cfg = read_config(home)
    plugins = cfg.setdefault("plugins", {})
    plugins["enabled"] = list(dict.fromkeys([*(plugins.get("enabled") or []), PLUGIN]))
    plugins["disabled"] = [p for p in plugins.get("disabled", []) if p != PLUGIN]
    entry = plugins.setdefault("entries", {}).setdefault(PLUGIN, {})
    entry["allow_tool_override"] = False
    llm = {k: v for k, v in (entry.get("llm") or {}).items() if k not in _LEGACY_GRANT}
    if llm:
        entry["llm"] = llm
    else:
        entry.pop("llm", None)
    hook = hook_timeout_for(settings.compiler.timeout_seconds)
    plugins["hook_callback_timeout"] = hook
    route, note = desired_route(cfg, settings)
    cfg.setdefault("auxiliary", {})[AUX_TASK] = route
    install_surfaces(home)
    write_config(home / "config.yaml", cfg)
    return {"profile": profile_name(home), "protected": True, "route": route,
            "notes": [*notes, *([note] if note else [])]}


def unprotect_profile(home: Path) -> dict[str, Any]:
    """Disable AgentsFence in one profile and remove everything protect wrote there."""
    cfg = read_config(home)
    plugins = cfg.get("plugins") or {}
    changed = False
    if PLUGIN in (plugins.get("enabled") or []):
        plugins["enabled"] = [p for p in plugins["enabled"] if p != PLUGIN]
        changed = True
    entries = plugins.get("entries") or {}
    if PLUGIN in entries:
        entries.pop(PLUGIN)
        changed = True
    aux = cfg.get("auxiliary") or {}
    if AUX_TASK in aux:
        aux.pop(AUX_TASK)
        changed = True
        if not aux:
            cfg.pop("auxiliary")
    if changed:
        write_config(home / "config.yaml", cfg)
    removed = remove_surfaces(home)
    return {"profile": profile_name(home), "protected": False, "config_changed": changed, "loader_removed": removed}
