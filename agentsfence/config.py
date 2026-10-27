"""Configuration loading.

Defaults ship in ``policies/defaults.yaml``. Settings shared by every profile
(``<Hermes root>/agentsfence/settings.yaml``) are deep-merged on top, then the
profile's own overrides (``$AGENTSFENCE_HOME/config.yaml``; maps merge, lists
replace), then a small set of environment variables override individual keys.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field

from .models import RiskClass, Verdict

DEFAULTS_PATH = Path(__file__).resolve().parent / "policies" / "defaults.yaml"


def hermes_home() -> Path:
    try:  # inside a Hermes process this honours profiles
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()


def agentsfence_home() -> Path:
    hh = hermes_home()
    env = profile_environment(hh).get("AGENTSFENCE_HOME")
    return Path(env).expanduser() if env else hh / "agentsfence"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _truthy(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


#: Compiler modes: "inherit" follows the profile's default model; "selected" is a dedicated model.
INHERIT, SELECTED = "inherit", "selected"
#: Providers written by AgentsFence before 0.3.0 for offline rules; migrated to inherit.
LEGACY_OFFLINE_PROVIDERS = frozenset({"rules", "static", "offline"})


class CompilerSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    #: Always "hermes": Hermes routes and authenticates every compile. Another value is
    #: a configuration from an older AgentsFence that `protect` migrates.
    provider: str = "hermes"
    mode: str = INHERIT
    #: The dedicated compiler model for mode "selected", routed and authenticated by Hermes.
    selected_model: str = ""
    selected_provider: str = "auto"
    timeout_seconds: float = 30
    max_concurrent_requests: int = Field(default=4, ge=1, le=32)
    max_request_chars: int = 8000
    stages: int = Field(default=1, ge=1, le=2)
    require_sensitive_approval: bool = True
    followup: str = "amend"
    hermes_task: str | None = None


class EvaluationSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    unauthorized: dict[RiskClass, Verdict]
    trust_inferred_reads: bool = True
    missing_policy: str = "fallback"
    strict_yolo: bool = False


class ExfilSettings(BaseModel):
    enabled: bool = True
    max_query_chars: int = 200
    max_segment_chars: int = 120
    max_token_chars: int = 64


class GuardSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    require_bound_recipients: bool = True
    exfil_url: ExfilSettings = Field(default_factory=ExfilSettings)
    protected_paths: list[str] = Field(default_factory=list)
    secret_paths: list[str] = Field(default_factory=list)


class PolicySettings(BaseModel):
    ttl_hours: float | None = 12
    inject_summary: bool = True


class AuditSettings(BaseModel):
    enabled: bool = True
    keep_keys: list[str] = Field(default_factory=list)
    max_value_chars: int = 200
    #: Rotate audit.jsonl past this size; rotated files older than retention_days are removed.
    max_bytes: int = Field(default=10_000_000, ge=100_000)
    retention_days: int = Field(default=90, ge=1)


class Settings(BaseModel):
    """Fully-resolved configuration."""

    model_config = ConfigDict(extra="ignore")

    raw: dict[str, Any]
    compiler: CompilerSettings
    evaluation: EvaluationSettings
    guards: GuardSettings
    policy: PolicySettings
    audit: AuditSettings
    fallback_policy: dict[str, Any]
    home: Path

    @property
    def risk_config(self) -> dict[str, Any]:
        keys = ("tools", "patterns", "domains", "verbs", "strong_verbs", "arg_hints")
        return {k: self.raw.get(k) or {} for k in keys}


def root_of(home: Path) -> Path:
    """The Hermes root that holds every profile: a profile home's grandparent, else the home itself."""
    return home.parent.parent if home.parent.name == "profiles" else home


def shared_settings_path(home: Path | None = None) -> Path:
    """Settings every profile shares: ``<Hermes root>/agentsfence/settings.yaml``."""
    root = root_of(home or hermes_home())
    configured = profile_environment(root).get("AGENTSFENCE_HOME")
    return (Path(configured).expanduser() if configured else root / "agentsfence") / "settings.yaml"


def profile_environment(home: Path) -> dict[str, str]:
    """Resolve a profile's dotenv without changing the process or another profile."""
    env = dict(os.environ)
    env.update({k: v for k, v in dotenv_values(home / ".env", interpolate=False).items() if v is not None})
    return env


def read_yaml(path: Path) -> Any:
    """Parse an operator-edited YAML file; syntax errors become ValueError naming it."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Cannot parse {path}: {str(exc).splitlines()[0]}") from exc


def load_settings(config_path: Path | None = None, *, overrides: dict[str, Any] | None = None,
                  hermes_dir: Path | None = None) -> Settings:
    with DEFAULTS_PATH.open("r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    hh = hermes_dir or hermes_home()
    resolved_env = profile_environment(hh)
    home = Path(resolved_env.get("AGENTSFENCE_HOME", str(hh / "agentsfence"))).expanduser()
    user_path = config_path or Path(resolved_env.get("AGENTSFENCE_CONFIG", home / "config.yaml")).expanduser()
    shared = shared_settings_path(hh)
    for path in dict.fromkeys([shared, user_path]):  # the default profile's overrides may be the shared file
        if path.is_file():
            user = read_yaml(path) or {}
            if not isinstance(user, dict):
                raise ValueError(f"{path} must contain a YAML mapping")
            raw = deep_merge(raw, user)
    if overrides:
        raw = deep_merge(raw, overrides)
    compiler = raw.get("compiler") or {}
    if isinstance(compiler, dict) and "mode" not in compiler and compiler.get("route_source") == "selected":
        compiler["mode"] = SELECTED  # recorded by AgentsFence before 0.3.0

    env_map = {
        "AGENTSFENCE_FOLLOWUP": ("compiler", "followup"),
        "AGENTSFENCE_MISSING_POLICY": ("evaluation", "missing_policy"),
    }
    for env, (section, key) in env_map.items():
        if resolved_env.get(env):
            raw.setdefault(section, {})[key] = resolved_env[env]
    strict = _truthy(resolved_env.get("AGENTSFENCE_STRICT_YOLO"))
    if strict is not None:
        raw.setdefault("evaluation", {})["strict_yolo"] = strict

    return Settings(
        raw=raw,
        compiler=CompilerSettings(**(raw.get("compiler") or {})),
        evaluation=EvaluationSettings(**(raw.get("evaluation") or {})),
        guards=GuardSettings(**(raw.get("guards") or {})),
        policy=PolicySettings(**(raw.get("policy") or {})),
        audit=AuditSettings(**(raw.get("audit") or {})),
        fallback_policy=raw.get("fallback_policy") or {},
        home=home,
    )
