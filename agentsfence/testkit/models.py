"""Pick the chat model for `agentsfence test`'s live run: the least capable one this profile can reach.

A weak model follows injected text more readily, which is the point of the live run.
Runs inside a Hermes process for the profile (``hermes -p NAME agentsfence probe
models``), because only Hermes knows which providers have credentials. Free models
come first; otherwise the cheapest priced one, with the projected cost of the run.
"""

from __future__ import annotations

import re
from typing import Any

#: Rough size of one live scenario: tool schemas, system prompt and injected content, a few turns.
PROMPT_TOKENS, COMPLETION_TOKENS, TURNS = 6000, 400, 3
LIVE_SCENARIOS = 6
_NOT_CHAT = re.compile(r"embed|whisper|tts|speech|transcri|image|dall-?e|flux|diffusion|video|sora|rerank|moderation|guard|"
                       r"audio|realtime|search-preview|ocr", re.IGNORECASE)


def _price(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def projected_cost(prompt: float, completion: float, scenarios: int = LIVE_SCENARIOS) -> float:
    return round(scenarios * TURNS * (prompt * PROMPT_TOKENS + completion * COMPLETION_TOKENS), 4)


def candidates() -> list[dict[str, Any]]:
    """Chat models on providers with credentials, with per-token prices where Hermes knows them."""
    from hermes_cli.models import list_available_providers, provider_model_ids

    try:
        from hermes_cli.models_pricing import get_pricing_for_provider
    except ImportError:
        get_pricing_for_provider = None
    found: list[dict[str, Any]] = []
    for provider in list_available_providers():
        pid = str(provider.get("id") or "")
        if not provider.get("authenticated") or pid in ("", "custom"):
            continue
        try:
            models = provider_model_ids(pid)
        except Exception:
            continue
        try:
            pricing = get_pricing_for_provider(pid) if get_pricing_for_provider else {}
        except Exception:
            pricing = {}
        for model in models:
            if not isinstance(model, str) or _NOT_CHAT.search(model):
                continue
            price = pricing.get(model) or {}
            prompt, completion = _price(price.get("prompt")), _price(price.get("completion"))
            free = model.endswith(":free") or (bool(price) and prompt == 0 and completion == 0)
            found.append({"provider": pid, "model": model, "free": free, "prompt": prompt, "completion": completion})
    return found


def choose(found: list[dict[str, Any]]) -> dict[str, Any]:
    """``{"provider", "model", "free", "cost", "why"}``, or ``{"error"}`` when nothing fits."""
    free = [c for c in found if c["free"]]
    if free:
        pick = sorted(free, key=lambda c: (c["provider"] != "openrouter", c["model"]))[0]
        return {**pick, "cost": 0.0, "why": "free model"}
    priced = [c for c in found if c["prompt"] is not None and c["completion"] is not None]
    if priced:
        pick = min(priced, key=lambda c: projected_cost(c["prompt"], c["completion"]))
        cost = projected_cost(pick["prompt"], pick["completion"])
        return {**pick, "cost": cost, "why": f"cheapest model Hermes can reach; projected cost about ${cost:.4f}"}
    if found:
        return {"error": "Hermes knows no free model and no prices for this profile's models. Name one with --model."}
    return {"error": "No provider with credentials lists any chat model. Name one with --model, or skip the live run "
                     "with --no-live."}


def probe() -> dict[str, Any]:
    try:
        found = candidates()
    except Exception as exc:
        return {"ok": False, "error": f"Hermes could not list models: {type(exc).__name__}: {exc}"}
    choice = choose(found)
    return {"ok": "error" not in choice, "choice": choice, "candidates": len(found), **({"error": choice["error"]} if "error" in choice else {})}
