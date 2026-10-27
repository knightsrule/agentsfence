"""Scheduled Hermes jobs in a profile, and dry runs of their prompts through the compiler.

Each cron run's prompt becomes that run's task policy, and nobody is present to
approve anything outside it. `agentsfence doctor --jobs` shows what each prompt
would authorize.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def scheduled_jobs(home: Path) -> list[dict[str, Any]]:
    """This profile's Hermes cron jobs (``<profile>/cron/jobs.json``); unreadable means none listed."""
    try:
        data = json.loads((home / "cron" / "jobs.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    jobs = data.get("jobs", []) if isinstance(data, dict) else data
    if isinstance(jobs, dict):
        jobs = [dict(v, id=v.get("id", k)) for k, v in jobs.items() if isinstance(v, dict)]
    out = []
    for job in jobs if isinstance(jobs, list) else []:
        if not isinstance(job, dict):
            continue
        schedule = job.get("schedule")
        when = schedule.get("display") or schedule.get("expr") or schedule.get("kind") if isinstance(schedule, dict) else schedule
        enabled = bool(job.get("enabled", True)) and str(job.get("state") or "") != "paused" and not job.get("paused_at")
        out.append({"id": str(job.get("id") or ""), "name": str(job.get("name") or job.get("id") or "unnamed"),
                    "prompt": str(job.get("prompt") or ""), "schedule": str(when or "unscheduled"), "enabled": enabled,
                    "script": bool(job.get("script")) or bool(job.get("no_agent"))})
    return out


def dry_run_jobs(fence: Any, home: Path) -> dict[str, Any]:
    """Compile each job's prompt with the real compiler and describe what it would authorize."""
    from ..compiler import CompileContext, instruction_conflicts
    from ..plugin import _host_hook_deadline
    from ..render import describe_policy

    results = []
    for job in scheduled_jobs(home):
        if not job["prompt"].strip():
            results.append({**job, "authority": None, "note": "No prompt: a script job runs no model, so no task policy applies."})
            continue
        began = time.monotonic()
        compiled = fence.compiler.compile(job["prompt"], CompileContext(available_tools=fence.catalogue_fn(),
                                                                        deadline=_host_hook_deadline()))
        policy = compiled.policy
        results.append({**job, "seconds": round(time.monotonic() - began, 2), "fell_back": compiled.fell_back,
                        "authority": describe_policy(policy), "conflicts": instruction_conflicts(job["prompt"])})
    return {"ok": True, "jobs": results}


def format_jobs(result: dict[str, Any], cron_mode: str) -> str:
    jobs = result.get("jobs")
    if jobs is None:
        return f"Scheduled-job dry run could not run: {result.get('error') or 'no result from Hermes'}"
    if not jobs:
        return "No scheduled jobs in this profile."
    lines = [f"Scheduled jobs: {len(jobs)}. Each run compiles the job's prompt into its task policy. Nobody is present "
             f"to approve, so anything outside it is blocked or decided by approvals.cron_mode ({cron_mode})."]
    for job in jobs:
        state = "enabled" if job["enabled"] else "paused"
        lines.append(f"\n{job['name']} ({job['schedule']}, {state})")
        if job.get("authority") is None:
            lines.append(f"  {job.get('note')}")
            continue
        if job.get("fell_back"):
            lines.append("  Compile FELL BACK to read-only in this dry run; the job would get no write or send authority.")
        lines += ["  " + line for line in str(job["authority"]).splitlines()]
        if job.get("conflicts"):
            lines.append(f"  Its prompt both forbids and asks for {', '.join(job['conflicts'])}; the prohibition applies.")
    return "\n".join(lines)
