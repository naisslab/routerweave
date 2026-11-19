"""Redacted intervention evidence; no alternative task runner or input engine."""
from __future__ import annotations

import json
import time
from pathlib import Path


def write_intervention(run_dir: Path, *, error_type: str | None = None) -> dict:
    observations, failures = [], []
    for path in sorted((run_dir / "semantic").glob("*/events.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("event_type") == "windows_observation":
                state = event["payload"].get("state", {})
                observations.append({key: state[key] for key in (
                    "allowed", "blocked", "blocker_kind", "error_type", "present_popups",
                    "benign_popups", "media_present", "playing", "media_advancing",
                    "content_page", "feed_ready", "detail_open") if key in state})
            elif event.get("event_type") == "interruption_finished":
                result = event["payload"]["result"]
                failures.append({key: result.get(key) for key in ("rule_id", "kind", "status")})
    protected = any(o.get("blocker_kind") == "authentication_or_captcha" for o in observations[-3:])
    report = {"schema_version": "windows-intervention-v1", "status": "needs_attention",
              "created_epoch": time.time(), "run": run_dir.name, "error_type": error_type,
              "handler": "operator" if protected else "agent",
              "last_observations": observations[-3:], "interruptions": failures[-5:],
              "resume_policy": "inspect_then_new_run", "replay_uncertain_input": False,
              "automatic_agent_invocation": False}
    path = run_dir / "intervention.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
    return report
