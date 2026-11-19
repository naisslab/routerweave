"""Reconstruct collection windows from the controller event stream."""

from datetime import datetime
import json
from pathlib import Path
from typing import Any


def _epoch(timestamp: str) -> float:
    value = datetime.fromisoformat(timestamp)
    if value.utcoffset() is None:
        raise ValueError("event timestamp requires a UTC offset")
    return value.timestamp()


def network_windows_from_mobile_events(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    started: dict[str, Any] | None = None
    finished: dict[str, Any] | None = None
    sustain_started: dict[str, dict[str, Any]] = {}
    sustain_windows: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for raw in source.read_text(encoding="utf-8-sig").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        if row.get("event_type") == "playbook_started":
            if started is not None:
                raise ValueError("expected a single playbook per event log")
            started = row
        elif row.get("event_type") == "sustain_started":
            step_id = str(row.get("payload", {}).get("step_id") or "")
            if step_id:
                sustain_started[step_id] = row
        elif row.get("event_type") == "sustain_finished":
            step_id = str(row.get("payload", {}).get("step_id") or "")
            window_start = sustain_started.pop(step_id, None)
            if step_id and window_start is not None:
                sustain_windows.append((step_id, window_start, row))
        elif row.get("event_type") == "playbook_finished":
            if finished is not None or started is None:
                raise ValueError("unexpected playbook finish")
            finished = row
    if started is None or finished is None:
        return []
    start_epoch = _epoch(started["recorded_at"])
    end_epoch = _epoch(finished["recorded_at"])
    if end_epoch < start_epoch:
        raise ValueError("playbook end precedes its start")
    result = finished.get("payload", {}).get("result", {})
    task_success = result.get("outcome") == "success"
    task_window = {
        "id": "mobile_control_task",
        "wait_action_index": 0,
        "source": "mobile_control/events.jsonl",
        "task_success": task_success,
        "actual_resolution": "mobile_control_playbook_started_to_finished",
        "actual": {
            "start_epoch": start_epoch,
            "end_epoch": end_epoch,
            "duration_s": round(end_epoch - start_epoch, 3),
            "start_iso": started["recorded_at"],
            "end_iso": finished["recorded_at"],
            "playbook_id": result.get("playbook_id"),
            "outcome": result.get("outcome"),
        },
    }
    if sustain_windows:
        # Browsing keeps navigation traffic as well as the verified page interval.
        windows: list[dict[str, Any]] = (
            [task_window] if result.get("playbook_id") == "browsing-session" else []
        )
        for index, (step_id, window_start, window_finish) in enumerate(sustain_windows, start=1):
            from_playbook_start = (
                window_start.get("payload", {}).get("budget_origin")
                == "playbook_start"
            )
            effective_window_start = started if from_playbook_start else window_start
            window_start_epoch = _epoch(effective_window_start["recorded_at"])
            window_end_epoch = _epoch(window_finish["recorded_at"])
            sustain_start_epoch = _epoch(window_start["recorded_at"])
            if not start_epoch <= sustain_start_epoch <= window_end_epoch <= end_epoch:
                raise ValueError("sustain window falls outside its playbook")
            sustain_result = window_finish.get("payload", {}).get("result", {})
            windows.append(
                {
                    "id": f"mobile_control_{step_id}_{index}",
                    "wait_action_index": len(windows),
                    "source": "mobile_control/events.jsonl",
                    "task_success": task_success
                    and sustain_result.get("outcome") == "success",
                    "actual_resolution": (
                        "mobile_control_playbook_budget_verified_state"
                        if from_playbook_start
                        else "mobile_control_sustained_verified_state"
                    ),
                    "actual": {
                        "start_epoch": window_start_epoch,
                        "end_epoch": window_end_epoch,
                        "duration_s": round(window_end_epoch - window_start_epoch, 3),
                        "start_iso": effective_window_start["recorded_at"],
                        "end_iso": window_finish["recorded_at"],
                        "sustain_start_iso": window_start["recorded_at"],
                        "budget_origin": window_start.get("payload", {}).get(
                            "budget_origin", "sustain_start"
                        ),
                        "budget_elapsed_before_sustain_seconds": window_start.get(
                            "payload", {}
                        ).get("budget_elapsed_before_sustain_seconds", 0.0),
                        "playbook_id": result.get("playbook_id"),
                        "step_id": step_id,
                        "outcome": sustain_result.get("outcome"),
                        "checks": sustain_result.get("checks"),
                        "recoveries": sustain_result.get("recoveries"),
                    },
                }
            )
        return windows
    return [task_window]

def verified_activity_intervals(path: str | Path) -> list[tuple[float, float]]:
    """Use the actual successful sustain interval for activity labels."""
    intervals = []
    for window in network_windows_from_mobile_events(path):
        timing = window["actual"]
        if window["task_success"] and timing.get("sustain_start_iso"):
            start = _epoch(timing["sustain_start_iso"])
            if start < timing["end_epoch"]:
                intervals.append((start, timing["end_epoch"]))
    return intervals
