#!/usr/bin/env python3
"""Independently validate an IoT light continuous-capture batch."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from collection.runtime.ios.iot_light_capture import ACTION_NAMES


def validate_rows(rows: list[dict[str, Any]], expected_counts: dict[str, dict[str, int]]) -> list[str]:
    errors: list[str] = []
    actual: Counter[tuple[str, str]] = Counter()
    windows: list[tuple[float, float, str]] = []
    for row in rows:
        sample_id = str(row.get("sample_id") or "<missing-id>")
        action = row.get("action")
        if action not in ACTION_NAMES:
            errors.append(f"{sample_id}: unknown action {action!r}")
            continue
        if not row.get("valid"):
            continue
        device_id = str(row.get("device_id") or "")
        actual[(device_id, action)] += 1
        try:
            start = float(row["baseline_start_epoch"])
            command = float(row["command_issued_epoch"])
            result = float(row["action_result_epoch"])
            end = float(row["tail_end_epoch"])
            if not start < command <= result <= end:
                errors.append(f"{sample_id}: invalid timestamp order")
            windows.append((start, end, sample_id))
        except (KeyError, TypeError, ValueError):
            errors.append(f"{sample_id}: missing or invalid timestamps")
        source, target = row.get("source_value"), row.get("target_value")
        confirmed = row.get("confirmed_state") or {}
        tail = row.get("tail_state") or {}
        if not row.get("tail_state_stable"):
            errors.append(f"{sample_id}: valid row has unstable tail")
        if action == "power_on":
            if target != "on" or confirmed.get("power") != "on" or tail.get("power") != "on":
                errors.append(f"{sample_id}: power_on state evidence is inconsistent")
        elif action == "power_off":
            if target != "off" or confirmed.get("power") != "off" or tail.get("power") != "off":
                errors.append(f"{sample_id}: power_off state evidence is inconsistent")
        elif action == "change_color":
            if not source or not target or source == target:
                errors.append(f"{sample_id}: color transition is not a real change")
            if confirmed.get("color") != target or tail.get("color") != target:
                errors.append(f"{sample_id}: color state evidence is inconsistent")
        else:
            try:
                source_n, target_n = int(source), int(target)
            except (TypeError, ValueError):
                errors.append(f"{sample_id}: brightness values are invalid")
                continue
            delta = target_n - source_n
            if (action == "brightness_up" and delta < 20) or (action == "brightness_down" and delta > -20):
                errors.append(f"{sample_id}: brightness direction or minimum delta is invalid")
            for state_name, state in (("confirmed", confirmed), ("tail", tail)):
                value = state.get("brightness")
                if value is None or abs(int(value) - target_n) > 5:
                    errors.append(f"{sample_id}: {state_name} brightness is outside tolerance")
    for device_id, actions in expected_counts.items():
        for action, expected in actions.items():
            found = actual[(device_id, action)]
            if found != int(expected):
                errors.append(f"{device_id}/{action}: expected {expected} valid rows, found {found}")
    windows.sort()
    for previous, current in zip(windows, windows[1:]):
        if current[0] < previous[1]:
            errors.append(f"overlapping valid windows: {previous[2]} and {current[2]}")
    return errors


def validate_plan_requirements(
    rows: list[dict[str, Any]], plan: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    devices = {str(device["id"]): device for device in plan.get("devices", [])}
    for row in rows:
        if not row.get("valid"):
            continue
        sample_id = str(row.get("sample_id") or "<missing-id>")
        device = devices.get(str(row.get("device_id") or ""))
        if device is None:
            errors.append(f"{sample_id}: device is missing from effective plan")
            continue
        if device.get("verify_state_after_reopen") and row.get("reopen_state_confirmed") is not True:
            errors.append(f"{sample_id}: required reopen postcondition is missing or false")
        required_settle = float(device.get("pre_baseline_settle_seconds", 0))
        if required_settle > 0:
            try:
                start = float(row["pre_baseline_settle_start_epoch"])
                end = float(row["pre_baseline_settle_end_epoch"])
                baseline = float(row["baseline_start_epoch"])
            except (KeyError, TypeError, ValueError):
                errors.append(f"{sample_id}: required pre-baseline settle evidence is missing")
                continue
            if end - start + 0.1 < required_settle:
                errors.append(f"{sample_id}: pre-baseline settle is shorter than configured")
            if end > baseline:
                errors.append(f"{sample_id}: pre-baseline settle overlaps the baseline")
    return errors


def validate_run(root: Path) -> dict[str, Any]:
    manifest_path, windows_path = root / "batch_manifest.json", root / "sample_windows.json"
    plan_path = root / "effective_plan.json"
    errors: list[str] = []
    if not manifest_path.is_file():
        return {"valid": False, "errors": ["batch_manifest.json is missing"]}
    if not windows_path.is_file():
        return {"valid": False, "errors": ["sample_windows.json is missing"]}
    if not plan_path.is_file():
        return {"valid": False, "errors": ["effective_plan.json is missing"]}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rows = json.loads(windows_path.read_text(encoding="utf-8-sig"))
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    if manifest.get("status") != "complete":
        errors.append(f"manifest status is {manifest.get('status')!r}, not 'complete'")
    pcap = Path(str(manifest.get("raw_pcap") or ""))
    if not pcap.is_file() or pcap.stat().st_size <= 24:
        errors.append("raw pcap is missing or empty")
    enabled_actions = tuple(manifest.get("enabled_actions") or ACTION_NAMES)
    expected = {
        device_id: {action: int(manifest["target_valid_per_action"]) for action in enabled_actions}
        for device_id in (manifest.get("valid_counts") or {})
    }
    errors.extend(validate_rows(rows, expected))
    errors.extend(validate_plan_requirements(rows, plan))
    manifest_counts = manifest.get("valid_counts") or {}
    for device_id, actions in expected.items():
        if manifest_counts.get(device_id) != actions:
            errors.append(f"manifest valid_counts mismatch for {device_id}")
    return {"valid": not errors, "errors": errors, "samples": len(rows), "pcap_bytes": pcap.stat().st_size if pcap.is_file() else 0}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root")
    args = parser.parse_args()
    result = validate_run(Path(args.run_root).resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
