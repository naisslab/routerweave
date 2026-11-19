"""Recover operation labels and their evidence level from original collection records."""

import math
from typing import Any


def _time(row: dict, key: str) -> float:
    value = row.get(key)
    if isinstance(value, bool) or value is None:
        raise ValueError(f"missing timestamp {key}")
    stamp = float(value)
    if not math.isfinite(stamp) or stamp <= 0:
        raise ValueError(f"invalid timestamp {key}")
    return stamp


def _recorded_state(row: dict, phase: str, field: str):
    state = row.get(phase + "_state") or {}
    scalar = "observed_state" if phase == "confirmed" else "tail_observed_state"
    return state.get(field, state.get("state", row.get(scalar)))


def _check_target(row: dict, phases: tuple[str, ...]) -> None:
    action = row["action"]
    target = row.get("target_value", row.get("expected_state"))
    if target is None:
        raise ValueError("missing target state")
    if action.startswith(("brightness_", "volume_")):
        field, direction = action.rsplit("_", 1)
        tolerance = float(row.get("volume_tolerance", 5)) if field == "volume" else 5
        delta = float(target) - float(row["source_value"])
        if direction not in {"up", "down"} or not (delta if direction == "up" else -delta) >= 20:
            raise ValueError("invalid direction or insufficient change")
        if not 0 <= tolerance <= 100:
            raise ValueError("invalid tolerance")
        for phase in phases:
            value = _recorded_state(row, phase, field)
            if value is None or not abs(float(value) - float(target)) <= tolerance:
                raise ValueError(f"{phase} {field} differs from target")
        return
    field = {"power_on": "power", "power_off": "power", "lock": "lock",
             "unlock": "lock", "change_color": "color"}.get(action, "state")
    fixed = {"power_on": "on", "power_off": "off", "lock": "locked", "unlock": "unlocked",
             "curtain_open": "open", "curtain_close": "closed", "play": "playing", "pause": "paused",
             "live_view_start": "playing", "live_view_stop": "closed"}
    if action not in fixed and action not in {"fan_speed_up", "fan_speed_down", "change_color"}:
        raise ValueError(f"{action} requires its device-specific evidence reader")
    if action in fixed and target != fixed[action]:
        raise ValueError("target conflicts with operation")
    if action in {"fan_speed_up", "fan_speed_down"}:
        source = str(row.get("source_value", ""))
        destination = str(target)
        if source.startswith("g") and destination.startswith("g"):
            change = int(destination[1:]) - int(source[1:])
            if (action == "fan_speed_up" and change <= 0) or (action == "fan_speed_down" and change >= 0):
                raise ValueError("fan speed changed in the opposite direction")
        else:
            raise ValueError("fan speed requires the device's ordered state mapping")
    if action in {"fan_speed_up", "fan_speed_down", "change_color"} and row.get("source_value") in {None, target}:
        raise ValueError("missing state transition")
    if any(_recorded_state(row, phase, field) != target for phase in phases):
        raise ValueError("observed state differs from target")
    if "reopen_state_confirmed" in row and row["reopen_state_confirmed"] is not True:
        raise ValueError("reopen check failed")


def operation_evidence(row: dict[str, Any], *, contract: str | None = None) -> dict:
    """Read one collection record; a command and a confirmed transition retain distinct labels."""
    if not row.get("device_id") or not row.get("action") or not row.get("sample_id"):
        raise ValueError("missing device, action or sample identity")
    if contract and row.get("state_evidence_contract") not in (None, contract):
        raise ValueError("sample and device evidence contracts disagree")
    contract = contract or row.get("state_evidence_contract")
    label = {key: row[key] for key in ("sample_id", "device_id", "action")}
    if contract == "operator_accepted_periodic_traffic_candidate":
        start = _time(row, "observed_first_packet_epoch")
        end = _time(row, "observed_last_packet_epoch")
        if (end < start or row["action"] != "periodic_sync_candidate"
                or row.get("sensor_sync_verified") is not False
                or row.get("source_capture_integrity_verified") is not False):
            raise ValueError("inconsistent periodic observation")
        return {**label, "evidence": contract, "observed_start": start, "observed_end": end}
    start = _time(row, "baseline_start_epoch")
    command = _time(row, "command_issued_epoch")
    result = _time(row, "action_result_epoch")
    end = _time(row, "tail_end_epoch")
    if not start < command <= result <= end:
        raise ValueError("inconsistent baseline, command, result and tail times")
    if contract in {"operator_reported_physical_action", "operator_accepted_command_traffic"}:
        if row.get("state_confirmed") is not False or int(row.get("direct_unicast_packets_after_command", 0)) <= 0:
            raise ValueError("missing independent device traffic or conflicting state claim")
        if contract == "operator_reported_physical_action":
            if row["action"] != "doorbell_press" or row.get("physical_action_reported") is not True:
                raise ValueError("missing physical action annotation")
        elif row.get("command_traffic_verified") is not True:
            raise ValueError("missing verified command traffic")
    else:
        if row.get("valid") is not True or row.get("state_confirmed") is False:
            raise ValueError("collector did not confirm this operation")
        if contract == "confirmed_and_tail_stable":
            if row.get("tail_state_stable") is not True:
                raise ValueError("missing stable tail")
            _check_target(row, ("confirmed", "tail"))
        elif contract == "action_result_confirmed_only":
            if row.get("state_confirmed") is not True or row.get("reason") != "state_confirmed":
                raise ValueError("missing action-result confirmation")
            _check_target(row, ("confirmed",))
        else:
            raise ValueError("missing or unsupported operation evidence contract")
    return {**label, "evidence": contract, "baseline_start_epoch": start,
            "command_issued_epoch": command, "action_result_epoch": result, "tail_end_epoch": end}
