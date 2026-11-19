#!/usr/bin/env python3
"""Verify device traffic in IoT command windows."""

from __future__ import annotations


import ipaddress
import json

import struct

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from collection.runtime.errors import DemoError
from collection.runtime.capture.pcap import pcap_format, pcap_timestamp


def supports_command_traffic(device: dict[str, Any]) -> bool:
    if device.get("command_evidence") == "native_toggle_selection":
        actions = device.get("actions", [])
        return (device.get("navigation_mode") == "semantic_detail"
                and bool(device.get("control_element_name"))
                and bool(device.get("state_element_name"))
                and bool(actions)
                and all((a.get("name"), a.get("from"), a.get("to")) in {
                    ("power_on", "off", "on"), ("power_off", "on", "off")}
                        for a in actions))
    if device.get("device_type") == "smart_curtain":
        return True
    binding = device.get("detail_binding", {})
    actions = device.get("actions", [])
    controls = binding.get("controls", {})
    levels = {"Low": 1, "Medium": 2, "High": 3}
    return (device.get("device_type") == "air_purifier"
            and device.get("command_evidence") == "native_option_selection"
            and bool(binding.get("menu_open_selector"))
            and bool(binding.get("menu_condition_selector"))
            and bool(actions)
            and all(a.get("name") in {"fan_speed_up", "fan_speed_down"}
                    and a.get("from") != a.get("to")
                    and a.get("from") in controls and a.get("to") in controls
                    and a.get("from") in levels and a.get("to") in levels
                    and ((levels[a["to"]] > levels[a["from"]]) == (a["name"] == "fan_speed_up"))
                    and all(isinstance(controls[v], dict) and controls[v].get("type") == "XCUIElementTypeOther"
                            and controls[v].get("name") == "actionTile" and controls[v].get("label") == v
                            for v in (a["from"], a["to"]))
                    for a in actions))


def review_command_traffic(run_root: Path) -> dict[str, Any]:
    """Recompute command-window traffic without asserting a physical state change."""
    manifest = read_json(run_root / "batch_manifest.json")
    rows = read_json(run_root / "sample_windows.json")
    plan = read_json(run_root / "effective_plan.json")
    if plan.get("acceptance_mode") != "command_traffic":
        raise DemoError("Command-traffic review requires an explicitly selected plan contract")
    devices = {d["id"]: d for d in plan["devices"]}
    if any(not supports_command_traffic(d) for d in devices.values()):
        raise DemoError("Command-traffic acceptance requires explicit supported native controls")
    source = Path(manifest["raw_pcap"])
    from collection.runtime.artifacts import resolve_artifact_path
    from collection.runtime.run_retention import _workspace
    workspace = _workspace(run_root.absolute()) or Path.cwd()
    if not source.is_absolute() and source.parts[0] not in {'runs', 'datasets'}:
        source = run_root / source
    source = resolve_artifact_path(source, workspace=workspace)
    raw = source.read_bytes()
    endian, scale = pcap_format(raw[:24])
    if struct.unpack(endian + "I", raw[20:24])[0] != 1:
        raise DemoError("Command-traffic review requires Ethernet PCAP records")
    packets = []
    for header, frame in _iter_pcap_records(raw, endian, source):
        # IPv4/IPv6 unicast only; ARP and multicast discovery cannot qualify.
        if len(frame) < 14 or frame[0] & 1 or frame[12:14] not in (b"\x08\x00", b"\x86\xdd"):
            continue
        packets.append((pcap_timestamp(endian, scale, header), frame_endpoints(frame)))
    counts: Counter[tuple[str, str]] = Counter()
    samples = []
    seen_ids: set[str] = set()
    windows: list[tuple[float, float]] = []
    integrity_errors: list[str] = []
    for row in rows:
        device = devices[row["device_id"]]
        valid, reason, total = False, "command_not_completed", 0
        if row.get("command_capture_complete") and not row.get("authentication_required"):
            try:
                start, command, end = (float(row[k]) for k in ("baseline_start_epoch", "command_issued_epoch", "tail_end_epoch"))
                if not start < command < end or command - start < 4.9 or end - command < 29.9:
                    raise ValueError("command window is too short or unordered")
                if row["sample_id"] in seen_ids or any(start < old_end and old_start < end for old_start, old_end in windows):
                    integrity_errors.append(row["sample_id"])
                    raise ValueError("duplicate sample or overlapping command windows")
                action = next((a for a in device["actions"] if a["name"] == row["action"]), None)
                if action is None:
                    raise ValueError("action is absent from the effective plan")
                if row.get("source_value") != action["from"] or row.get("target_value") != action["to"]:
                    raise ValueError("command labels disagree with the effective plan")
                if device.get("command_evidence") == "native_toggle_selection":
                    if (row.get("source_state_confirmed") is not True
                            or row.get("observed_before") != action["from"]
                            or row.get("selected_native_control") != {"name": device["control_element_name"]}
                            or row.get("gesture_type") != "tap"
                            or float(row.get("gesture_start_epoch", -1)) != command
                            or not command <= float(row.get("gesture_complete_epoch", -1)) < end):
                        raise ValueError("native toggle source or command evidence is missing")
                if device.get("command_evidence") == "native_option_selection":
                    selector = device["detail_binding"]["controls"][action["to"]]
                    selected = row.get("selected_native_control", {})
                    source_selected = row.get("source_option_selection", {}).get("selected_native_control", {})
                    source_selector = device["detail_binding"]["controls"][action["from"]]
                    if (not row.get("selection_sheet_dismissed") or not row.get("source_selection_sheet_dismissed")
                            or not source_selected or any(source_selected.get(k) != v for k,v in source_selector.items() if k in {"type","name","label"})
                            or not selected or any(selected.get(k) != v for k, v in selector.items() if k in {"type", "name", "label"})):
                        raise ValueError("native option selection evidence is missing or mismatched")
                seen_ids.add(row["sample_id"])
                windows.append((start, end))
                mac, ip = str(device["mac"]).lower(), str(device["ip"])
                total = sum(command <= epoch < end and mac in macs and ip in ips
                            for epoch, (macs, ips) in packets)
                valid, reason = total > 0, "direct_device_unicast_after_command" if total else "no_direct_device_unicast_after_command"
            except (KeyError, TypeError, ValueError) as exc:
                reason = str(exc)
        if valid:
            counts[(row["device_id"], row["action"])] += 1
        samples.append({"sample_id": row["sample_id"], "accepted": valid,
                        "direct_unicast_packets_after_command": total, "reason": reason})
    expected = {(d["id"], a["name"]): int(plan["target_valid_per_action"])
                for d in devices.values() for a in d["actions"]}
    return {"contract": "operator_accepted_command_traffic", "state_confirmed": False,
            "valid": not integrity_errors and all(counts[k] == n for k, n in expected.items()),
            "integrity_errors": integrity_errors,
            "pcap_sha256": hashlib.sha256(raw).hexdigest(), "pcap_bytes": len(raw),
            "samples": samples,
            "accepted_counts": {d: {a: counts[(d, a)] for dd, a in expected if dd == d} for d in devices}}


MODEL_COLUMNS = (
    "device_ip", "device_mac", "traffic_scope", "traffic_filter_ip",
    "traffic_filter_mac", "device_related_pcap_path",
    "device_related_packet_count", "device_related_pcap_bytes",
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _iter_pcap_records(raw: bytes, endian: str, source: Path) -> Iterator[tuple[bytes, bytes]]:
    """Yield ``(record header, frame)`` pairs without copying the whole pcap."""
    cursor = 24
    while cursor < len(raw):
        if cursor + 16 > len(raw):
            raise DemoError(f"Truncated PCAP record header: {source}")
        header = raw[cursor:cursor + 16]
        incl_len = struct.unpack(endian + "I", header[8:12])[0]
        end = cursor + 16 + incl_len
        if end > len(raw):
            raise DemoError(f"Truncated PCAP record data: {source}")
        yield header, raw[cursor + 16:end]
        cursor = end


def frame_endpoints(frame: bytes) -> tuple[list[str], list[str]]:
    """Return the MAC and IP values a frame carries, in both directions."""
    if len(frame) < 14:
        return [], []
    macs = [_format_mac(frame[0:6]), _format_mac(frame[6:12])]
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    ips: list[str] = []
    if ether_type == 0x0800 and len(frame) >= offset + 20:
        ips = [
            str(ipaddress.IPv4Address(frame[offset + 12:offset + 16])),
            str(ipaddress.IPv4Address(frame[offset + 16:offset + 20])),
        ]
    elif ether_type == 0x86DD and len(frame) >= offset + 40:
        ips = [
            str(ipaddress.IPv6Address(frame[offset + 8:offset + 24])),
            str(ipaddress.IPv6Address(frame[offset + 24:offset + 40])),
        ]
    elif ether_type == 0x0806 and len(frame) >= offset + 28:
        ips = [
            str(ipaddress.IPv4Address(frame[offset + 14:offset + 18])),
            str(ipaddress.IPv4Address(frame[offset + 24:offset + 28])),
        ]
    return macs, ips


def _format_mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)
