"""Temporal Android UID attribution for router-side packet metadata."""

from __future__ import annotations

import csv
from .export import write_json, PACKET_COLUMNS
from .evidence import AttributionResult
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .pcap import iter_decoded_packets, packet_local_remote, verified_network_window_id


def attribute_android_capture(
    *,
    pcap_path: str | Path,
    samples_path: str | Path,
    uid_packages: dict[int, list[str]],
    target_package: str,
    target_uid: int,
    phone_ip: str,
    network_windows: list[dict[str, Any]],
    out_dir: str | Path,
    max_sample_distance_seconds: float = 3.0,
) -> AttributionResult:
    """Attribute packets and export target-app rows using time-near socket evidence."""

    if max_sample_distance_seconds <= 0:
        raise ValueError("max_sample_distance_seconds must be positive")
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    attribution_path = destination / "packet_attribution.jsonl"
    summary_path = destination / "packet_attribution_summary.json"
    windows_summary_path = destination / "packet_attribution_windows_summary.json"
    app_dir = destination / "app_attributed_packets"
    app_dir.mkdir(parents=True, exist_ok=True)
    safe_package = re.sub(r"[^A-Za-z0-9_.-]+", "_", target_package)
    target_csv_path = app_dir / f"{safe_package}.csv"
    export_manifest_path = destination / "app_attributed_packets_manifest.json"

    samples = _load_socket_samples(Path(samples_path))
    candidates_by_key = _socket_candidates(samples)
    shared_uid_packages = uid_packages.get(target_uid, [])
    unique_target_uid = shared_uid_packages == [target_package]
    windows_by_id = {str(window.get("id")): window for window in network_windows}
    verified_window_count = sum(
        1 for window in network_windows if window.get("task_success") is True
    )
    window_counts = {
        window_id: {"id": window_id, "packets": 0, "bytes": 0, "target_packets": 0, "target_bytes": 0}
        for window_id in windows_by_id
    }
    by_uid: dict[int, dict[str, Any]] = {}
    decoded_packets = 0
    phone_packets = 0
    matched_packets = 0
    target_packets = 0
    target_bytes = 0
    target_window_packets = 0

    with attribution_path.open("x", encoding="utf-8", newline="\n") as attribution_handle, target_csv_path.open(
        "x", encoding="utf-8", newline=""
    ) as csv_handle:
        writer = csv.DictWriter(
            csv_handle,
            fieldnames=PACKET_COLUMNS,
        )
        writer.writeheader()
        for packet in iter_decoded_packets(pcap_path):
            decoded_packets += 1
            local = packet_local_remote(packet, phone_ip)
            if local is None:
                continue
            phone_packets += 1
            local_port, _remote_ip, _remote_port, direction = local
            packet_epoch = float(packet["ts_epoch"])
            candidates = candidates_by_key.get((str(packet["proto"]), local_port), ())
            match, basis, sample_distance = _best_match(
                candidates,
                packet,
                phone_ip,
                packet_epoch,
                max_sample_distance_seconds,
            )
            window_id = verified_network_window_id(packet_epoch, network_windows)
            row = {
                **packet,
                "direction": direction,
                "network_window_id": window_id,
                "uid": None,
                "packages": [],
                "match_basis": None,
                "confidence": "unmatched",
                "socket_sample_recorded_at": None,
                "socket_sample_distance_seconds": None,
            }
            if match is not None:
                uid = int(match["uid"])
                packages = uid_packages.get(uid, [])
                confidence = "high" if basis == "exact_5tuple" else "medium"
                row.update(
                    {
                        "uid": uid,
                        "packages": packages,
                        "match_basis": basis,
                        "confidence": confidence,
                        "socket_sample_recorded_at": match.get("sample_recorded_at"),
                        "socket_sample_distance_seconds": round(sample_distance, 6),
                    }
                )
                matched_packets += 1
                uid_bucket = by_uid.setdefault(
                    uid,
                    {"uid": uid, "packages": packages, "packets": 0, "bytes": 0},
                )
                uid_bucket["packets"] += 1
                uid_bucket["bytes"] += int(packet["length"])
                if uid == target_uid and unique_target_uid:
                    target_packets += 1
                    target_bytes += int(packet["length"])
                    if window_id is not None:
                        target_window_packets += 1
                    writer.writerow(
                        {
                            "time": packet["ts"],
                            "stream_id": packet["index"],
                            "protocol": packet["proto"],
                            "source_address": packet["src_ip"],
                            "source_port": packet["src_port"],
                            "destination_address": packet["dst_ip"],
                            "destination_port": packet["dst_port"],
                            "length": packet["length"],
                            "certificate": "",
                            "app": target_package,
                            "network_window_id": window_id or "",
                            "attribution_confidence": confidence,
                        }
                    )
            if window_id in window_counts:
                bucket = window_counts[window_id]
                bucket["packets"] += 1
                bucket["bytes"] += int(packet["length"])
                if row["uid"] == target_uid and unique_target_uid:
                    bucket["target_packets"] += 1
                    bucket["target_bytes"] += int(packet["length"])
            attribution_handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            attribution_handle.write("\n")

    window_rows = list(window_counts.values())
    ready = bool(decoded_packets > 0 and phone_packets > 0 and samples)
    formal_ready = bool(
        ready
        and unique_target_uid
        and target_packets > 0
        and target_window_packets > 0
        and verified_window_count > 0
    )
    formal_reasons: list[str] = []
    if not unique_target_uid:
        formal_reasons.append("target UID is shared by multiple packages")
    if target_packets <= 0:
        formal_reasons.append("no packets were attributed to the target UID")
    if verified_window_count <= 0:
        formal_reasons.append("no successful verified task window is available")
    elif target_window_packets <= 0:
        formal_reasons.append("no target UID packets fall inside a verified task window")

    metrics = {
        "pcap_packets_decoded": decoded_packets,
        "phone_packets": phone_packets,
        "matched_packets": matched_packets,
        "unmatched_packets": phone_packets - matched_packets,
        "socket_samples": len(samples),
        "max_sample_distance_seconds": max_sample_distance_seconds,
        "target_package": target_package,
        "target_uid": target_uid,
        "target_uid_packages": shared_uid_packages,
        "target_uid_unique": unique_target_uid,
        "target_packets": target_packets,
        "target_bytes": target_bytes,
        "target_window_packets": target_window_packets,
        "verified_window_count": verified_window_count,
        "by_uid": sorted(by_uid.values(), key=lambda row: int(row["bytes"]), reverse=True),
        "by_network_window": window_rows,
        "formal_readiness_failures": formal_reasons,
    }
    write_json(summary_path, metrics)
    write_json(windows_summary_path, window_rows)
    write_json(
        export_manifest_path,
        {
            "schema_version": 1,
            "target_package": target_package,
            "target_uid": target_uid,
            "rows_written": target_packets,
            "target_uid_unique": unique_target_uid,
            "file": str(target_csv_path),
        },
    )
    artifacts = {
        "packet_attribution": str(attribution_path),
        "packet_attribution_summary": str(summary_path),
        "packet_attribution_windows_summary": str(windows_summary_path),
        "app_attributed_packets": str(target_csv_path),
        "app_attributed_packets_manifest": str(export_manifest_path),
    }
    return AttributionResult(ready, formal_ready, artifacts, metrics)


def _load_socket_samples(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid socket sample JSON at line {line_number}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _socket_candidates(
    samples: Iterable[dict[str, Any]],
) -> dict[tuple[str, int], list[dict[str, Any]]]:
    indexed: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for sample in samples:
        recorded_at = sample.get("recorded_at")
        try:
            stamp = datetime.fromisoformat(str(recorded_at))
            if stamp.utcoffset() is None:
                continue
            sample_epoch = stamp.timestamp()
        except (TypeError, ValueError):
            continue
        entries = sample.get("entries")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            copied = dict(entry)
            copied["sample_recorded_at"] = recorded_at
            copied["sample_epoch"] = sample_epoch
            try:
                key = (str(copied["proto"]), int(copied["local_port"]))
            except (KeyError, TypeError, ValueError):
                continue
            indexed.setdefault(key, []).append(copied)
    return indexed


def _best_match(
    candidates: Iterable[dict[str, Any]],
    packet: dict[str, Any],
    phone_ip: str,
    packet_epoch: float,
    max_distance: float,
) -> tuple[dict[str, Any] | None, str | None, float]:
    eligible: list[tuple[int, float, dict[str, Any], str]] = []
    for entry in candidates:
        distance = abs(packet_epoch - float(entry["sample_epoch"]))
        if distance > max_distance:
            continue
        basis = _match_basis(entry, packet, phone_ip)
        if basis is None:
            continue
        priority = 0 if basis == "exact_5tuple" else 1
        eligible.append((priority, distance, entry, basis))
    if not eligible:
        return None, None, 0.0
    best_rank = min((priority, distance) for priority, distance, _, _ in eligible)
    best = [item for item in eligible if item[:2] == best_rank]
    if len({item[2]["uid"] for item in best}) != 1:
        return None, None, 0.0
    _, distance, entry, basis = best[0]
    return entry, basis, distance


def _match_basis(
    entry: dict[str, Any], packet: dict[str, Any], phone_ip: str
) -> str | None:
    local = packet_local_remote(packet, phone_ip)
    if local is None:
        return None
    local_port, remote_ip, remote_port, _direction = local
    if entry.get("proto") != packet.get("proto"):
        return None
    try:
        if int(entry.get("local_port", -1)) != local_port:
            return None
        entry_remote_port = int(entry.get("remote_port", -1))
    except (TypeError, ValueError):
        return None
    if str(entry.get("local_ip")) not in {phone_ip, "0.0.0.0", "::"}:
        return None
    if str(entry.get("remote_ip")) == remote_ip and entry_remote_port == remote_port:
        return "exact_5tuple"
    if packet.get("proto") == "udp" and str(entry.get("remote_ip")) in {"0.0.0.0", "::"}:
        return "udp_local_port"
    return None
