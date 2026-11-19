"""App attribution for an iOS process-scoped packet capture."""

from __future__ import annotations

import csv
from .export import write_json, PACKET_COLUMNS
from .evidence import AttributionResult
import json
from pathlib import Path
import re
from typing import Any

from .pcap import iter_decoded_packets, packet_local_remote, verified_network_window_id


def attribute_ios_process_capture(
    *,
    pcap_path: str | Path,
    bundle_id: str,
    process_name: str,
    phone_ip: str,
    network_windows: list[dict[str, Any]],
    out_dir: str | Path,
) -> AttributionResult:
    """Export one process-scoped pcap under the common packet evidence contract."""

    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    attribution_path = destination / "packet_attribution.jsonl"
    summary_path = destination / "packet_attribution_summary.json"
    windows_summary_path = destination / "packet_attribution_windows_summary.json"
    app_dir = destination / "app_attributed_packets"
    app_dir.mkdir(parents=True, exist_ok=True)
    safe_bundle = re.sub(r"[^A-Za-z0-9_.-]+", "_", bundle_id)
    target_csv_path = app_dir / f"{safe_bundle}.csv"
    export_manifest_path = destination / "app_attributed_packets_manifest.json"

    window_counts = {
        str(window.get("id")): {
            "id": str(window.get("id")),
            "packets": 0,
            "bytes": 0,
            "target_packets": 0,
            "target_bytes": 0,
        }
        for window in network_windows
    }
    verified_window_count = sum(
        1 for window in network_windows if window.get("task_success") is True
    )
    decoded_packets = 0
    phone_packets = 0
    configured_phone_ip_packets = 0
    phone_bytes = 0
    window_packets = 0

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
            if local is not None:
                configured_phone_ip_packets += 1
            phone_packets += 1
            phone_bytes += int(packet["length"])
            window_id = verified_network_window_id(
                float(packet["ts_epoch"]), network_windows
            )
            if window_id is not None:
                window_packets += 1
            row = {
                **packet,
                "direction": local[3] if local is not None else "process_scoped",
                "network_window_id": window_id,
                "uid": None,
                "packages": [bundle_id],
                "bundle_ids": [bundle_id],
                "process_name": process_name,
                "match_basis": "ios_process_pcap",
                "confidence": "high",
            }
            if window_id in window_counts:
                bucket = window_counts[window_id]
                bucket["packets"] += 1
                bucket["bytes"] += int(packet["length"])
                bucket["target_packets"] += 1
                bucket["target_bytes"] += int(packet["length"])
            attribution_handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            attribution_handle.write("\n")
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
                    "app": bundle_id,
                    "network_window_id": window_id or "",
                    "attribution_confidence": "high",
                }
            )

    window_rows = list(window_counts.values())
    # PID-scoped VPN packets may use a tunnel address instead of the Wi-Fi address.
    ready = decoded_packets > 0 and phone_packets > 0
    formal_ready = ready and verified_window_count > 0 and window_packets > 0
    formal_reasons: list[str] = []
    if phone_packets <= 0:
        formal_reasons.append("process pcap contains no decoded TCP/UDP packets")
    if verified_window_count <= 0:
        formal_reasons.append("no successful verified task window is available")
    elif window_packets <= 0:
        formal_reasons.append("no process-scoped packets fall inside a verified task window")
    metrics = {
        "bundle_id": bundle_id,
        "process_name": process_name,
        "pcap_packets_decoded": decoded_packets,
        "phone_packets": phone_packets,
        "configured_phone_ip_packets": configured_phone_ip_packets,
        "address_scope": (
            "configured_phone_ip"
            if configured_phone_ip_packets > 0
            else "process_tunnel"
        ),
        "matched_packets": phone_packets,
        "unmatched_packets": 0,
        "target_packets": phone_packets,
        "target_bytes": phone_bytes,
        "target_window_packets": window_packets,
        "verified_window_count": verified_window_count,
        "by_network_window": window_rows,
        "formal_readiness_failures": formal_reasons,
    }
    write_json(summary_path, metrics)
    write_json(windows_summary_path, window_rows)
    write_json(
        export_manifest_path,
        {
            "schema_version": 1,
            "target_package": bundle_id,
            "process_name": process_name,
            "rows_written": phone_packets,
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
