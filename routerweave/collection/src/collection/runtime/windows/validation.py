"""Artifact validation for Windows desktop collection runs."""

from __future__ import annotations

import csv
import json
import struct
import tempfile
from pathlib import Path
from typing import Any


def assess_coverage_foreground(
    ground_truth: Path, *, started_epoch: float, ended_epoch: float,
    expected_process: str, sample_interval_seconds: float,
    required_seconds: float, tab_events: Path | None = None,
) -> dict[str, Any]:
    """Count target foreground time, excluding other tabs when evidence is required."""
    interval = max(0.2, sample_interval_seconds)
    focus_intervals: list[tuple[float, float]] = []
    focus_evidence: dict[str, Any] | None = None
    if tab_events is not None:
        focus_intervals, focus_evidence = _target_tab_focus_intervals(
            tab_events, started_epoch=started_epoch, ended_epoch=ended_epoch)
    samples: list[tuple[float, str, bool]] = []
    if ground_truth.is_file():
        with ground_truth.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                try:
                    epoch = int(row["timestamp_ms"]) / 1000.0
                except (KeyError, TypeError, ValueError):
                    continue
                if started_epoch <= epoch <= ended_epoch:
                    samples.append((epoch, Path(str(row.get("foreground_app") or "")).name.lower(),
                                    str(row.get("screen_or_session_active") or "").lower() == "true"))
    samples.sort(key=lambda item: item[0])
    duration = max(0.0, ended_epoch - started_epoch)
    expected_count = max(1, int(duration / interval))
    sample_coverage = min(1.0, len(samples) / expected_count)
    max_gap = max((right[0] - left[0] for left, right in zip(samples, samples[1:])), default=duration)
    foreground_seconds = 0.0
    focus_index = 0
    for index, (epoch, name, active) in enumerate(samples):
        next_epoch = samples[index + 1][0] if index + 1 < len(samples) else ended_epoch
        seconds = max(0.0, min(interval, next_epoch - epoch, ended_epoch - epoch))
        if name == expected_process.lower() and active:
            if tab_events is None:
                foreground_seconds += seconds
            else:
                while focus_index < len(focus_intervals) and focus_intervals[focus_index][1] <= epoch:
                    focus_index += 1
                for left, right in focus_intervals[focus_index:]:
                    if left >= epoch + seconds:
                        break
                    foreground_seconds += max(0.0, min(right, epoch + seconds) - max(left, epoch))
    gap_limit = max(5.0, interval * 3.0)
    ok = (len(samples) > 1 and sample_coverage >= 0.9 and max_gap <= gap_limit
          and samples[0][0] - started_epoch <= gap_limit
          and ended_epoch - samples[-1][0] <= gap_limit
          and (focus_evidence is None or focus_evidence["ok"])
          and foreground_seconds >= required_seconds)
    return {"ok": ok, "foreground_seconds": round(foreground_seconds, 3),
            "excluded_foreground_seconds": round(max(0.0, duration - foreground_seconds), 3),
            "sample_count": len(samples), "sample_coverage": round(sample_coverage, 6),
            "max_gap_seconds": round(max_gap, 3),
            **({"target_tab_focus": focus_evidence} if focus_evidence is not None else {})}


def _target_tab_focus_intervals(
    events_path: Path, *, started_epoch: float, ended_epoch: float,
) -> tuple[list[tuple[float, float]], dict[str, Any]]:
    """Use only intervals bounded by two positive, timely focus observations."""
    checks: list[tuple[float, bool]] = []
    unknown_focus_epochs: list[float] = []
    malformed = False
    try:
        with events_path.open("r", encoding="utf-8-sig") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                event = json.loads(raw)
                if event.get("event_type") != "windows_observation":
                    continue
                payload = event["payload"]
                epoch = float(payload["observed_epoch"])
                if not started_epoch - 8 <= epoch <= ended_epoch + 8:
                    continue
                active = payload["state"].get("tab_active")
                if type(active) is not bool:
                    unknown_focus_epochs.append(epoch)
                    continue
                checks.append((epoch, active))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        malformed = True
    checks.sort()
    first_known_epoch = checks[0][0] if checks else float("inf")
    malformed = malformed or any(
        epoch >= first_known_epoch or epoch > started_epoch + 8
        for epoch in unknown_focus_epochs
    )
    gaps = [right[0] - left[0] for left, right in zip(checks, checks[1:])]
    max_gap = max(gaps, default=float("inf"))
    coverage_ok = (not malformed and len(checks) >= 2
                   and checks[0][0] <= started_epoch + 8
                   and checks[-1][0] >= ended_epoch - 8
                   and max_gap <= 8)
    intervals: list[tuple[float, float]] = []
    if coverage_ok:
        for (left, left_active), (right, right_active) in zip(checks, checks[1:]):
            if not (left_active and right_active):
                continue
            start, end = max(started_epoch, left), min(ended_epoch, right)
            if start >= end:
                continue
            if intervals and start <= intervals[-1][1]:
                intervals[-1] = (intervals[-1][0], max(intervals[-1][1], end))
            else:
                intervals.append((start, end))
    return intervals, {"ok": coverage_ok, "samples": len(checks),
                       "positive_samples": sum(active for _, active in checks),
                       "max_gap_seconds": round(max_gap, 3) if len(checks) > 1 else None,
                       "malformed": malformed}


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _csv_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return max(0, sum(1 for _ in csv.reader(handle)) - 1)


def _jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, start=1):
            if not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            rows.append(value)
    return rows


def assess_full_packets(paths: list[Path]) -> dict[str, Any]:
    """Check actual PCAP records rather than trusting the requested snaplen."""
    packets = truncated = 0
    errors = []
    magic = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
             b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    for path in paths:
        try:
            with path.open("rb") as handle:
                header = handle.read(24)
                if len(header) != 24 or header[:4] not in magic:
                    raise ValueError("Invalid PCAP header")
                size = path.stat().st_size
                while record := handle.read(16):
                    if len(record) != 16:
                        raise ValueError("Incomplete packet record")
                    _, _, captured, original = struct.unpack(magic[header[:4]] + "IIII", record)
                    if captured > original or handle.tell() + captured > size:
                        raise ValueError("Invalid or incomplete packet data")
                    packets += 1
                    truncated += captured < original
                    handle.seek(captured, 1)
        except (OSError, ValueError) as exc:
            errors.append(f"{path}: {exc}")
    return {"ok": packets > 0 and truncated == 0 and not errors,
            "packets": packets, "truncated_packets": truncated, "errors": errors}


def validate_windows_run(run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    checks: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}

    def add(name: str, ok: bool, detail: str = "", value: Any = None) -> None:
        row: dict[str, Any] = {"name": name, "ok": bool(ok)}
        if detail:
            row["detail"] = detail
        if value is not None:
            row["value"] = value
        checks.append(row)

    manifest_path = run_dir / "windows_capture_manifest.json"
    add("manifest:exists", manifest_path.is_file(), str(manifest_path))
    if not manifest_path.is_file():
        return {"profile": "windows_network_capture", "run_dir": str(run_dir), "ok": False, "checks": checks, "metrics": metrics}
    try:
        manifest = _json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        add("manifest:read", False, str(exc))
        return {"profile": "windows_network_capture", "run_dir": str(run_dir), "ok": False, "checks": checks, "metrics": metrics}

    add("manifest:complete", manifest.get("status") == "complete", str(manifest.get("status")))
    from ..collection_environment import validate_run_environment
    environment_starts = []
    if manifest.get("collection_environment"):
        try:
            environment_starts = [float(json.loads(line)["started_epoch"])
                for line in (run_dir / "usage_windows.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, ValueError, KeyError, TypeError):
            add("environment:foreground_boundaries", False, "missing foreground start evidence")
    environment_errors = validate_run_environment(run_dir, str(manifest.get("target_name") or ""),
        manifest.get("collection_environment"), foreground_start=min(environment_starts) if environment_starts else None)
    add("environment:preparation", not environment_errors, "; ".join(environment_errors))
    add("foreground_capture_mode", not manifest.get("background_control_only", False),
        "background control probes are not foreground capture")
    continuous_focus = None
    if manifest.get('browser_tab_focus') is not None:
        from .browser_control import verify_continuous_focus
        continuous_focus = run_dir / 'platform_evidence' / 'browser_tab_focus.jsonl'
        try:
            metadata = manifest['browser_tab_focus']
            effective = _json(run_dir / 'effective_plan.json')
            targets = [t for c in effective['categories'] if c['id'] == manifest['category_id']
                       for t in c['targets'] if t['name'] == manifest['target_name']]
            valid_focus = (metadata['events'] == 'platform_evidence/browser_tab_focus.jsonl'
                           and len(targets) == 1 and verify_continuous_focus(
                continuous_focus, metadata, session_id=manifest['browser_attachment']['session_id'],
                tab_id=manifest['resolved_edge_tab_id'], expected_hosts=targets[0]['expected_hosts'],target=targets[0]))
        except (OSError, ValueError, KeyError, TypeError):
            valid_focus = False
        add('browser_tab_focus:continuous_evidence', valid_focus,
            'Replay buffered visibility events from the same authorized pinned tab')
    session_dir = Path(str(manifest.get("session_dir", "")))
    if not session_dir.is_absolute():
        session_dir = run_dir / session_dir
    ground_truth = session_dir / "ground_truth.csv"
    ground_truth_rows = _csv_rows(ground_truth)
    metrics["screen_samples"] = ground_truth_rows
    add("ground_truth:rows", ground_truth_rows > 0, str(ground_truth), ground_truth_rows)

    events = _jsonl_rows(run_dir / "events.jsonl")
    metrics["event_rows"] = len(events)
    add("events:rows", len(events) > 0, str(run_dir / "events.jsonl"), len(events))

    automation_enabled = bool(manifest.get("automation_enabled"))
    windows = _jsonl_rows(run_dir / "usage_windows.jsonl")
    accepted = sum(1 for row in windows if row.get("status") == "accepted")
    foreground_evidence = sum(1 for row in windows if isinstance(row.get("foreground_evidence"), dict))
    required_media = [row for row in windows if row.get("media_probe_required") is True]
    verified_required_media = sum(
        1
        for row in required_media
        if isinstance(row.get("media_evidence"), dict) and row["media_evidence"].get("ok") is True
    )
    metrics["usage_windows"] = len(windows)
    from .semantic import validate_activity_events, validate_shared_task, verified_browsing_interactions
    shared_activity_valid: dict[str, bool] = {}
    for row in windows:
        if row.get("shared_activity") and row.get("status") == "accepted":
            expected_path = run_dir / "semantic" / str(row.get("window_id")) / "events.jsonl"
            valid_shared_activity = (
                validate_shared_task(expected_path.parent, row) if row.get("shared_task_version") == 2
                else validate_activity_events(expected_path, int(row.get("action_count", 0)))
            )
            shared_activity_valid[str(row.get("window_id"))] = valid_shared_activity
            add("usage_windows:shared_activity_evidence",
                valid_shared_activity,
                str(expected_path))
    if manifest.get("collection_task_id") == "windows-browser-control-smoke":
        for row in windows:
            if row.get("status") == "accepted" and (row.get("category_id") == "web_browsing"
                    or manifest.get("category_id") == "web_browsing"):
                directory = run_dir / "semantic" / str(row.get("window_id"))
                add("browsing:complete_interactions",
                    row.get("shared_activity") is True and row.get("shared_task_version") == 2
                    and shared_activity_valid.get(str(row.get("window_id"))) is True
                    and verified_browsing_interactions(directory),
                    "Requires successful content entry, detail scrolling and return with matched postconditions")
    metrics["accepted_windows"] = accepted
    metrics["foreground_evidence_windows"] = foreground_evidence
    metrics["media_probe_required_windows"] = len(required_media)
    metrics["media_probe_verified_windows"] = verified_required_media
    add("usage_windows:accepted", (accepted > 0) if automation_enabled else (len(windows) > 0), str(run_dir / "usage_windows.jsonl"), accepted)
    if manifest.get("collection_task_id") in {"windows-browser-control-smoke", "windows-native-control-smoke"}:
        smoke_windows = [row for row in windows if row.get("status") == "accepted"]
        smoke = smoke_windows[0] if len(windows) == len(smoke_windows) == 1 else None
        add("browser_smoke:behavior",
            smoke is not None and smoke.get("shared_activity") is True
            and int(smoke.get("action_count") or 0) > 0
            and shared_activity_valid.get(str(smoke.get("window_id"))) is True
            and (smoke.get("media_probe_required") is not True
                 or (isinstance(smoke.get("media_evidence"), dict)
                     and smoke["media_evidence"].get("ok") is True)),
            "Registered smoke verifies action postconditions and required playback; foreground is a formal-run gate")
    minimum = float(manifest.get("minimum_foreground_seconds") or 0)
    if minimum > 0:
        verified = [
            assess_coverage_foreground(
                ground_truth, started_epoch=float(row["started_epoch"]), ended_epoch=float(row["ended_epoch"]),
                expected_process=Path(row["command"]).name.lower(),
                sample_interval_seconds=float(manifest["sample_interval_ms"]) / 1000,
                required_seconds=minimum,
                tab_events=continuous_focus if manifest.get("target_tab_focus_required") else None,
            )
            for row in windows if row.get("status") == "accepted"
            and row.get("category_id") == manifest.get("category_id")
            and row.get("target_name") == manifest.get("target_name")
        ]
        add("foreground:required_duration", len(windows) == len(verified) == 1 and verified[0]["ok"],
            "Verified target foreground time", verified[0] if verified else {})
        metrics["verified_foreground_seconds"] = verified[0]["foreground_seconds"] if verified else 0
    if automation_enabled:
        # Exploratory browser smokes prove behavior, not workstation focus.
        # Formal and coverage runs retain the foreground evidence requirement.
        if manifest.get("collection_task_id") != "windows-browser-control-smoke":
            add(
                "usage_windows:foreground_evidence",
                foreground_evidence == len(windows) and len(windows) > 0,
                str(run_dir / "usage_windows.jsonl"),
                foreground_evidence,
            )
        if required_media:
            add(
                "usage_windows:required_media_verified",
                verified_required_media == len(required_media),
                str(run_dir / "usage_windows.jsonl"),
                verified_required_media,
            )

    router_enabled = bool(manifest.get("router_capture_enabled"))
    pcap_files = []
    for value in manifest.get("pcap_files", []):
        path = Path(str(value))
        if not path.is_absolute():
            path = run_dir / path
        from ..screen_time_storage import resolve_run_original
        pcap_files.append(resolve_run_original(run_dir, path))
    pcap_bytes = sum(path.stat().st_size for path in pcap_files if path.is_file())
    metrics["pcap_files"] = len(pcap_files)
    metrics["pcap_bytes"] = pcap_bytes
    if router_enabled:
        add("router_pcap:non_empty", bool(pcap_files) and pcap_bytes > 24, "router capture was enabled", pcap_bytes)
        if manifest.get("router", {}).get("require_full_packets"):
            packet_check = assess_full_packets(pcap_files)
            metrics["full_packet_capture"] = packet_check
            add("router_pcap:full_packets", packet_check["ok"],
                "Every captured packet must retain its original recorded length", packet_check)
        bucket_rows = _csv_rows(session_dir / "network" / "network_flow_buckets.csv")
        metrics["network_bucket_rows"] = bucket_rows
        add("network_buckets:rows", bucket_rows > 0, str(session_dir / "network" / "network_flow_buckets.csv"), bucket_rows)

    if manifest.get("process_attribution", {}).get("enabled"):
        try:
            from .process_attribution import export_attribution, sha256
            saved_path = run_dir / "process_filter" / "summary.json"
            saved = _json(saved_path)
            legacy_export = saved.get('schema_version') == 2
            view_sources = None
            if not legacy_export:
                view_path = saved_path.parent / saved['retained_capture']
                view = _json(view_path)
                view_sources = [{**s, 'path': str((view_path.parent / s['path']).resolve())} for s in view['sources']]
            with tempfile.TemporaryDirectory(prefix="windows-attribution-verify-") as tmp:
                proof = export_attribution(pcap_files, run_dir / "platform_evidence" / "socket_samples.jsonl.gz", tmp,
                    materialize_pcaps=legacy_export, view_sources=view_sources, reference_base=saved_path.parent)
            hashes_ok = all((run_dir / "process_filter" / name).is_file()
                            and sha256(run_dir / "process_filter" / name) == digest
                            for name, digest in proof["files"].items())
            metrics["process_attribution"] = proof
            add("process_attribution:recomputed", saved == proof and hashes_ok and proof["ok"]
                and proof["excluded_process_roots"] == manifest["process_attribution"]["excluded_process_roots"],
                "Replay socket evidence against actual packet bytes and verify filtered exports")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            add("process_attribution:recomputed", False, str(exc))

    if manifest.get('background_scenario') or manifest.get('collection_task_id') == 'windows-background-parity':
        try:
            from .background import validate_background_evidence
            proof = validate_background_evidence(run_dir, manifest)
            metrics['background_state'] = proof
            add('background:independent_state_replay', proof['ok'], 'Replay actual WTS, desktop and last-input state')
            add('background:device_full_capture', manifest.get('automation_enabled') is False
                and manifest.get('router_capture_enabled') is True
                and manifest.get('router', {}).get('require_full_packets') is True
                and manifest.get('process_attribution', {}).get('enabled') is True,
                'Background collection requires a full device capture and socket ownership evidence')
        except (OSError, ValueError, KeyError, TypeError) as exc:
            add('background:independent_state_replay', False, str(exc))

    return {
        "profile": "windows_network_capture",
        "platform": "windows",
        "run_dir": str(run_dir),
        "ok": all(row["ok"] for row in checks),
        "checks": checks,
        "metrics": metrics,
    }
