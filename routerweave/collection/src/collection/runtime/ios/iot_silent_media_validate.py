#!/usr/bin/env python3
"""Independently validate silent IoT media capture artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from collection.runtime.ios.iot_silent_media_capture import MEDIA_ACTIONS


def validate_rows(rows: list[dict[str, Any]], expected: dict[str, dict[str, int]]) -> list[str]:
    errors: list[str] = []
    actual: Counter[tuple[str, str]] = Counter()
    windows: list[tuple[float, float, str]] = []
    for row in rows:
        sample_id = str(row.get("sample_id") or "<missing-id>")
        action = str(row.get("action") or "")
        if action not in MEDIA_ACTIONS:
            errors.append(f"{sample_id}: unknown action {action!r}")
            continue
        if not row.get("valid"):
            continue
        device_id = str(row.get("device_id") or "")
        actual[(device_id, action)] += 1
        identity = row.get("camera_identity_evidence")
        if row.get("camera_identity_evidence_required") and not identity:
            errors.append(f"{sample_id}: exact camera identity evidence is missing")
        if identity:
            try:
                path = Path(identity["source_xml"])
                raw = path.read_bytes()
                names = [e for e in ET.fromstring(raw).iter() if (e.attrib.get("type") or e.tag) == "XCUIElementTypeTextField"
                         and e.attrib.get("visible") == "true" and e.attrib.get("value") == row["device_name"]]
                if len(names) != 1 or hashlib.sha256(raw).hexdigest() != identity["sha256"] or identity["device_id"] != device_id or identity["device_name"] != row["device_name"]:
                    errors.append(f"{sample_id}: camera identity source/hash/name mismatch")
                if float(identity["verified_epoch"]) > float(row["baseline_start_epoch"]):
                    errors.append(f"{sample_id}: camera identity was verified after the baseline")
            except (KeyError, TypeError, ValueError, OSError, ET.ParseError):
                errors.append(f"{sample_id}: camera identity evidence is invalid")
        verified = row.get("verified_device_ips")
        if verified is not None:
            endpoint = row.get("endpoint_identity_evidence") or {}
            if not verified or row.get("device_ip") not in verified or set(endpoint.get("verified_ips") or []) != set(verified):
                errors.append(f"{sample_id}: verified endpoint identity is incomplete or inconsistent")
            proof = Path(str(endpoint.get("evidence_file") or ""))
            if not proof.is_file() or hashlib.sha256(proof.read_bytes()).hexdigest() != endpoint.get("evidence_sha256"):
                errors.append(f"{sample_id}: endpoint evidence file/hash mismatch")
            else:
                try:
                    content = json.loads(proof.read_text(encoding="utf-8-sig"))
                    if content.get("device_id") != device_id or set(content.get("verified_ips") or []) != set(verified):
                        errors.append(f"{sample_id}: endpoint proof contents disagree with row identity")
                except (ValueError, TypeError):
                    errors.append(f"{sample_id}: endpoint proof JSON is invalid")
            for key, value in (endpoint.get("artifacts") or {}).items():
                path = Path(value)
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != (endpoint.get("artifacts_sha256") or {}).get(key):
                    errors.append(f"{sample_id}: endpoint evidence artifact/hash mismatch: {key}")
        needs_silence_evidence = (
            action.startswith("live_view")
            or action == "talk_session"
            or (
                action in {"play", "pause"}
                and row.get("playback_volume_managed", True)
            )
        )
        if needs_silence_evidence:
            if not row.get("controller_media_muted"):
                errors.append(f"{sample_id}: controller media mute evidence is missing")
            silence = row.get("silence_preflight") or {}
            evidence_path = Path(str(silence.get("evidence_file") or ""))
            if not evidence_path.is_file():
                errors.append(f"{sample_id}: silence preflight evidence file is missing")
            else:
                digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                if digest != silence.get("evidence_sha256"):
                    errors.append(f"{sample_id}: silence preflight evidence hash does not match")
            if silence.get("media_volume_percent") != 0 or not silence.get("controller_identifier"):
                errors.append(f"{sample_id}: silence preflight evidence is incomplete")
            for key, artifact in (silence.get("artifacts") or {}).items():
                artifact_path = Path(str(artifact))
                if not artifact_path.is_file() or artifact_path.stat().st_size <= 0:
                    errors.append(f"{sample_id}: silence preflight artifact is missing or empty: {artifact_path}")
                elif key in (silence.get("artifacts_sha256") or {}) and hashlib.sha256(artifact_path.read_bytes()).hexdigest() != silence["artifacts_sha256"][key]:
                    errors.append(f"{sample_id}: silence preflight artifact hash does not match: {key}")
        if not row.get("device_brand") or not row.get("device_model") or not row.get("device_type"):
            errors.append(f"{sample_id}: exact device identity is incomplete")
        try:
            start = float(row["baseline_start_epoch"])
            command = float(row["command_issued_epoch"])
            result = float(row["action_result_epoch"])
            end = float(row["tail_end_epoch"])
            if not start < command <= result <= end:
                errors.append(f"{sample_id}: invalid timestamp order")
            quality = str(row.get("command_timing_quality") or "")
            if quality:
                operation = float(row.get("operation_started_epoch", command))
                gesture_start = float(row["gesture_start_epoch"])
                gesture_complete = float(row["gesture_complete_epoch"])
                if not start < operation <= gesture_start <= gesture_complete <= result:
                    errors.append(f"{sample_id}: invalid operation/gesture timestamp order")
                if abs(command - gesture_start) > 0.001:
                    errors.append(f"{sample_id}: command_issued_epoch is not the gesture start")
                if not row.get("gesture_action_kind") or not row.get("command_timing_source"):
                    errors.append(f"{sample_id}: command timing provenance is incomplete")
            windows.append((start, end, sample_id))
        except (KeyError, TypeError, ValueError):
            errors.append(f"{sample_id}: missing or invalid timestamps")
        if not row.get("tail_state_stable"):
            errors.append(f"{sample_id}: valid row has an unstable tail")
        source, target = row.get("source_value"), row.get("target_value")
        confirmed, tail = row.get("confirmed_state") or {}, row.get("tail_state") or {}
        if action == "live_view_start":
            if source != "closed" or target != "playing" or confirmed.get("state") != "playing" or tail.get("state") != "playing":
                errors.append(f"{sample_id}: live-view start evidence is inconsistent")
        elif action == "live_view_stop":
            if source != "playing" or target != "closed" or confirmed.get("state") != "closed" or tail.get("state") != "closed":
                errors.append(f"{sample_id}: live-view stop evidence is inconsistent")
        elif action == "talk_session":
            if source != "playing" or target != "playing" or confirmed.get("state") != "playing" or tail.get("state") != "playing":
                errors.append(f"{sample_id}: talk-session state evidence is inconsistent")
            try:
                command_time = float(row["command_issued_epoch"])
                result_time = float(row["action_result_epoch"])
                talk_confirmed = float(row["talking_confirmed_epoch"])
                audio = row["talk_audio"]
                audio_start = float(audio["audio_start_epoch"])
                audio_end = float(audio["audio_end_epoch"])
                talk_stopped = float(row["talk_stopped_confirmed_epoch"])
                if not command_time <= talk_confirmed <= audio_start < audio_end <= talk_stopped <= result_time:
                    errors.append(f"{sample_id}: talk/audio timestamp order is invalid")
                asset = Path(str(audio["asset_path"]))
                if not asset.is_file() or hashlib.sha256(asset.read_bytes()).hexdigest() != audio.get("sha256"):
                    errors.append(f"{sample_id}: talk audio asset/hash evidence is invalid")
                if abs(float(audio["duration_seconds"]) - 5.0) > 0.05:
                    errors.append(f"{sample_id}: talk audio is not the fixed five-second asset")
                attempts = row.get("command_attempts") or []
                if row.get("speaker_talk_enabled"):
                    speaker_started = float(row["speaker_started_confirmed_epoch"])
                    microphone_stopped = float(row["microphone_stopped_confirmed_epoch"])
                    speaker_stopped = float(row["speaker_stopped_confirmed_epoch"])
                    if not command_time <= speaker_started <= talk_confirmed <= audio_start < audio_end <= microphone_stopped <= speaker_stopped <= result_time:
                        errors.append(f"{sample_id}: speaker/microphone talk timestamp order is invalid")
                    if len(attempts) != 4:
                        errors.append(f"{sample_id}: speaker-enabled talk session must contain exactly four gestures")
                elif len(attempts) != 2:
                    errors.append(f"{sample_id}: talk session must contain exactly start and stop gestures")
            except (KeyError, TypeError, ValueError):
                errors.append(f"{sample_id}: talk/audio evidence is incomplete")
        elif action in {"play", "pause"}:
            expected_source = "paused" if action == "play" else "playing"
            expected_target = "playing" if action == "play" else "paused"
            precommand = row.get("precommand_state") or {}
            if row.get("playback_volume_managed", True):
                silent_target = row.get("silent_volume_percent")
                try:
                    silent_n = int(silent_target)
                    pre_n = int(precommand["volume"])
                    confirmed_n = int(confirmed["volume"])
                    tail_n = int(tail["volume"])
                except (KeyError, TypeError, ValueError):
                    errors.append(f"{sample_id}: speaker playback mute evidence is incomplete")
                    continue
                tolerance = int(row.get("volume_tolerance", 5))
                if silent_n != 0 or not row.get("speaker_output_muted"):
                    errors.append(f"{sample_id}: speaker output was not declared muted")
                if any(abs(value - silent_n) > tolerance for value in (pre_n, confirmed_n, tail_n)):
                    errors.append(f"{sample_id}: speaker output volume left the silent tolerance")
            if (
                source != expected_source
                or target != expected_target
                or precommand.get("state") != expected_source
                or confirmed.get("state") != expected_target
                or tail.get("state") != expected_target
            ):
                errors.append(f"{sample_id}: speaker playback state evidence is inconsistent")
            attempts = row.get("command_attempts") or []
            if len(attempts) != 1:
                errors.append(f"{sample_id}: speaker playback action must contain exactly one gesture")
        else:
            try:
                source_n, target_n = int(source), int(target)
                confirmed_n, tail_n = int(confirmed["volume"]), int(tail["volume"])
            except (KeyError, TypeError, ValueError):
                errors.append(f"{sample_id}: volume evidence is incomplete")
                continue
            delta = target_n - source_n
            if abs(delta) < 20:
                errors.append(f"{sample_id}: volume change is smaller than 20 percentage points")
            if action == "volume_up" and delta <= 0:
                errors.append(f"{sample_id}: volume_up direction is wrong")
            if action == "volume_down" and delta >= 0:
                errors.append(f"{sample_id}: volume_down direction is wrong")
            tolerance = int(row.get("volume_tolerance", 5))
            if abs(confirmed_n - target_n) > tolerance or abs(tail_n - target_n) > tolerance:
                errors.append(f"{sample_id}: confirmed or tail volume is outside tolerance")
            if confirmed.get("state") != "idle" or tail.get("state") != "idle":
                errors.append(f"{sample_id}: speaker was not confirmed idle")
    for device_id, actions in expected.items():
        for action, count in actions.items():
            found = actual[(device_id, action)]
            if found != int(count):
                errors.append(f"{device_id}/{action}: expected {count} valid rows, found {found}")
    windows.sort()
    for previous, current in zip(windows, windows[1:]):
        if current[0] < previous[1]:
            errors.append(f"overlapping valid windows: {previous[2]} and {current[2]}")
    return errors


def service_error_evidence_errors(root: Path, rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for row in rows:
        if not row.get("valid") or row.get("control_platform") != "alexa":
            continue
        sample_id = str(row.get("sample_id") or "")
        path = root / "events" / f"{sample_id}.jsonl"
        if not path.is_file():
            errors.append(f"{sample_id}: action event evidence is missing")
            continue
        try:
            command, end = float(row["command_issued_epoch"]), float(row["tail_end_epoch"])
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                event = json.loads(line)
                if event.get("event") not in {
                    "silent_media_dismiss_alexa_transient_error",
                    "silent_media_alexa_service_error",
                    "silent_media_alexa_unknown_dialog",
                }:
                    continue
                epoch = datetime.fromisoformat(str(event["ts"])).timestamp()
                if command <= epoch <= end:
                    errors.append(f"{sample_id}: Alexa blocking dialog after command; UI state is unverified")
                    break
        except (KeyError, TypeError, ValueError, OSError) as exc:
            errors.append(f"{sample_id}: invalid action event evidence: {exc}")
    return errors


def validate_run(root: Path) -> dict[str, Any]:
    manifest_path = root / "batch_manifest.json"
    rows_path = root / "sample_windows.json"
    errors: list[str] = []
    if not manifest_path.is_file():
        return {"valid": False, "errors": ["batch_manifest.json is missing"]}
    if not rows_path.is_file():
        return {"valid": False, "errors": ["sample_windows.json is missing"]}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rows = json.loads(rows_path.read_text(encoding="utf-8-sig"))
    if manifest.get("status") != "complete":
        errors.append(f"manifest status is {manifest.get('status')!r}, not 'complete'")
    pcap = Path(str(manifest.get("raw_pcap") or ""))
    if not pcap.is_file() or pcap.stat().st_size <= 24:
        errors.append("raw pcap is missing or empty")
    target = int(manifest.get("target_valid_per_action", 0))
    expected = {
        device_id: {action: target for action in actions}
        for device_id, actions in (manifest.get("valid_counts") or {}).items()
    }
    errors.extend(validate_rows(rows, expected))
    errors.extend(service_error_evidence_errors(root, rows))
    if manifest.get("valid_counts") != expected:
        errors.append("manifest valid_counts does not equal the declared target")
    return {
        "valid": not errors,
        "errors": errors,
        "samples": len(rows),
        "pcap_bytes": pcap.stat().st_size if pcap.is_file() else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_root")
    args = parser.parse_args()
    result = validate_run(Path(args.run_root).resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
