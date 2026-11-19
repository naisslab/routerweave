#!/usr/bin/env python3
"""Capture silent camera, doorbell, and smart-speaker UI actions.

The collector is plan-driven. It accepts only positive UI evidence for a
playing stream or an idle speaker, records one continuous router PCAP, and
keeps failed attempts as audit rows without counting them as valid samples.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import random
import time
import wave
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.capture import RouterStreamCapture
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA
from collection.runtime.ios.iot_google_home_capture import GoogleHomeUI
from collection.runtime.ios.iot_identity_preflight import (
    materialize_endpoint_evidence,
    apply_resolved_identities,
    run_identity_preflight,
)
from collection.runtime.ios.iot_capture_network import resolve_capture_addresses
from collection.runtime.ios.iot_light_probe import (
    center,
    dismiss_restored_detail,
    ensure_dashboard,
    find_target,
    scroll_toward_target,
    target_is_hittable,
)
from collection.runtime.ios.iot_light_ui import percentage, select, select_one, slider_target


MEDIA_ACTIONS = (
    "live_view_start", "live_view_stop", "talk_session",
    "volume_up", "volume_down", "play", "pause",
)
PLAYBACK_DEVICE_TYPES = frozenset({"smart_speaker", "media_player"})


def camera_video_point(source: str, *, allow_unnamed: bool = False) -> dict[str, int]:
    """Reveal camera controls at the current native video container's center."""
    videos = select(source, {"type": "XCUIElementTypeOther", "name": "视频", "visible": True})
    if len(videos) == 1:
        video = videos[0]
    elif not videos and allow_unnamed:
        surfaces = {}
        for scroll in select(source, {"type": "XCUIElementTypeScrollView", "visible": True}):
            for element in scroll.iter():
                if (element.attrib.get("type") or element.tag) != "XCUIElementTypeOther" or element.attrib.get("name") or element.attrib.get("visible") != "true":
                    continue
                try:
                    bounds = tuple(float(element.attrib[key]) for key in ("x", "y", "width", "height"))
                except (KeyError, ValueError):
                    continue
                x, y, width, height = bounds
                if all(math.isfinite(v) for v in bounds) and min(x, y) >= 0 and width > 100 and height > 50 and abs(width / height - 16 / 9) < 0.15:
                    surfaces[bounds] = element
        if len(surfaces) != 1:
            raise DemoError(f"Expected one verified camera video surface, found {len(surfaces)}")
        video = next(iter(surfaces.values()))
    else:
        raise DemoError(f"Expected one camera video container, found {len(videos)}")
    try:
        x, y, width, height = (float(video.attrib[key]) for key in ("x", "y", "width", "height"))
    except (KeyError, ValueError) as exc:
        raise DemoError("Camera video container has no valid native bounds") from exc
    if not all(math.isfinite(value) for value in (x, y, width, height)) or min(x, y) < 0 or min(width, height) < 1:
        raise DemoError("Camera video container has unusable native bounds")
    return {"x": int(x + width / 2), "y": int(y + height / 2)}


@dataclass(frozen=True)
class MediaIntent:
    action: str
    source_value: str | int
    target_value: str | int


def camera_action(device: dict[str, Any], action: str) -> bool:
    return device["device_type"] in {"smart_camera", "video_doorbell"} and action in {
        "live_view_start", "live_view_stop", "talk_session"
    }


def speaker_playback_action(device: dict[str, Any], action: str) -> bool:
    return device["device_type"] in PLAYBACK_DEVICE_TYPES and action in {"play", "pause"}


def manages_playback_volume(device: dict[str, Any]) -> bool:
    return bool(device.get("manage_playback_volume", True))


def wav_duration(path: Path) -> float:
    try:
        with wave.open(str(path), "rb") as audio:
            frames, rate = audio.getnframes(), audio.getframerate()
            if frames <= 0 or rate <= 0:
                raise DemoError(f"Talk WAV has no audio frames: {path}")
            return frames / rate
    except (OSError, wave.Error) as exc:
        raise DemoError(f"Invalid talk WAV {path}: {exc}") from exc


def load_talk_audio(plan: dict[str, Any]) -> dict[str, Any] | None:
    has_talk = any(
        "talk_session" in (device.get("actions") or []) for device in (plan.get("devices") or [])
    )
    if not has_talk:
        return None
    config = plan.get("talk_audio") or {}
    path = Path(str(config.get("asset_path") or "")).resolve()
    if not path.is_file() or path.stat().st_size <= 44:
        raise DemoError(f"Talk audio asset is missing or empty: {path}")
    duration = wav_duration(path)
    expected = float(config.get("expected_duration_seconds", 5))
    tolerance = float(config.get("duration_tolerance_seconds", 0.05))
    if abs(duration - expected) > tolerance:
        raise DemoError(
            f"Talk audio duration mismatch: expected={expected}, actual={duration}, tolerance={tolerance}"
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected_hash = str(config.get("sha256") or "").lower()
    if expected_hash and digest != expected_hash:
        raise DemoError(f"Talk audio SHA-256 mismatch for {path}")
    return {
        "asset_path": str(path),
        "sha256": digest,
        "duration_seconds": duration,
        "output_device_name": str(config.get("output_device_name") or ""),
    }


def play_talk_audio(audio: dict[str, Any], log: EventLog) -> dict[str, Any]:
    import numpy as np
    import sounddevice as sd

    with wave.open(str(audio["asset_path"]), "rb") as source:
        if source.getsampwidth() != 2:
            raise DemoError("Talk WAV must use signed 16-bit PCM")
        sample_rate = source.getframerate()
        channels = source.getnchannels()
        samples = np.frombuffer(source.readframes(source.getnframes()), dtype=np.int16)
        if channels > 1:
            samples = samples.reshape((-1, channels))
    requested = str(audio.get("output_device_name") or "").strip()
    default_output = int(sd.default.device[1])
    devices = sd.query_devices()
    candidates = [
        index for index, device in enumerate(devices)
        if int(device["max_output_channels"]) > 0 and requested.lower() in str(device["name"]).lower()
    ] if requested else []
    device_index = default_output if default_output in candidates or not candidates else candidates[0]
    device_name = str(devices[device_index]["name"])

    started = time.time()
    output = {**audio, "output_device_index": device_index, "output_device_name": device_name}
    log.write("talk_audio_start", epoch=started, **output)
    sd.play(samples, sample_rate, device=device_index, blocking=True)
    ended = time.time()
    log.write("talk_audio_end", epoch=ended, elapsed_seconds=ended - started, **output)
    return {
        **output,
        "audio_start_epoch": started,
        "audio_end_epoch": ended,
        "elapsed_seconds": ended - started,
    }


def load_silence_preflight(plan: dict[str, Any]) -> dict[str, Any]:
    """Load and verify fresh, file-backed evidence that the controller is muted."""
    config = plan.get("silence_preflight") or {}
    evidence_path = Path(str(config.get("evidence_file") or "")).resolve()
    if not evidence_path.is_file():
        raise DemoError(f"Silence preflight evidence is missing: {evidence_path}")
    raw = evidence_path.read_bytes()
    evidence = json.loads(raw.decode("utf-8-sig"))
    if evidence.get("valid") is not True or int(evidence.get("media_volume_percent", -1)) != 0:
        raise DemoError("Silence preflight does not prove controller media volume is zero")
    controller_id = str((plan.get("controller") or {}).get("identifier") or "")
    if not controller_id or str(evidence.get("controller_identifier") or "") != controller_id:
        raise DemoError("Silence preflight controller identity does not match the plan")
    captured = float(evidence.get("captured_at_epoch", 0))
    max_age = float(config.get("max_age_seconds", 1800))
    age = time.time() - captured
    if captured <= 0 or age < -60 or age > max_age:
        raise DemoError(f"Silence preflight evidence is stale or future-dated: age={age:.1f}s")
    artifacts = evidence.get("artifacts") or {}
    verified_artifacts: dict[str, str] = {}
    for key in ("source_xml", "screenshot"):
        artifact = Path(str(artifacts.get(key) or ""))
        if not artifact.is_absolute():
            artifact = evidence_path.parent / artifact
        artifact = artifact.resolve()
        if not artifact.is_file() or artifact.stat().st_size <= 0:
            raise DemoError(f"Silence preflight artifact is missing or empty: {key}={artifact}")
        verified_artifacts[key] = str(artifact)
    return {
        "evidence_file": str(evidence_path),
        "evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "captured_at_epoch": captured,
        "media_volume_percent": 0,
        "controller_identifier": controller_id,
        "artifacts": verified_artifacts,
        "artifacts_sha256": {
            key: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for key, path in verified_artifacts.items()
        },
    }


def materialize_silence_preflight(root: Path, evidence: dict[str, Any]) -> dict[str, Any]:
    """Keep controller proof inside each run's complete raw evidence archive."""
    destination = root / "controller_evidence" / "silence"
    destination.mkdir(parents=True, exist_ok=True)
    source_file = Path(evidence["evidence_file"])
    raw = source_file.read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence["evidence_sha256"]:
        raise DemoError("Silence evidence changed before its run-local copy")
    payload = json.loads(raw.decode("utf-8-sig"))
    artifacts: dict[str, str] = {}
    hashes: dict[str, str] = {}
    for key, filename in (("source_xml", "source.xml"), ("screenshot", "screenshot.png")):
        content = Path(evidence["artifacts"][key]).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != evidence["artifacts_sha256"][key]:
            raise DemoError(f"Silence artifact changed before its run-local copy: {key}")
        target = destination / filename
        if target.exists() and target.read_bytes() != content:
            raise DemoError(f"Refusing conflicting run-local silence artifact: {key}")
        target.write_bytes(content)
        artifacts[key], hashes[key] = str(target.resolve()), digest
    payload["artifacts"] = {key: Path(path).name for key, path in artifacts.items()}
    local_file = destination / "evidence.json"
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if local_file.exists() and local_file.read_bytes() != encoded:
        raise DemoError("Refusing conflicting run-local silence evidence")
    local_file.write_bytes(encoded)
    return {
        **evidence,
        "source_evidence_file": str(source_file),
        "source_evidence_sha256": evidence["evidence_sha256"],
        "evidence_file": str(local_file.resolve()),
        "evidence_sha256": hashlib.sha256(encoded).hexdigest(),
        "artifacts": artifacts,
        "artifacts_sha256": hashes,
    }


def condition_matches(source: str, condition: dict[str, Any]) -> bool:
    """Evaluate a serializable, positive UI condition."""
    if "selector" in condition:
        expected = int(condition.get("count", 1))
        return len(select(source, condition["selector"])) == expected
    if "contains" in condition:
        return str(condition["contains"]) in source
    if "all" in condition:
        values = list(condition["all"])
        return bool(values) and all(condition_matches(source, value) for value in values)
    if "any" in condition:
        values = list(condition["any"])
        return bool(values) and any(condition_matches(source, value) for value in values)
    raise DemoError(f"Unsupported UI condition: {condition}")


def radial_target(element: ET.Element, target_percent: int, config: dict[str, Any]) -> dict[str, int]:
    """Map a percentage to a point on a configured circular volume arc."""
    if not 0 <= target_percent <= 100:
        raise DemoError(f"Volume target is outside 0..100: {target_percent}")
    cx = int(element.attrib["x"]) + int(element.attrib["width"]) / 2
    cy = int(element.attrib["y"]) + int(element.attrib["height"]) / 2
    radius_fraction = float(config.get("radius_fraction", 0.42))
    if not 0 < radius_fraction <= 0.5:
        raise DemoError("radial volume radius_fraction must be inside 0..0.5")
    radius = min(int(element.attrib["width"]), int(element.attrib["height"])) * radius_fraction
    start = float(config.get("start_degrees", 135))
    end = float(config.get("end_degrees", 405))
    angle = math.radians(start + (end - start) * target_percent / 100.0)
    return {"x": round(cx + radius * math.cos(angle)), "y": round(cy + radius * math.sin(angle))}


def volume_pair(plan: dict[str, Any], device: dict[str, Any], cycle: int) -> tuple[int, int]:
    policy = plan["parameter_policy"]["smart_speaker_volume"]
    seed = f"{int(policy['random_seed'])}:{device['id']}:{cycle}"
    rng = random.Random(seed)
    low_min, low_max = map(int, policy["low_range_percent"])
    high_min, high_max = map(int, policy["high_range_percent"])
    step = int(policy.get("step_percent", 5))
    minimum = int(policy.get("minimum_change_percent", 20))
    lows = list(range(low_min, low_max + 1, step))
    highs = list(range(high_min, high_max + 1, step))
    pairs = [(low, high) for low in lows for high in highs if high - low >= minimum]
    if not pairs:
        raise DemoError("smart-speaker volume policy has no valid transition")
    return rng.choice(pairs)


def intents_for_cycle(plan: dict[str, Any], device: dict[str, Any], cycle: int) -> list[MediaIntent]:
    actions = tuple(device["actions"])
    if device["device_type"] in {"smart_camera", "video_doorbell"}:
        known = {
            "live_view_start": MediaIntent("live_view_start", "closed", "playing"),
            "live_view_stop": MediaIntent("live_view_stop", "playing", "closed"),
            "talk_session": MediaIntent("talk_session", "playing", "playing"),
        }
    else:
        known = {
            "play": MediaIntent("play", "paused", "playing"),
            "pause": MediaIntent("pause", "playing", "paused"),
        }
        if set(actions) & {"volume_up", "volume_down"}:
            low, high = volume_pair(plan, device, cycle)
            known.update({
                "volume_up": MediaIntent("volume_up", low, high),
                "volume_down": MediaIntent("volume_down", high, low),
            })
    return [known[action] for action in actions]


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("control_platform") not in {"apple_home", "alexa", "google_home"}:
        raise DemoError("control_platform must be apple_home, alexa, or google_home")
    if int(plan.get("target_valid_per_action", 0)) <= 0:
        raise DemoError("target_valid_per_action must be positive")
    if int(plan.get("cycle_start", 1)) <= 0:
        raise DemoError("cycle_start must be positive")
    if type(plan.get("sample_index_offset", 0)) is not int or plan.get("sample_index_offset", 0) < 0:
        raise DemoError("sample_index_offset must be a non-negative integer")
    for key in ("application_bundle_id", "wda_url"):
        if not (plan.get("controller") or {}).get(key):
            raise DemoError(f"controller is missing {key}")
    if not (plan.get("controller") or {}).get("identifier"):
        raise DemoError("controller is missing identifier")
    silence = plan.get("silence_preflight") or {}
    has_silent_media = any(
        camera_action(device, str(action))
        or (
            speaker_playback_action(device, str(action))
            and manages_playback_volume(device)
        )
        for device in (plan.get("devices") or [])
        for action in (device.get("actions") or [])
    )
    if has_silent_media and (
        not silence.get("evidence_file") or float(silence.get("max_age_seconds", 0)) <= 0
    ):
        raise DemoError("camera and speaker-playback plans need silence preflight evidence")
    for key in ("host", "user", "interface", "capture_transport_host"):
        if not (plan.get("router") or {}).get(key):
            raise DemoError(f"router is missing {key}")
    devices = list(plan.get("devices") or [])
    if not devices:
        raise DemoError("plan has no devices")
    ids = [str(device.get("id") or "") for device in devices]
    if "" in ids or len(ids) != len(set(ids)):
        raise DemoError("device ids must be non-empty and unique")
    for device in devices:
        for key in ("brand", "model", "device_type", "name"):
            if not device.get(key):
                raise DemoError(f"{device['id']} is missing exact {key}")
        actions = tuple(device.get("actions") or ())
        if not actions or any(action not in MEDIA_ACTIONS for action in actions):
            raise DemoError(f"{device['id']} has invalid actions")
        for key in ("baseline_seconds", "tail_seconds", "poll_seconds", "state_timeout_seconds"):
            if float(device.get(key, 0)) <= 0:
                raise DemoError(f"{device['id']} has invalid {key}")
        tail_seconds_by_action = device.get("tail_seconds_by_action") or {}
        unknown_tail_actions = set(tail_seconds_by_action) - set(actions)
        if unknown_tail_actions:
            raise DemoError(f"{device['id']} has tail durations for unknown actions: {sorted(unknown_tail_actions)}")
        if any(float(value) <= 0 for value in tail_seconds_by_action.values()):
            raise DemoError(f"{device['id']} has a non-positive action-specific tail duration")
        for key in (
            "inter_action_cooldown_seconds",
            "inter_cycle_cooldown_seconds",
            "failure_cooldown_seconds",
        ):
            if float(device.get(key, 0)) < 0:
                raise DemoError(f"{device['id']} has invalid {key}")
        if "cold_launch_before_live_view_start" in device and not isinstance(
            device["cold_launch_before_live_view_start"], bool
        ):
            raise DemoError(f"{device['id']} has invalid cold_launch_before_live_view_start")
        if float(device.get("cold_launch_settle_seconds", 2)) < 0:
            raise DemoError(f"{device['id']} has invalid cold_launch_settle_seconds")
        if device.get("verified_ips") is not None:
            values = device["verified_ips"]
            if not isinstance(values, list) or not values:
                raise DemoError(f"{device['id']} needs a nonempty verified_ips list")
            try:
                device["verified_ips"] = sorted({str(ipaddress.ip_address(value)) for value in values})
            except ValueError as exc:
                raise DemoError(f"{device['id']} has invalid verified_ips") from exc
            if str(device.get("ip")) not in device["verified_ips"]:
                raise DemoError(f"{device['id']} primary IP is absent from verified_ips")
        ui = device.get("ui") or {}
        if not ui.get("page_condition"):
            raise DemoError(f"{device['id']} needs an exact page_condition")
        if device.get("open_method") == "platform_selector" and not ui.get("entry_selector"):
            raise DemoError(f"{device['id']} platform_selector needs entry_selector")
        condition_matches("<root />", ui["page_condition"])
        if device["device_type"] in {"smart_camera", "video_doorbell"}:
            if set(actions) - {"live_view_start", "live_view_stop", "talk_session"}:
                raise DemoError(f"{device['id']} mixes camera and speaker actions")
            if not ui.get("playing_condition") or not ui.get("closed_condition") or not ui.get("close_selector"):
                raise DemoError(f"{device['id']} needs positive playing, closed, and close-control evidence")
            condition_matches("<root />", ui["playing_condition"])
            condition_matches("<root />", ui["closed_condition"])
            identity = ui.get("settings_identity")
            if identity:
                if plan["control_platform"] != "apple_home":
                    raise DemoError("Camera settings identity is only supported for Apple Home")
                for key in ("open_selector", "name_selector", "close_selector", "live_condition", "stream_condition"):
                    if not identity.get(key):
                        raise DemoError(f"{device['id']} camera settings identity is missing {key}")
                name = identity["name_selector"]
                if name.get("type") != "XCUIElementTypeTextField" or name.get("value") != device["name"] or name.get("visible") not in (True, "true"):
                    raise DemoError("Camera settings identity needs the exact visible native name field")
                condition_matches("<root />", identity["live_condition"])
                condition_matches("<root />", identity["stream_condition"])
            if "talk_session" in actions:
                for key in ("talk_start_selector", "talk_stop_selector", "talking_condition"):
                    if not ui.get(key):
                        raise DemoError(f"{device['id']} talk session is missing {key}")
                condition_matches("<root />", ui["talking_condition"])
                speaker_keys = (
                    "speaker_start_selector", "speaker_stop_selector",
                    "speaker_on_condition", "speaker_off_condition",
                )
                supplied = [key for key in speaker_keys if ui.get(key)]
                if supplied and len(supplied) != len(speaker_keys):
                    missing = [key for key in speaker_keys if not ui.get(key)]
                    raise DemoError(f"{device['id']} talk speaker controls are incomplete: {missing}")
                for key in ("speaker_on_condition", "speaker_off_condition"):
                    if ui.get(key):
                        condition_matches("<root />", ui[key])
            if device.get("open_method") == "alexa_text_chat":
                for key in ("entry_selector", "chat_input_selector", "chat_send_selector", "text_command"):
                    if not ui.get(key):
                        raise DemoError(f"{device['id']} Alexa text-chat route is missing {key}")
        elif device["device_type"] in PLAYBACK_DEVICE_TYPES:
            if set(actions) - {"volume_up", "volume_down", "play", "pause"}:
                raise DemoError(f"{device['id']} mixes speaker and camera actions")
            volume = ui.get("volume") or {}
            volume_actions = set(actions) & {"volume_up", "volume_down"}
            playback_actions = set(actions) & {"play", "pause"}
            if volume_actions and not ui.get("idle_condition"):
                raise DemoError(f"{device['id']} needs idle evidence for volume actions")
            managed_playback_actions = playback_actions if manages_playback_volume(device) else set()
            if (volume_actions or managed_playback_actions) and not volume.get("selector"):
                raise DemoError(f"{device['id']} needs a volume selector")
            if (volume_actions or managed_playback_actions) and volume.get("mode") not in {
                "linear", "radial", "hardware_buttons"
            }:
                raise DemoError(
                    f"{device['id']} volume mode must be linear, radial, or hardware_buttons"
                )
            if volume.get("mode") == "hardware_buttons":
                if int(volume.get("max_button_presses", 0)) <= 0:
                    raise DemoError(
                        f"{device['id']} hardware_buttons needs positive max_button_presses"
                    )
                if float(volume.get("button_press_interval_seconds", 0.4)) < 0:
                    raise DemoError(
                        f"{device['id']} has invalid button_press_interval_seconds"
                    )
            if volume.get("mode") == "linear" and volume.get("gesture", "drag") not in {"drag", "tap"}:
                raise DemoError(f"{device['id']} linear volume gesture must be drag or tap")
            if volume.get("mode") == "linear" and not (
                0 <= float(volume.get("track_start_fraction", 0.0))
                < float(volume.get("track_end_fraction", 1.0)) <= 1
            ):
                raise DemoError(
                    f"{device['id']} volume track fractions must satisfy 0 <= start < end <= 1"
                )
            if volume.get("mode") == "linear" and not (
                0 <= float(volume.get("endpoint_drag_padding_fraction", 0.0)) <= 0.15
            ):
                raise DemoError(f"{device['id']} endpoint drag padding must be between 0 and 0.15")
            if volume.get("mode") == "linear" and "drag_distance_span_fraction" in volume and not (
                0 < float(volume["drag_distance_span_fraction"]) <= 1
            ):
                raise DemoError(f"{device['id']} drag distance span must be between 0 exclusive and 1")
            if volume.get("mode") == "linear" and not (
                0 <= float(volume.get("drag_start_padding_fraction", 0.0)) <= 0.1
            ):
                raise DemoError(f"{device['id']} drag start padding must be between 0 and 0.1")
            if (volume_actions or managed_playback_actions) and int(device.get("volume_command_attempts", 1)) <= 0:
                raise DemoError(f"{device['id']} volume_command_attempts must be positive")
            if (volume_actions or managed_playback_actions) and float(device.get("volume_attempt_timeout_seconds", device["state_timeout_seconds"])) <= 0:
                raise DemoError(f"{device['id']} volume_attempt_timeout_seconds must be positive")
            if volume_actions:
                condition_matches("<root />", ui["idle_condition"])
            if playback_actions:
                for key in ("playing_condition", "paused_condition", "play_selector", "pause_selector"):
                    if not ui.get(key):
                        raise DemoError(f"{device['id']} speaker playback is missing {key}")
                condition_matches("<root />", ui["playing_condition"])
                condition_matches("<root />", ui["paused_condition"])
                if not manages_playback_volume(device):
                    continue
                if int(device.get("silent_volume_percent", -1)) != 0:
                    raise DemoError(f"{device['id']} speaker playback must set silent_volume_percent=0")
                volume_panel_keys = {
                    "volume_panel_open_selector",
                    "volume_panel_condition",
                    "volume_panel_back_selector",
                }
                configured_volume_panel_keys = volume_panel_keys & set(ui)
                if configured_volume_panel_keys and configured_volume_panel_keys != volume_panel_keys:
                    missing = sorted(volume_panel_keys - configured_volume_panel_keys)
                    raise DemoError(
                        f"{device['id']} volume panel configuration is missing {missing}"
                    )
                if ui.get("volume_panel_condition"):
                    condition_matches("<root />", ui["volume_panel_condition"])
        else:
            raise DemoError(f"Unsupported device_type for {device['id']}: {device['device_type']}")
    load_talk_audio(plan)


class SilentMediaUI:
    def __init__(self, plan: dict[str, Any], wda: WDA, log: EventLog) -> None:
        self.plan, self.wda, self.log = plan, wda, log
        self.platform = str(plan["control_platform"])
        self.bundle_id = str(plan["controller"]["application_bundle_id"])
        self.google = GoogleHomeUI(wda, log, self.bundle_id) if self.platform == "google_home" else None
        self.command_attempts: list[dict[str, Any]] = []
        self.active_camera_device_id: str | None = None
        self.active_camera_playing_confirmed = False
        self.confirmed_volumes: dict[str, int] = {}
        self.camera_identity_evidence: dict[str, dict[str, Any]] = {}

    def reset_command_timing(self) -> None:
        self.command_attempts = []

    def _gesture(self, *, device: dict[str, Any], action_kind: str, callback: Callable[[], None], **details: Any) -> None:
        started = time.time()
        self.log.write(
            "silent_media_gesture_start", device=device["id"],
            action_kind=action_kind, epoch=started, **details,
        )
        callback()
        completed = time.time()
        attempt = {
            "attempt": len(self.command_attempts) + 1,
            "gesture_start_epoch": started,
            "gesture_complete_epoch": completed,
            "gesture_action_kind": action_kind,
            **details,
        }
        self.command_attempts.append(attempt)
        self.log.write(
            "silent_media_gesture_complete", device=device["id"],
            action_kind=action_kind, epoch=completed, **details,
        )

    def foreground(self) -> bool:
        return self.wda.active_bundle_id() == self.bundle_id

    def dismiss_alexa_transient_error(
        self, source: str, device: dict[str, Any], log: EventLog
    ) -> str:
        if self.platform != "alexa":
            return source
        message = "Sorry, something went wrong. Try again in a few minutes."
        errors = select(
            source,
            {"type": "XCUIElementTypeStaticText", "name": message, "label": message},
        )
        controls = select(
            source,
            {"type": "XCUIElementTypeButton", "name": "Ok", "label": "Ok", "visible": True},
        )
        if errors and controls:
            log.write(
                "silent_media_alexa_service_error",
                device=device["id"], message=message,
            )
            raise DemoError(f"{device['id']}: Alexa service error; UI state is not success evidence")
        if controls:
            log.write("silent_media_alexa_unknown_dialog", device=device["id"])
            raise DemoError(f"{device['id']}: unrecognized Alexa dialog blocks state verification")
        return source

    def dashboard_state(self, source: str) -> bool:
        marker = self.plan.get("dashboard_condition")
        if marker:
            return condition_matches(source, marker)
        defaults = {
            "google_home": "HomeRootViewController_mainContentView",
            "alexa": "DevicePageSearchButton",
            "apple_home": "Home.Tab.家庭",
        }
        return defaults[self.platform] in source

    def dismiss_apple_home_accessory_sheet(
        self, source: str, device: dict[str, Any]
    ) -> str:
        """Dismiss Apple Home's restored accessory sheet without a close button."""
        if self.platform != "apple_home":
            return source
        sheets = select(
            source,
            {
                "type": "XCUIElementTypeScrollView",
                "name": "AccessoryControl.SheetView",
            },
        )
        if len(sheets) != 1:
            return source
        sheet = sheets[0]
        x = int(sheet.attrib["x"]) + max(20, int(int(sheet.attrib["width"]) * 0.08))
        y = int(sheet.attrib["y"])
        height = int(sheet.attrib["height"])
        start = {"x": x, "y": y + int(height * 0.15)}
        end = {"x": x, "y": y + int(height * 0.90)}
        self.log.write(
            "silent_media_dismiss_apple_home_accessory_sheet",
            device=device["id"], point_start=start, point_end=end,
        )
        self.wda.drag(start, end, 0.9)
        time.sleep(float(self.plan.get("detail_close_wait_seconds", 2)))
        return self.wda.source()

    def dashboard(self, device: dict[str, Any]) -> str:
        self.wda.launch(self.bundle_id)
        time.sleep(float(self.plan.get("launch_wait_seconds", 3)))
        if not self.foreground():
            raise DemoError(f"{self.platform} is not foreground")
        if self.platform == "google_home":
            assert self.google is not None
            return self.google.dashboard()
        source = self.wda.source()
        source = self.dismiss_alexa_transient_error(source, device, self.log)
        camera_spec = device["ui"].get("settings_identity")
        if (self.platform == "apple_home" and camera_spec
                and not self.dashboard_state(source)
                and not select(source, device["ui"].get("close_selector", {}))
                and condition_matches(source, camera_spec["stream_condition"])):
            point = camera_video_point(source, allow_unnamed=True)
            self.log.write("silent_media_reveal_restored_camera_controls", point=point)
            self.wda.tap(point)
            time.sleep(1)
            source = self.wda.source()
        if self.platform == "apple_home":
            now_playing_close = select(
                source,
                {"type": "XCUIElementTypeButton", "name": "NowPlayingDismissButton"},
            )
            if len(now_playing_close) == 1:
                point = center(now_playing_close[0])
                self.log.write(
                    "silent_media_close_apple_home_now_playing",
                    device=device["id"], point=point,
                )
                self.wda.tap(point)
                time.sleep(2)
                source = self.wda.source()
        if self.platform == "alexa":
            for _ in range(3):
                back = []
                for name in (
                    "now_playing_screen_header_back_button",
                    "volume_control_slider_header_back_button",
                ):
                    back = select(
                        source,
                        {"type": "XCUIElementTypeButton", "name": name},
                    )
                    if back:
                        break
                if len(back) != 1:
                    break
                point = center(back[0])
                self.log.write(
                    "silent_media_restore_alexa_dashboard", point=point,
                )
                self.wda.tap(point)
                time.sleep(2)
                source = self.wda.source()
        if (
            device["device_type"] in PLAYBACK_DEVICE_TYPES
            and condition_matches(source, device["ui"]["page_condition"])
            and device["ui"].get("close_selector")
        ):
            close = select(source, device["ui"]["close_selector"])
            if len(close) == 0 and self.platform == "apple_home":
                source = self.dismiss_apple_home_accessory_sheet(source, device)
            elif len(close) != 1:
                raise DemoError(
                    f"Speaker detail close control is not unique for {device['id']}: {len(close)}"
                )
            else:
                point = center(close[0])
                self.log.write(
                    "silent_media_close_restored_speaker_detail",
                    device=device["id"], point=point,
                )
                self.wda.tap(point)
                time.sleep(2)
                source = self.wda.source()
        # Alexa keeps the Devices page mounted behind restored bottom sheets.
        # Looking for the dashboard marker first therefore produces a false
        # positive and leaves the sheet blocking every device control.  Always
        # dismiss a restored detail before confirming the dashboard.
        source = dismiss_restored_detail(self.platform, source, self.wda, self.log)
        if self.dashboard_state(source):
            self.active_camera_device_id = None
            self.active_camera_playing_confirmed = False
            self.camera_identity_evidence = {}
            return ensure_dashboard(self.platform, source, self.wda, self.log)
        close_selector = device["ui"].get("close_selector")
        close = select(source, close_selector) if close_selector else []
        if len(close) == 1:
            point = center(close[0])
            self.log.write("silent_media_restore_dashboard", device=device["id"], point=point)
            self.wda.tap(point)
            time.sleep(2)
            source = self.wda.source()
            source = self.dismiss_alexa_transient_error(source, device, self.log)
        source = dismiss_restored_detail(self.platform, source, self.wda, self.log)
        source = ensure_dashboard(self.platform, source, self.wda, self.log)
        if not self.dashboard_state(source):
            raise DemoError(f"{self.platform} dashboard is not confirmed")
        self.active_camera_device_id = None
        self.active_camera_playing_confirmed = False
        self.camera_identity_evidence = {}
        return source

    def verify_camera_settings_identity(self, device: dict[str, Any], source: str) -> str:
        spec = device["ui"].get("settings_identity")
        if not spec or self.platform != "apple_home" or self.active_camera_device_id != str(device["id"]):
            raise DemoError("Camera settings identity requires the exact selected Apple Home tile")
        if not select(source, spec["open_selector"]) and condition_matches(source, spec["stream_condition"]):
            self.wda.tap(camera_video_point(source, allow_unnamed=True))
            time.sleep(1)
            source = self.wda.source()
        entry = select_one(source, spec["open_selector"], "camera identity settings")
        self.wda.tap(center(entry))
        time.sleep(2)
        settings = self.wda.source()
        field = select_one(settings, spec["name_selector"], "exact camera accessory name")
        if field.attrib.get("value") != device["name"]:
            raise DemoError(f"Camera accessory name does not match {device['name']}")
        path = self.log.path.parent / "camera_identity" / f"{device['id']}-{time.time_ns()}.xml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(settings, encoding="utf-8")
        self.camera_identity_evidence[device["id"]] = {
            "device_id": device["id"], "device_name": device["name"],
            "source_xml": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "verified_epoch": time.time(), "name_selector": spec["name_selector"],
        }
        close = select_one(settings, spec["close_selector"], "camera identity settings close")
        self.wda.tap(center(close))
        time.sleep(2)
        returned = self.wda.source()
        if self.dashboard_state(returned):
            target = find_target(self.platform, returned, str(device["name"]))
            if target is None or not target_is_hittable(self.platform, target):
                raise DemoError("Exact camera tile is unavailable after closing its identity settings")
            self.wda.tap(center(target))
            time.sleep(float(device.get("open_wait_seconds", 3)))
            returned = self.wda.source()
        if not condition_matches(returned, spec["live_condition"]) and condition_matches(returned, spec["stream_condition"]):
            self.wda.tap(camera_video_point(returned, allow_unnamed=True))
            time.sleep(1)
            returned = self.wda.source()
        if not condition_matches(returned, spec["live_condition"]):
            raise DemoError("Verified camera did not return to its native live view")
        camera_video_point(returned, allow_unnamed=True)
        self.active_camera_playing_confirmed = True
        self.log.write("camera_settings_identity_verified", **self.camera_identity_evidence[device["id"]])
        return returned

    def open_device(self, device: dict[str, Any]) -> str:
        if self.foreground():
            source = self.wda.source()
            source = self.dismiss_alexa_transient_error(source, device, self.log)
            if condition_matches(source, device["ui"]["page_condition"]):
                if device["device_type"] in PLAYBACK_DEVICE_TYPES or self.page_state(device, source) in {
                    "playing", "loading", "unavailable", "detail"
                }:
                    return source
        if device.get("open_method") == "alexa_text_chat":
            if self.platform != "alexa":
                raise DemoError("alexa_text_chat is only valid for the Alexa platform")
            source = self.dashboard(device)
            prepare = device["ui"].get("entry_prepare_selector")
            if prepare:
                matches = select(source, prepare)
                if len(matches) != 1:
                    raise DemoError(f"Alexa text-chat preparation control is not unique: {len(matches)}")
                self.wda.tap(center(matches[0]))
                time.sleep(3)
                source = self.wda.source()
            entry = select_one(source, device["ui"]["entry_selector"], "Alexa device entry")
            self.wda.tap(center(entry))
            time.sleep(3)
            source = self.wda.source()
            chat_input = select_one(source, device["ui"]["chat_input_selector"], "Alexa chat input")
            current = str(chat_input.attrib.get("value") or "").strip()
            if current:
                raise DemoError(f"Alexa chat input is not empty: {current!r}")
            self.wda.tap(center(chat_input))
            time.sleep(1)
            self.wda.request("POST", "/wda/keys", {"value": [str(device["ui"]["text_command"])]})
            time.sleep(1)
            source = self.wda.source()
            send = select_one(source, device["ui"]["chat_send_selector"], "Alexa chat send")
            self.wda.tap(center(send))
            time.sleep(float(device.get("open_wait_seconds", 20)))
            source = self.wda.source()
            if not condition_matches(source, device["ui"]["page_condition"]):
                raise DemoError(f"Alexa text command did not open {device['id']}")
            play_selector = device["ui"].get("play_selector")
            if play_selector:
                matches = select(source, play_selector)
                if len(matches) == 1:
                    self.wda.tap(center(matches[0]))
                    time.sleep(float(device.get("play_wait_seconds", 15)))
                    source = self.wda.source()
                elif len(matches) > 1:
                    raise DemoError(f"Alexa play control is not unique: {len(matches)}")
            return source
        if device.get("open_method") == "platform_selector":
            source = self.dashboard(device)
            entry = select_one(
                source,
                device["ui"]["entry_selector"],
                f"{self.platform} media entry",
            )
            point = center(entry)
            self.log.write(
                "silent_media_open_platform_entry",
                device=device["id"], point=point,
            )
            self._gesture(
                device=device, action_kind="tap",
                callback=lambda: self.wda.tap(point), point=point,
            )
            time.sleep(float(device.get("open_wait_seconds", 3)))
            source = self.wda.source()
            if not condition_matches(source, device["ui"]["page_condition"]):
                raise DemoError(f"Platform media entry did not open {device['id']}")
            return source
        if self.platform == "google_home":
            assert self.google is not None
            _, target = self.google.visible_tile(device)
        else:
            source = self.dashboard(device)
            target = find_target(self.platform, source, str(device["name"]))
            for attempt in range(8):
                if target is not None and target_is_hittable(self.platform, target):
                    break
                self.log.write("silent_media_target_scroll", device=device["id"], attempt=attempt + 1)
                scroll_toward_target(self.platform, target, self.wda, source=source, target_name=str(device["name"]))
                time.sleep(2)
                source = self.wda.source()
                target = find_target(self.platform, source, str(device["name"]))
            if target is None:
                raise DemoError(f"Device tile not found: {device['name']}")
            if not target_is_hittable(self.platform, target):
                raise DemoError(f"Device tile did not reach the safe tap region: {device['name']}")
        point = center(target)
        if device["device_type"] in {"smart_camera", "video_doorbell"}:
            # The exact tile was positively identified immediately before this
            # gesture.  Apple Home later auto-hides the title and controls, so
            # keep that identity while separately requiring a confirmed live
            # state before accepting its generic full-screen video surface.
            self.active_camera_device_id = str(device["id"])
            self.active_camera_playing_confirmed = False
        gesture = str(device.get("open_gesture", "tap"))
        self.log.write("silent_media_open_device", device=device["id"], gesture=gesture, point=point)
        if gesture == "long_press":
            self._gesture(
                device=device, action_kind="long_press",
                callback=lambda: self.wda.long_press(point, float(device.get("open_press_seconds", 0.9))),
                point=point,
            )
        elif gesture == "tap":
            self._gesture(device=device, action_kind="tap", callback=lambda: self.wda.tap(point), point=point)
        else:
            raise DemoError(f"Unsupported open gesture: {gesture}")
        time.sleep(float(device.get("open_wait_seconds", 3)))
        source = self.wda.source()
        if device["ui"].get("settings_identity"):
            source = self.verify_camera_settings_identity(device, source)
        return source

    def page_state(self, device: dict[str, Any], source: str) -> str:
        ui = device["ui"]
        if self.dashboard_state(source) or (ui.get("closed_condition") and condition_matches(source, ui["closed_condition"])):
            if self.dashboard_state(source):
                self.active_camera_device_id = None
                self.active_camera_playing_confirmed = False
            return "closed"
        # A camera's error/loading overlay can replace its accessible title.
        # Check it before cached identity or hidden-control playback handling.
        if device["device_type"] in {"smart_camera", "video_doorbell"}:
            for state, key in (("unavailable", "unavailable_condition"), ("loading", "loading_condition")):
                if ui.get(key) and condition_matches(source, ui[key]):
                    self.active_camera_playing_confirmed = False
                    return state
        exact_page = condition_matches(source, ui["page_condition"])
        if not exact_page:
            proof = getattr(self, "camera_identity_evidence", {}).get(device["id"])
            spec = ui.get("settings_identity")
            if (proof and spec and self.active_camera_device_id == str(device["id"])
                    and (condition_matches(source, spec["live_condition"])
                         or (self.active_camera_playing_confirmed
                             and condition_matches(source, spec["stream_condition"])))):
                camera_video_point(source, allow_unnamed=True)
                self.active_camera_playing_confirmed = True
                return "playing"
            if (
                self.platform == "apple_home"
                and self.active_camera_device_id == str(device["id"])
                and self.active_camera_playing_confirmed
                and len(select(source, {"type": "XCUIElementTypeOther", "name": "视频"})) == 1
                and ui.get("playing_condition")
                and condition_matches(source, ui["playing_condition"])
            ):
                return "playing"
            return "unknown"
        for state, key in (
            ("unavailable", "unavailable_condition"),
            ("loading", "loading_condition"),
            ("talking", "talking_condition"),
            ("paused", "paused_condition"),
            ("playing", "playing_condition"),
        ):
            if ui.get(key) and condition_matches(source, ui[key]):
                if state == "playing" and device["device_type"] in {"smart_camera", "video_doorbell"}:
                    self.active_camera_device_id = str(device["id"])
                    self.active_camera_playing_confirmed = True
                return state
        if device["device_type"] in PLAYBACK_DEVICE_TYPES and ui.get("idle_condition") and condition_matches(source, ui["idle_condition"]):
            return "detail"
        return "unknown"

    def wait_state(
        self,
        device: dict[str, Any],
        expected: str,
        log: EventLog,
        *,
        required_volume: int | None = None,
    ) -> tuple[str, str]:
        deadline, last = time.time() + float(device["state_timeout_seconds"]), "unknown"
        play_attempts = 0
        play_attempt_limit = int(device.get("play_command_attempts", 2))
        while time.time() < deadline:
            time.sleep(float(device["poll_seconds"]))
            if not self.foreground():
                last = "foreground_mismatch"
                log.write("silent_media_state_poll", state=last, expected=expected)
                continue
            source = self.wda.source()
            source = self.dismiss_alexa_transient_error(source, device, log)
            if (
                expected == "talking"
                and self.platform == "apple_home"
                and self.active_camera_device_id == str(device["id"])
                and 'name="视频"' in source
                and not condition_matches(source, device["ui"]["talking_condition"])
            ):
                # Apple Home immediately auto-hides the camera overlay after
                # Talk is activated.  Reveal it before deciding that the
                # state is still merely playing; the visible Done control is
                # the positive evidence that two-way audio is active.
                point = camera_video_point(source, allow_unnamed=bool(getattr(self, "camera_identity_evidence", {}).get(device["id"])))
                log.write("silent_media_reveal_controls_for_talk_confirmation", device=device["id"], point=point)
                self.wda.tap(point)
                time.sleep(1)
                source = self.wda.source()
            if (
                expected == "playing"
                and self.platform == "apple_home"
                and self.active_camera_device_id == str(device["id"])
                and not self.active_camera_playing_confirmed
                and 'name="视频"' in source
            ):
                point = camera_video_point(source, allow_unnamed=bool(getattr(self, "camera_identity_evidence", {}).get(device["id"])))
                log.write("silent_media_reveal_controls_for_confirmation", device=device["id"], point=point)
                self.wda.tap(point)
                time.sleep(1)
                source = self.wda.source()
            play_selector = device["ui"].get("play_selector")
            if (
                expected == "playing"
                and device["device_type"] in {"smart_camera", "video_doorbell"}
                and play_selector
                and condition_matches(source, device["ui"]["page_condition"])
                and play_attempts < play_attempt_limit
            ):
                controls = select(source, play_selector)
                if len(controls) > 1:
                    raise DemoError(f"{device['id']} play control is not unique: {len(controls)}")
                if len(controls) == 1:
                    point = center(controls[0])
                    play_attempts += 1
                    log.write(
                        "silent_media_play_control",
                        device=device["id"], attempt=play_attempts, point=point,
                    )
                    self._gesture(
                        device=device,
                        action_kind="tap",
                        callback=lambda: self.wda.tap(point),
                        point=point,
                    )
                    time.sleep(float(device.get("play_wait_seconds", 10)))
                    continue
            last = self.page_state(device, source)
            observed_volume = None
            if required_volume is not None and last == expected:
                volume_config = device["ui"]["volume"]
                volumes = select(source, volume_config["selector"])
                if len(volumes) == 1:
                    observed_volume = percentage(
                        volumes[0].attrib.get(str(volume_config.get("attribute", "value")))
                    )
            log.write(
                "silent_media_state_poll",
                state=last,
                expected=expected,
                required_volume=required_volume,
                observed_volume=observed_volume,
            )
            if last == "unavailable":
                raise DemoError(f"{device['id']} reported unavailable")
            if last == expected and (
                required_volume is None
                or (
                    observed_volume is not None
                    and abs(observed_volume - required_volume)
                    <= int(device.get("volume_tolerance", 5))
                )
            ):
                return last, source
        raise DemoError(f"State confirmation timed out for {device['id']}: expected={expected}, last={last}")

    def wait_ui_condition(
        self, device: dict[str, Any], condition_key: str, description: str, log: EventLog,
    ) -> str:
        deadline = time.time() + float(device["state_timeout_seconds"])
        while time.time() < deadline:
            time.sleep(float(device["poll_seconds"]))
            if not self.foreground():
                log.write("silent_media_condition_poll", condition=condition_key, matched=False, state="foreground_mismatch")
                continue
            source = self.wda.source()
            if device["ui"].get("unavailable_condition") and condition_matches(
                source, device["ui"]["unavailable_condition"]
            ):
                raise DemoError(f"{device['id']} reported unavailable")
            matched = condition_matches(source, device["ui"][condition_key])
            log.write("silent_media_condition_poll", condition=condition_key, matched=matched)
            if matched:
                return source
        raise DemoError(f"{description} was not confirmed for {device['id']}")

    def close_device(self, device: dict[str, Any]) -> None:
        self.tap_camera_control(device, "close_selector", "media close control")

    def tap_camera_control(self, device: dict[str, Any], selector_key: str, description: str) -> None:
        source = self.wda.source()
        selector = device["ui"][selector_key]
        if isinstance(selector, dict) and isinstance(selector.get("any"), list):
            controls = []
            for candidate in selector["any"]:
                controls.extend(select(source, candidate.get("selector", candidate)))
        else:
            controls = select(source, selector)
        if not controls and self.platform == "apple_home":
            # Apple Home hides the live-view overlay after a few seconds.  A
            # tap in the video area restores the close/talk controls without
            # changing the stream state.
            point = camera_video_point(source, allow_unnamed=bool(getattr(self, "camera_identity_evidence", {}).get(device["id"])))
            self.log.write("silent_media_reveal_controls", device=device["id"], point=point)
            self.wda.tap(point)
            time.sleep(1)
            source = self.wda.source()
            controls = select(source, device["ui"][selector_key])
        if len(controls) != 1:
            raise DemoError(f"{description} must match exactly once, got {len(controls)}")
        element = controls[0]
        point = center(element)
        self.log.write(
            "silent_media_camera_control", device=device["id"],
            selector_key=selector_key, description=description, point=point,
        )
        self._gesture(
            device=device,
            action_kind="tap",
            callback=lambda: self.wda.tap(point),
            point=point,
            selector_key=selector_key,
            description=description,
        )

    def tap_speaker_control(self, device: dict[str, Any], selector_key: str) -> None:
        source = self.wda.source()
        selector = device["ui"][selector_key]
        if isinstance(selector, dict) and isinstance(selector.get("any"), list):
            controls = []
            for candidate in selector["any"]:
                controls.extend(select(source, candidate.get("selector", candidate)))
        else:
            controls = select(source, selector)
        if len(controls) != 1:
            raise DemoError(
                f"speaker {selector_key} must match exactly once for {device['id']}, got {len(controls)}"
            )
        point = center(controls[0])
        self.log.write(
            "silent_media_speaker_control", device=device["id"],
            selector_key=selector_key, point=point,
        )
        self._gesture(
            device=device,
            action_kind="tap",
            callback=lambda: self.wda.tap(point),
            point=point,
            selector_key=selector_key,
            description=f"speaker {selector_key}",
        )

    def idle_and_volume(
        self, device: dict[str, Any], *, require_idle: bool = True
    ) -> tuple[int, str]:
        panel_condition = device["ui"].get("volume_panel_condition")
        source = self.wda.source() if panel_condition and self.foreground() else ""
        panel_is_open = bool(
            source and condition_matches(source, panel_condition)
        )
        if not panel_is_open:
            source = self.open_device(device)
            if require_idle and not condition_matches(source, device["ui"]["idle_condition"]):
                raise DemoError(f"{device['id']} is not confirmed idle or paused")
            if not condition_matches(source, device["ui"]["page_condition"]):
                raise DemoError(f"{device['id']} exact speaker page is not confirmed")
        panel_open_selector = device["ui"].get("volume_panel_open_selector")
        if panel_open_selector and not panel_is_open:
            control = select_one(source, panel_open_selector, "volume panel control")
            point = center(control)
            self.log.write(
                "silent_media_open_volume_panel", device=device["id"], point=point,
            )
            self.wda.tap(point)
            time.sleep(float(device.get("volume_panel_wait_seconds", 2)))
            source = self.wda.source()
            if not condition_matches(source, device["ui"]["volume_panel_condition"]):
                raise DemoError(f"{device['id']} volume panel is not confirmed")
        config = device["ui"]["volume"]
        element = select_one(source, config["selector"], "volume control")
        value = percentage(element.attrib.get(str(config.get("attribute", "value"))))
        if value is None:
            raise DemoError(f"{device['id']} volume is unreadable")
        return value, source

    def close_volume_panel(self, device: dict[str, Any]) -> None:
        ui = device.get("ui") or {}
        selector = ui.get("volume_panel_back_selector")
        if not selector:
            return
        source = self.wda.source()
        if not condition_matches(source, ui["volume_panel_condition"]):
            return
        control = select_one(source, selector, "volume panel back control")
        point = center(control)
        self.log.write(
            "silent_media_close_volume_panel", device=device["id"], point=point,
        )
        self.wda.tap(point)
        time.sleep(float(device.get("volume_panel_wait_seconds", 2)))
        source = self.wda.source()
        if not condition_matches(source, ui["page_condition"]):
            raise DemoError(f"{device['id']} playback page did not return from volume panel")

    def set_volume(
        self, device: dict[str, Any], target: int, *, require_idle: bool = True
    ) -> None:
        current, source = self.idle_and_volume(device, require_idle=require_idle)
        if current == target:
            return
        config = device["ui"]["volume"]
        if config["mode"] == "linear":
            element = select_one(source, config["selector"], "volume control")
            if config.get("gesture", "drag") == "tap":
                point = slider_target(
                    element, target, orientation=str(config["orientation"]),
                    high_at_start=bool(config.get("high_at_start", False)),
                    edge_margin_fraction=float(config.get("edge_margin_fraction", 0.05)),
                    track_start_fraction=float(config.get("track_start_fraction", 0.0)),
                    track_end_fraction=float(config.get("track_end_fraction", 1.0)),
                )
                self._gesture(device=device, action_kind="tap",
                              callback=lambda: self.wda.tap(point), point=point, target=target)
                self.log.write("silent_media_volume_command", device=device["id"],
                               target=target, gesture="tap", point=point)
                return
            start = slider_target(
                element, current,
                orientation=str(config["orientation"]),
                high_at_start=bool(config.get("high_at_start", False)),
                edge_margin_fraction=float(config.get("edge_margin_fraction", 0.05)),
                track_start_fraction=float(config.get("track_start_fraction", 0.0)),
                track_end_fraction=float(config.get("track_end_fraction", 1.0)),
            )
            end = slider_target(
                element, target,
                orientation=str(config["orientation"]),
                high_at_start=bool(config.get("high_at_start", False)),
                edge_margin_fraction=float(config.get("edge_margin_fraction", 0.05)),
                track_start_fraction=float(config.get("track_start_fraction", 0.0)),
                track_end_fraction=float(config.get("track_end_fraction", 1.0)),
            )
            axis = "x" if config["orientation"] == "horizontal" else "y"
            dimension = "width" if axis == "x" else "height"
            lower = int(element.attrib[axis])
            span = int(element.attrib[dimension])
            if "drag_distance_span_fraction" in config:
                direction = -1 if config.get("high_at_start", False) else 1
                end[axis] = max(lower, min(lower + span - 1, round(
                    start[axis] + direction * (target - current) / 100.0
                    * span * float(config["drag_distance_span_fraction"]))))
            start_padding = float(config.get("drag_start_padding_fraction", 0.0))
            if start_padding:
                direction = (1 if target > current else -1) * (-1 if config.get("high_at_start", False) else 1)
                end[axis] = max(lower, min(lower + span - 1,
                    round(end[axis] + direction * span * start_padding)))
            padding = float(config.get("endpoint_drag_padding_fraction", 0.0))
            if padding and target in (0, 100):
                direction = 1 if (target == 0) == bool(config.get("high_at_start", False)) else -1
                end[axis] = max(lower, min(lower + span - 1,
                    round(end[axis] + direction * span * padding)))
            duration = float(config.get("duration_seconds", 0.8))
            self._gesture(
                device=device, action_kind="drag",
                callback=lambda: self.wda.drag(start, end, duration),
                start=start, end=end, requested_duration_seconds=duration, target=target,
            )
            command = {"gesture": "drag", "start": start, "end": end}
        elif config["mode"] == "radial":
            element = select_one(source, config["selector"], "volume control")
            point = radial_target(element, target, config)
            self._gesture(
                device=device, action_kind="tap", callback=lambda: self.wda.tap(point),
                point=point, target=target,
            )
            command = {"gesture": "tap", "point": point}
        else:
            direction = "volumeDown" if target < current else "volumeUp"
            step = max(1, int(config.get("button_step_percent", 1)))
            needed = abs(target - current) // step + 1
            presses = min(int(config["max_button_presses"]), max(1, needed))
            interval = float(config.get("button_press_interval_seconds", 0.4))

            def press_buttons() -> None:
                for index in range(presses):
                    self.wda.request("POST", "/wda/pressButton", {"name": direction})
                    if interval and index + 1 < presses:
                        time.sleep(interval)

            self._gesture(
                device=device,
                action_kind="hardware_button_sequence",
                callback=press_buttons,
                button=direction,
                presses=presses,
                target=target,
            )
            command = {
                "gesture": "hardware_button_sequence",
                "button": direction,
                "presses": presses,
            }
        self.log.write("silent_media_volume_command", device=device["id"], target=target, **command)

    def wait_volume(
        self,
        device: dict[str, Any],
        target: int,
        log: EventLog,
        timeout_seconds: float | None = None,
        require_idle: bool = True,
    ) -> int:
        tolerance = int(device.get("volume_tolerance", 5))
        timeout = float(timeout_seconds if timeout_seconds is not None else device["state_timeout_seconds"])
        deadline, last = time.time() + timeout, None
        while time.time() < deadline:
            time.sleep(float(device["poll_seconds"]))
            last, _ = self.idle_and_volume(device, require_idle=require_idle)
            log.write("silent_media_volume_poll", target=target, observed=last)
            if abs(last - target) <= tolerance:
                return last
        raise DemoError(f"Volume confirmation timed out for {device['id']}: target={target}, last={last}")

    def set_volume_and_confirm(
        self, device: dict[str, Any], target: int, log: EventLog, *, require_idle: bool = True
    ) -> int:
        """Retry a volume gesture after re-reading the live slider position."""
        attempts = int(device.get("volume_command_attempts", 1))
        timeout = float(device.get("volume_attempt_timeout_seconds", device["state_timeout_seconds"]))
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            self.set_volume(device, target, require_idle=require_idle)
            try:
                observed = self.wait_volume(
                    device, target, log, timeout_seconds=timeout, require_idle=require_idle
                )
                if not hasattr(self, "confirmed_volumes"):
                    self.confirmed_volumes = {}
                self.confirmed_volumes[device["id"]] = observed
                self.close_volume_panel(device)
                return observed
            except DemoError as exc:
                last_error = exc
                log.write(
                    "silent_media_volume_command_retry",
                    device=device["id"],
                    target=target,
                    attempt=attempt,
                    attempts=attempts,
                    error=repr(exc),
                )
        raise DemoError(
            f"Volume confirmation failed after {attempts} command attempts for "
            f"{device['id']}: target={target}, last_error={last_error}"
        )


class SilentMediaCollector:
    def __init__(self, root: Path, plan: dict[str, Any]) -> None:
        validate_plan(plan)
        self.silence_evidence = load_silence_preflight(plan) if plan.get("silence_preflight") else None
        self.root, self.plan = root, plan
        self.root.mkdir(parents=True, exist_ok=True)
        if self.silence_evidence is not None:
            self.silence_evidence = materialize_silence_preflight(self.root, self.silence_evidence)
        self.endpoint_evidence = {
            device["id"]: materialize_endpoint_evidence(self.root, device)
            for device in plan["devices"]
        }
        self.log = EventLog(root / "batch_events.jsonl")
        self.wda = WDA(plan["controller"]["wda_url"], self.log)
        self.ui = SilentMediaUI(plan, self.wda, self.log)
        self.talk_audio = load_talk_audio(plan)
        self.cycle_start = int(plan.get("cycle_start", 1))
        self.rows: list[dict[str, Any]] = []
        self.counts = {device["id"]: {action: 0 for action in device["actions"]} for device in plan["devices"]}
        self.attempts = {device["id"]: {action: 0 for action in device["actions"]} for device in plan["devices"]}
        write_json(root / "effective_plan.json", plan)

    def manifest(self, status: str, pcap: Path) -> None:
        write_json(self.root / "batch_manifest.json", {
            "experiment": self.plan["experiment"], "status": status, "updated_at": now_iso(),
            "control_platform": self.plan["control_platform"],
            "target_valid_per_action": self.plan["target_valid_per_action"],
            "valid_counts": self.counts, "attempt_counts": self.attempts,
            "cycle_start": self.cycle_start,
            "cycle_end": max((int(row["global_cycle"]) for row in self.rows), default=self.cycle_start - 1),
            "raw_pcap": str(pcap), "samples": len(self.rows),
            "capture_filter": self.plan["router"].get("capture_filter"),
        })
        write_json(self.root / "sample_windows.json", self.rows)

    def normalize(self, device: dict[str, Any], intent: MediaIntent, log: EventLog) -> None:
        if intent.action == "live_view_start":
            if device.get("cold_launch_before_live_view_start", False):
                settle_seconds = float(device.get("cold_launch_settle_seconds", 2))
                self.log.write(
                    "silent_media_cold_launch",
                    device=device["id"],
                    action=intent.action,
                    settle_seconds=settle_seconds,
                )
                self.wda.terminate(self.plan["controller"]["application_bundle_id"])
                if settle_seconds > 0:
                    time.sleep(settle_seconds)
            self.ui.dashboard(device)
        elif intent.action == "live_view_stop":
            source = self.ui.open_device(device)
            state = self.ui.page_state(device, source)
            if state != "playing":
                self.ui.wait_state(device, "playing", log)
        elif intent.action == "talk_session":
            source = self.ui.open_device(device)
            state = self.ui.page_state(device, source)
            if state == "talking":
                self.ui.tap_camera_control(device, "talk_stop_selector", "talk stop control")
                self.ui.wait_state(device, "playing", log)
            elif state != "playing":
                self.ui.wait_state(device, "playing", log)
        elif speaker_playback_action(device, intent.action):
            source = self.ui.open_device(device)
            state = self.ui.page_state(device, source)
            expected_source = str(intent.source_value)
            if state not in {"paused", "playing"}:
                raise DemoError(
                    f"Speaker playback source state is unknown for {device['id']}: {state}"
                )
            if manages_playback_volume(device):
                muted = self.ui.set_volume_and_confirm(
                    device, int(device["silent_volume_percent"]), log, require_idle=False
                )
                if muted != 0:
                    raise DemoError(f"Speaker output mute was not confirmed for {device['id']}: {muted}")
                source = self.ui.open_device(device)
                state = self.ui.page_state(device, source)
                if state not in {"paused", "playing"}:
                    raise DemoError(
                        f"Speaker playback source state is unknown after mute for {device['id']}: {state}"
                    )
            if state != expected_source:
                selector_key = "play_selector" if expected_source == "playing" else "pause_selector"
                self.ui.tap_speaker_control(device, selector_key)
                self.ui.wait_state(device, expected_source, log)
        else:
            current, _ = self.ui.idle_and_volume(device)
            target = int(intent.source_value)
            if abs(current - target) > int(device.get("volume_tolerance", 5)):
                self.ui.set_volume_and_confirm(device, target, log)

    def observed(self, device: dict[str, Any], intent: MediaIntent) -> dict[str, Any]:
        if camera_action(device, intent.action):
            source = self.wda.source()
            return {"state": self.ui.page_state(device, source)}
        if speaker_playback_action(device, intent.action):
            source = self.ui.open_device(device)
            if not manages_playback_volume(device):
                return {"state": self.ui.page_state(device, source)}
            if device["ui"].get("volume_panel_open_selector"):
                volume = self.ui.confirmed_volumes.get(device["id"])
                if volume is None:
                    raise DemoError(f"Speaker volume has not been confirmed for {device['id']}")
            else:
                volume, source = self.ui.idle_and_volume(device, require_idle=False)
            return {"state": self.ui.page_state(device, source), "volume": volume}
        value, _ = self.ui.idle_and_volume(device)
        return {"state": "idle", "volume": value}

    def expected(self, device: dict[str, Any], intent: MediaIntent, observed: dict[str, Any]) -> bool:
        if intent.action == "live_view_start":
            return observed.get("state") == "playing"
        if intent.action == "live_view_stop":
            return observed.get("state") == "closed"
        if intent.action == "talk_session":
            return observed.get("state") == "playing"
        if speaker_playback_action(device, intent.action):
            if not manages_playback_volume(device):
                return observed.get("state") == intent.target_value
            volume = observed.get("volume")
            return (
                observed.get("state") == intent.target_value
                and volume is not None
                and abs(int(volume) - int(device["silent_volume_percent"]))
                <= int(device.get("volume_tolerance", 5))
            )
        value = observed.get("volume")
        return value is not None and abs(int(value) - int(intent.target_value)) <= int(device.get("volume_tolerance", 5))

    def issue_and_confirm(self, device: dict[str, Any], intent: MediaIntent, log: EventLog) -> dict[str, Any]:
        if intent.action == "live_view_start":
            self.ui.open_device(device)
            _, source = self.ui.wait_state(device, "playing", log)
            return {"state": self.ui.page_state(device, source)}
        if intent.action == "live_view_stop":
            self.ui.close_device(device)
            _, source = self.ui.wait_state(device, "closed", log)
            return {"state": self.ui.page_state(device, source)}
        if intent.action == "talk_session":
            if self.talk_audio is None:
                raise DemoError("Talk session has no verified fixed audio asset")
            speaker_enabled = bool(device["ui"].get("speaker_start_selector"))
            speaker_started_confirmed_epoch = None
            if speaker_enabled:
                self.ui.tap_camera_control(device, "speaker_start_selector", "speaker start control")
            self.ui.tap_camera_control(device, "talk_start_selector", "talk start control")
            _, source = self.ui.wait_state(device, "talking", log)
            talking_confirmed_epoch = time.time()
            if speaker_enabled:
                # Alexa exposes separate speaker and microphone controls.  Tap
                # them back-to-back, then use the combined talking condition
                # as positive evidence that both are on.
                speaker_started_confirmed_epoch = talking_confirmed_epoch
            audio = play_talk_audio(self.talk_audio, log)
            self.ui.tap_camera_control(device, "talk_stop_selector", "talk stop control")
            speaker_stopped_confirmed_epoch = None
            if speaker_enabled:
                self.ui.tap_camera_control(device, "speaker_stop_selector", "speaker stop control")
                self.ui.wait_ui_condition(device, "speaker_off_condition", "speaker off state", log)
            _, source = self.ui.wait_state(device, "playing", log)
            microphone_stopped_confirmed_epoch = time.time()
            if speaker_enabled:
                speaker_stopped_confirmed_epoch = microphone_stopped_confirmed_epoch
            return {
                "state": self.ui.page_state(device, source),
                "speaker_talk_enabled": speaker_enabled,
                "speaker_started_confirmed_epoch": speaker_started_confirmed_epoch,
                "talking_confirmed_epoch": talking_confirmed_epoch,
                "talk_audio": audio,
                "microphone_stopped_confirmed_epoch": microphone_stopped_confirmed_epoch,
                "speaker_stopped_confirmed_epoch": speaker_stopped_confirmed_epoch,
                "talk_stopped_confirmed_epoch": speaker_stopped_confirmed_epoch or microphone_stopped_confirmed_epoch,
            }
        if speaker_playback_action(device, intent.action):
            selector_key = "play_selector" if intent.action == "play" else "pause_selector"
            self.ui.tap_speaker_control(device, selector_key)
            manage_volume = manages_playback_volume(device)
            separate_volume_panel = bool(
                manage_volume and device["ui"].get("volume_panel_open_selector")
            )
            _, source = self.ui.wait_state(
                device,
                str(intent.target_value),
                log,
                required_volume=(
                    None
                    if not manage_volume or separate_volume_panel
                    else int(device["silent_volume_percent"])
                ),
            )
            if not manage_volume:
                return {"state": self.ui.page_state(device, source)}
            if separate_volume_panel:
                volume = self.ui.confirmed_volumes.get(device["id"])
                if volume is None:
                    raise DemoError(
                        f"Speaker volume has not been confirmed for {device['id']}"
                    )
            else:
                volume, source = self.ui.idle_and_volume(device, require_idle=False)
            return {"state": self.ui.page_state(device, source), "volume": volume}
        value = self.ui.set_volume_and_confirm(device, int(intent.target_value), log)
        return {"state": "idle", "volume": value}

    def sample(self, device: dict[str, Any], intent: MediaIntent, cycle: int, pcap: Path) -> bool:
        name = intent.action
        self.attempts[device["id"]][name] += 1
        attempt = self.attempts[device["id"]][name] + int(self.plan.get("sample_index_offset", 0))
        sample_id = f"{device['id']}-{name}-{attempt:03d}"
        log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {
            "sample_id": sample_id, "cycle": cycle, "global_cycle": cycle,
            "device_id": device["id"], "device_name": device["name"],
            "device_brand": device["brand"], "device_model": device["model"],
            "device_type": device["device_type"], "device_ip": device.get("ip"), "device_mac": device.get("mac"),
            "verified_device_ips": device.get("verified_ips"),
            "endpoint_identity_evidence": getattr(self, "endpoint_evidence", {}).get(device["id"]),
            "control_platform": self.plan["control_platform"], "action": name,
            "source_value": intent.source_value, "target_value": intent.target_value,
            "volume_tolerance": int(device.get("volume_tolerance", 5)),
            "parameter_seed": (self.plan.get("parameter_policy") or {}).get("smart_speaker_volume", {}).get("random_seed"),
            "raw_pcap": str(pcap), "valid": False,
            "controller_media_muted": self.silence_evidence is not None,
            "speaker_output_muted": False,
            "playback_volume_managed": (
                manages_playback_volume(device) if speaker_playback_action(device, name) else None
            ),
            "silent_volume_percent": (
                device.get("silent_volume_percent")
                if speaker_playback_action(device, name) and manages_playback_volume(device)
                else None
            ),
            "silence_preflight": self.silence_evidence,
            "camera_identity_evidence_required": bool(device["ui"].get("settings_identity")),
            "sample_attempt_started_epoch": time.time(),
        }
        try:
            row["session_normalization_started_epoch"] = time.time()
            self.normalize(device, intent, log)
            if device["ui"].get("settings_identity"):
                row["camera_identity_evidence"] = self.ui.camera_identity_evidence.get(device["id"])
            row["session_normalization_completed_epoch"] = time.time()
            before = self.observed(device, intent)
            row["precommand_state"] = before
            if speaker_playback_action(device, intent.action) and manages_playback_volume(device):
                muted_target = int(device["silent_volume_percent"])
                muted_observed = before.get("volume")
                row["speaker_output_muted"] = (
                    muted_observed is not None
                    and abs(int(muted_observed) - muted_target)
                    <= int(device.get("volume_tolerance", 5))
                )
            row["precommand_state_observed_epoch"] = time.time()
            expected_source = intent.source_value
            if camera_action(device, intent.action):
                if before.get("state") != expected_source:
                    raise DemoError(f"Pre-command state mismatch: {before}")
            elif speaker_playback_action(device, intent.action):
                if before.get("state") != expected_source:
                    raise DemoError(f"Speaker pre-command state mismatch: {before}")
                if manages_playback_volume(device) and not row["speaker_output_muted"]:
                    raise DemoError(f"Silent speaker pre-command state mismatch: {before}")
            elif abs(int(before["volume"]) - int(expected_source)) > int(device.get("volume_tolerance", 5)):
                raise DemoError(f"Pre-command volume mismatch: {before}")
            row["baseline_start_epoch"] = time.time()
            log.write("baseline_start", seconds=device["baseline_seconds"], observed=before)
            time.sleep(float(device["baseline_seconds"]))
            row["baseline_end_epoch"] = time.time()
            row["operation_started_epoch"] = row["baseline_end_epoch"]
            self.ui.reset_command_timing()
            confirmed = self.issue_and_confirm(device, intent, log)
            if not self.ui.command_attempts:
                raise DemoError("Action completed without a recorded controller gesture")
            # Freeze the per-sample gesture evidence.  The UI controller
            # reuses its list for later samples; retaining that mutable list
            # here would let a subsequent device-open gesture leak into an
            # already completed row.
            command_attempts = [dict(item) for item in self.ui.command_attempts]
            first, last = command_attempts[0], command_attempts[-1]
            # Opening a camera tile is the live-view command when it starts
            # automatically.  If Alexa exposes a separate play control, the
            # last recorded gesture is the actual command that started video.
            issued = last if name == "live_view_start" else first
            row.update({
                "gesture_start_epoch": issued["gesture_start_epoch"],
                "gesture_complete_epoch": last["gesture_complete_epoch"],
                "gesture_action_kind": issued["gesture_action_kind"],
                "command_issued_epoch": issued["gesture_start_epoch"],
                "command_attempts": command_attempts,
                "command_timing_quality": "observed_controller_request",
                "command_timing_source": "wda_request_boundary",
            })
            log.write(
                "command_issued", action=name, target=intent.target_value,
                command_issued_epoch=row["command_issued_epoch"],
                gesture_complete_epoch=row["gesture_complete_epoch"],
            )
            row["action_result_epoch"] = time.time()
            row["state_confirmed_epoch"] = row["action_result_epoch"]
            row["confirmed_state"] = confirmed
            if name == "talk_session":
                row["speaker_talk_enabled"] = confirmed["speaker_talk_enabled"]
                row["speaker_started_confirmed_epoch"] = confirmed["speaker_started_confirmed_epoch"]
                row["talking_confirmed_epoch"] = confirmed["talking_confirmed_epoch"]
                row["talk_audio"] = confirmed["talk_audio"]
                row["microphone_stopped_confirmed_epoch"] = confirmed["microphone_stopped_confirmed_epoch"]
                row["speaker_stopped_confirmed_epoch"] = confirmed["speaker_stopped_confirmed_epoch"]
                row["talk_stopped_confirmed_epoch"] = confirmed["talk_stopped_confirmed_epoch"]
                phase_names = {
                    "speaker_start_selector": "speaker_on",
                    "talk_start_selector": "microphone_on",
                    "talk_stop_selector": "microphone_off",
                    "speaker_stop_selector": "speaker_off",
                }
                row["phase_timestamps"] = {
                    phase_names[item["selector_key"]]: {
                        "request_start_epoch": item["gesture_start_epoch"],
                        "request_complete_epoch": item["gesture_complete_epoch"],
                        "selector_key": item["selector_key"],
                        "description": item["description"],
                    }
                    for item in command_attempts
                    if item.get("selector_key") in phase_names
                }
            tail_seconds = float((device.get("tail_seconds_by_action") or {}).get(name, device["tail_seconds"]))
            row["tail_seconds"] = tail_seconds
            row["tail_start_epoch"] = time.time()
            deadline, stable, last = row["tail_start_epoch"] + tail_seconds, True, confirmed
            while time.time() < deadline:
                time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
                try:
                    last = self.observed(device, intent)
                    if not self.expected(device, intent, last):
                        stable = False
                    log.write("tail_state_poll", state=last, stable=stable)
                except Exception as exc:
                    stable = False
                    log.write("tail_state_poll_failed", error=repr(exc))
            row.update({
                "tail_end_epoch": time.time(), "tail_state": last, "tail_state_stable": stable,
                "valid": stable,
                "reason": "state_confirmed_and_tail_stable" if stable else "state_changed_or_unreadable_during_tail",
            })
        except Exception as exc:
            row.update({"tail_end_epoch": time.time(), "reason": f"sample_error:{exc}"})
            log.write("sample_failed", error=repr(exc))
        row["sample_attempt_finished_epoch"] = time.time()
        self.rows.append(row)
        if row["valid"]:
            self.counts[device["id"]][name] += 1
        self.manifest("running", pcap)
        return bool(row["valid"])

    def run(self) -> int:
        pcap = self.root / "raw" / "batch.pcap"
        router = self.plan["router"]
        resolve_capture_addresses(self.plan, self.root, log=self.log)
        capture_filter = router.get("capture_filter") or f"not host {router['capture_transport_host']}"
        capture = RouterStreamCapture(
            user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None,
            local_pcap=pcap, log=self.log, identity_file=router.get("identity_file"), capture_filter=capture_filter,
        )
        target = int(self.plan["target_valid_per_action"])
        apply_resolved_identities(
            self.plan, run_identity_preflight(self.plan, self.root, log=self.log), log=self.log
        )
        self.manifest("starting", pcap)
        try:
            capture.start()
            self.manifest("running", pcap)
            for device in self.plan["devices"]:
                cycle = self.cycle_start - 1
                failures = 0
                limit = int(device.get("max_consecutive_failures", self.plan.get("max_consecutive_failures", 3)))
                while any(self.counts[device["id"]][action] < target for action in device["actions"]):
                    cycle += 1
                    for intent in intents_for_cycle(self.plan, device, cycle):
                        name = intent.action
                        if self.counts[device["id"]][name] >= target:
                            continue
                        while self.counts[device["id"]][name] < target:
                            valid = self.sample(device, intent, cycle, pcap)
                            pending = any(
                                self.counts[device["id"]][action] < target
                                for action in device["actions"]
                            )
                            cooldown = float(
                                device.get("inter_action_cooldown_seconds", 0)
                            )
                            if pending and cooldown > 0:
                                self.log.write(
                                    "silent_media_inter_action_cooldown",
                                    device=device["id"], action=name,
                                    seconds=cooldown,
                                )
                                time.sleep(cooldown)
                            if valid:
                                failures = 0
                                break
                            failures += 1
                            self.log.write("silent_media_failure_streak", device=device["id"], action=name, count=failures, limit=limit)
                            if failures >= limit:
                                self.manifest("stopped_consecutive_failures", pcap)
                                return 3
                            if device["device_type"] in {"smart_camera", "video_doorbell"}:
                                try:
                                    if device.get("cold_relaunch_after_failure", False):
                                        bundle_id = self.plan["controller"]["application_bundle_id"]
                                        settle_seconds = float(device.get("failure_relaunch_settle_seconds", 3))
                                        self.log.write(
                                            "silent_media_failure_cold_relaunch",
                                            device=device["id"], action=name,
                                            bundle_id=bundle_id, settle_seconds=settle_seconds,
                                        )
                                        self.wda.terminate(bundle_id)
                                        if settle_seconds > 0:
                                            time.sleep(settle_seconds)
                                        self.wda.launch(bundle_id)
                                        time.sleep(float(self.plan.get("launch_wait_seconds", 3)))
                                    self.ui.dashboard(device)
                                except Exception as exc:
                                    self.log.write(
                                        "silent_media_failure_recovery_failed",
                                        device=device["id"], action=name, error=repr(exc),
                                    )
                            failure_cooldown = float(device.get("failure_cooldown_seconds", 0))
                            if device.get("failure_cooldown_exponential", False) and failure_cooldown > 0:
                                factor = float(device.get("failure_cooldown_backoff_factor", 2))
                                maximum = float(device.get("failure_cooldown_max_seconds", failure_cooldown))
                                failure_cooldown = min(failure_cooldown * factor ** (failures - 1), maximum)
                            if failure_cooldown > 0:
                                self.log.write(
                                    "silent_media_failure_cooldown",
                                    device=device["id"], action=name, seconds=failure_cooldown,
                                )
                                time.sleep(failure_cooldown)
                    if any(self.counts[device["id"]][action] < target for action in device["actions"]):
                        cooldown = float(device.get("inter_cycle_cooldown_seconds", 0))
                        if cooldown > 0:
                            self.log.write(
                                "silent_media_inter_cycle_cooldown",
                                device=device["id"], seconds=cooldown,
                            )
                            time.sleep(cooldown)
            self.manifest("complete", pcap)
            return 0
        finally:
            capture.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--target-valid-per-action", type=int)
    parser.add_argument("--inter-action-cooldown-seconds", type=float)
    parser.add_argument("--cycle-start", type=int)
    parser.add_argument("--devices")
    parser.add_argument("--actions", help="Comma-separated action names to retain for selected devices")
    parser.add_argument("--validate-plan-only", action="store_true")
    parser.add_argument("--identity-preflight", choices=("enforce", "advisory", "off"))
    args = parser.parse_args()
    from .plan_config import load_plan
    plan = load_plan(args.plan)
    if args.identity_preflight:
        plan["identity_preflight"] = args.identity_preflight
    if args.target_valid_per_action is not None:
        plan["target_valid_per_action"] = args.target_valid_per_action
    if args.inter_action_cooldown_seconds is not None:
        if args.inter_action_cooldown_seconds < 0:
            raise DemoError("inter-action cooldown must be non-negative")
        for device in plan["devices"]:
            device["inter_action_cooldown_seconds"] = args.inter_action_cooldown_seconds
    if args.cycle_start is not None:
        plan["cycle_start"] = args.cycle_start
    if args.devices:
        wanted = {value.strip() for value in args.devices.split(",") if value.strip()}
        plan["devices"] = [device for device in plan["devices"] if device["id"] in wanted]
        missing = wanted - {device["id"] for device in plan["devices"]}
        if missing:
            raise DemoError(f"Unknown device ids: {sorted(missing)}")
    if args.actions:
        wanted_actions = {value.strip() for value in args.actions.split(",") if value.strip()}
        unknown = wanted_actions - set(MEDIA_ACTIONS)
        if unknown:
            raise DemoError(f"Unknown actions: {sorted(unknown)}")
        for device in plan["devices"]:
            device["actions"] = [action for action in device["actions"] if action in wanted_actions]
            if not device["actions"]:
                raise DemoError(f"No selected actions remain for {device['id']}")
    validate_plan(plan)
    if args.validate_plan_only:
        print(json.dumps({"valid": True, "devices": [device["id"] for device in plan["devices"]]}, ensure_ascii=False))
        return 0
    return SilentMediaCollector(Path(args.run_root).resolve(), plan).run()


if __name__ == "__main__":
    raise SystemExit(main())
