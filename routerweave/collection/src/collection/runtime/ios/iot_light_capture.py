#!/usr/bin/env python3
"""Continuously capture validated light actions from Apple Home, Alexa, or Google Home."""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any, Callable

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.capture import RouterStreamCapture
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA, corroborate_native_foreground
from collection.runtime.ios.iot_google_home_capture import GoogleHomeUI
from collection.runtime.ios.iot_identity_preflight import (
    apply_resolved_identities,
    run_identity_preflight,
)
from collection.runtime.ios.iot_capture_network import resolve_capture_addresses
from collection.runtime.ios.iot_light_probe import (
    center,
    detail_is_target,
    dismiss_restored_detail,
    ensure_dashboard,
    find_target,
    scroll_toward_target,
    target_is_hittable,
)
from collection.runtime.ios.iot_light_ui import (
    LightActionIntent,
    LightState,
    avoid_slider_overlays,
    control_point,
    light_action_cycle,
    read_light_state,
    relative_slider_target,
    select,
    select_one,
    slider_target,
)
from collection.voice_assistant.iot_voice import VoiceStimulus, apply_voice_device_names, apply_voice_override


ACTION_NAMES = ("power_on", "change_color", "brightness_up", "brightness_down", "power_off")


class LightForegroundMismatch(DemoError):
    """A native foreground observation failed before reading light state."""


def validate_plan(plan: dict[str, Any]) -> None:
    platform = plan.get("control_platform")
    if platform not in {"apple_home", "alexa", "google_home"}:
        raise DemoError("Light plan control_platform must be apple_home, alexa, or google_home")
    if int(plan.get("target_valid_per_action", 0)) <= 0:
        raise DemoError("target_valid_per_action must be positive")
    if int(plan.get("cycle_start", 1)) <= 0:
        raise DemoError("cycle_start must be positive")
    enabled_actions = tuple(plan.get("enabled_actions") or ACTION_NAMES)
    if not enabled_actions or any(action not in ACTION_NAMES for action in enabled_actions):
        raise DemoError(f"enabled_actions must be a non-empty subset of {ACTION_NAMES}")
    current_only = plan.get("current_detail_only", False)
    if not isinstance(current_only, bool):
        raise DemoError("current_detail_only must be boolean")
    corroborate = plan.get("corroborate_springboard_foreground", False)
    if not isinstance(corroborate, bool) or (corroborate and not current_only):
        raise DemoError("foreground corroboration requires boolean opt-in and current_detail_only")
    if current_only and (
        platform != "google_home"
        or not set(enabled_actions) <= {"brightness_up", "brightness_down"}
        or plan.get("command_input")
        or plan.get("color_hard_reset_on_failure")
        or plan.get("color_hard_reset_after_valid_sample")
        or any(d.get("verify_state_after_reopen") or d.get("recover_transient_pre_baseline_foreground")
               for d in plan.get("devices", []))
    ):
        raise DemoError("current_detail_only requires Google Home brightness-only UI without reopen or recovery")
    if "random_seed" not in plan:
        raise DemoError("Light plan must declare random_seed")
    controller = plan.get("controller") or {}
    for key in ("application_bundle_id", "wda_url"):
        if not controller.get(key):
            raise DemoError(f"Light plan controller is missing {key}")
    router = plan.get("router") or {}
    for key in ("host", "user", "interface", "capture_transport_host"):
        if not router.get(key):
            raise DemoError(f"Light plan router is missing {key}")
    colors = list(plan.get("supported_colors") or [])
    if len(set(colors)) < 2:
        raise DemoError("Light plan needs at least two distinct supported_colors")
    if not plan.get("devices"):
        raise DemoError("Light plan has no devices")
    if not isinstance(plan.get("diagnostic_ui_snapshots", False), bool):
        raise DemoError("diagnostic_ui_snapshots must be boolean")
    ids = [str(device.get("id") or "") for device in plan["devices"]]
    names = [str(device.get("name") or "") for device in plan["devices"]]
    if "" in ids or len(ids) != len(set(ids)):
        raise DemoError("Light device ids must be non-empty and unique")
    if "" in names or len(names) != len(set(names)):
        raise DemoError("Light device names must be non-empty and unique")
    for device in plan["devices"]:
        for key in ("baseline_seconds", "tail_seconds", "poll_seconds", "state_timeout_seconds"):
            if float(device.get(key, 0)) <= 0:
                raise DemoError(f"{device['id']} has invalid {key}")
        if float(device.get("pre_baseline_settle_seconds", 0)) < 0:
            raise DemoError(f"{device['id']} has invalid pre_baseline_settle_seconds")
        recovery = device.get("recover_transient_pre_baseline_foreground", False)
        if not isinstance(recovery, bool):
            raise DemoError(f"{device['id']} foreground recovery must be boolean")
        if recovery and not (
            float(device.get("pre_baseline_settle_seconds", 0)) > 0
            and device.get("verify_state_after_reopen")
            and device.get("reopen_with_cold_launch")
            and not plan.get("command_input")
        ):
            raise DemoError(f"{device['id']} foreground recovery requires UI settle and cold reopen")
        ui = device.get("ui") or {}
        state, controls = ui.get("state") or {}, ui.get("controls") or {}
        for key in ("power", "brightness", "colors"):
            if not state.get(key):
                raise DemoError(f"{device['id']} is missing UI state config {key}")
        for key in ("power", "brightness", "color_open", "color_options"):
            if not controls.get(key):
                raise DemoError(f"{device['id']} is missing UI control config {key}")
        if controls["brightness"].get("orientation") not in {"horizontal", "vertical"}:
            raise DemoError(f"{device['id']} brightness orientation is invalid")
        brightness = controls["brightness"]
        if "drag_avoid_selector" in brightness and (
            not isinstance(brightness["drag_avoid_selector"], dict)
            or not brightness["drag_avoid_selector"]
            or brightness.get("mode") != "from_current"
        ):
            raise DemoError(f"{device['id']} drag_avoid_selector requires from_current and a selector")
        if "drag_start_fill_fraction" in brightness:
            fraction = brightness["drag_start_fill_fraction"]
            if (
                isinstance(fraction, bool)
                or not isinstance(fraction, (int, float))
                or not 0 < fraction <= 1
                or brightness.get("mode") != "from_current"
            ):
                raise DemoError(f"{device['id']} drag_start_fill_fraction requires from_current and 0 < value <= 1")
        missing_state_colors = set(colors) - set(state["colors"])
        missing_control_colors = set(colors) - set(controls["color_options"])
        if missing_state_colors or missing_control_colors:
            raise DemoError(
                f"{device['id']} lacks color selectors; state={sorted(missing_state_colors)}, "
                f"controls={sorted(missing_control_colors)}"
            )
    if plan.get("command_input"):
        VoiceStimulus(plan["command_input"])


class LightUI:
    def __init__(self, plan: dict[str, Any], wda: WDA, log: EventLog) -> None:
        self.plan, self.wda, self.log = plan, wda, log
        self.platform = str(plan["control_platform"])
        self.bundle_id = str(plan["controller"]["application_bundle_id"])
        self.google_home = GoogleHomeUI(wda, log, self.bundle_id) if self.platform == "google_home" else None
        self.confirmed_colors: dict[str, str] = {}
        self.last_gesture_timing: dict[str, Any] | None = None
        self.snapshot_index = 0

    def diagnostic_snapshot(self, device: dict[str, Any], stage: str, **details: Any) -> None:
        """Read-only diagnostic evidence; failures never change the sample verdict."""
        if not self.plan.get("diagnostic_ui_snapshots", False):
            return
        self.snapshot_index += 1
        root = self.log.path.parent / "ui_snapshots"
        stem = f"{self.snapshot_index:03d}-{stage}"
        metadata: dict[str, Any] = {
            "device_id": device["id"], "stage": stage,
            "started_epoch": time.time(), **details,
        }
        try:
            root.mkdir(parents=True, exist_ok=True)
            active = self.wda.active_bundle_id()
            metadata["active_bundle_before"] = active
            if active == self.bundle_id:
                for kind in ("screenshot", "source"):
                    try:
                        metadata[f"{kind}_start_epoch"] = time.time()
                        if kind == "screenshot":
                            self.wda.screenshot(root / f"{stem}.png")
                        else:
                            (root / f"{stem}.xml").write_text(self.wda.source(), encoding="utf-8")
                        metadata[f"{kind}_end_epoch"] = time.time()
                    except Exception as exc:
                        metadata[f"{kind}_error"] = repr(exc)
            else:
                metadata["capture_skipped"] = "unexpected_foreground"
            metadata["active_bundle_after"] = self.wda.active_bundle_id()
            metadata["finished_epoch"] = time.time()
            write_json(root / f"{stem}.json", metadata)
            self.log.write("light_diagnostic_snapshot", metadata=str(root / f"{stem}.json"))
        except Exception as exc:
            try:
                self.log.write("light_diagnostic_snapshot_failed", stage=stage, error=repr(exc))
            except Exception:
                pass

    def _gesture_start(self, device: dict[str, Any], action_kind: str, **details: Any) -> float:
        started = time.time()
        self.last_gesture_timing = {
            "gesture_start_epoch": started,
            "gesture_action_kind": action_kind,
        }
        self.log.write(
            "light_gesture_start",
            device=device["id"],
            action_kind=action_kind,
            gesture_start_epoch=started,
            **details,
        )
        return started

    def _gesture_complete(
        self, device: dict[str, Any], action_kind: str, started: float, **details: Any
    ) -> float:
        completed = time.time()
        self.last_gesture_timing = {
            "gesture_start_epoch": started,
            "gesture_complete_epoch": completed,
            "gesture_action_kind": action_kind,
        }
        self.log.write(
            "light_gesture_complete",
            device=device["id"],
            action_kind=action_kind,
            gesture_start_epoch=started,
            gesture_complete_epoch=completed,
            **details,
        )
        return completed

    def command_timing(self) -> dict[str, Any]:
        if not self.last_gesture_timing:
            raise DemoError("UI command completed without gesture timing")
        return dict(self.last_gesture_timing)

    def _foreground(self) -> bool:
        return self.wda.active_bundle_id() == self.bundle_id

    def hard_reset(self, *, reason: str, wait_seconds: float) -> None:
        """Restore a clean controller-app state between labelled samples."""
        self.log.write(
            "light_controller_hard_reset_start",
            platform=self.platform, reason=reason, wait_seconds=wait_seconds,
        )
        self.wda.terminate(self.bundle_id)
        time.sleep(2)
        self.wda.launch(self.bundle_id)
        time.sleep(wait_seconds)
        if not self._foreground():
            raise DemoError(f"{self.platform} did not return to foreground after hard reset")
        self.log.write(
            "light_controller_hard_reset_complete",
            platform=self.platform, reason=reason,
        )

    def open_detail(self, device: dict[str, Any]) -> str:
        if self.plan.get("current_detail_only", False):
            # Operator-prepared page: no activation or navigation fallback.
            return self.strict_source(device)
        self.wda.launch(self.bundle_id)
        time.sleep(float(self.plan.get("launch_wait_seconds", 3)))
        if not self._foreground():
            raise DemoError(f"{self.platform} is not foreground")
        source = self.wda.source()
        if detail_is_target(self.platform, source, device["name"]):
            return source
        for selector in device.get("ui", {}).get("subpage_close_selectors", []):
            matches = select(source, selector)
            if len(matches) == 1:
                self.wda.tap(center(matches[0])); time.sleep(2); source = self.wda.source()
                if detail_is_target(self.platform, source, device["name"]):
                    return source
        if self.platform == "google_home":
            assert self.google_home is not None
            _, target = self.google_home.visible_tile(device)
            point = center(target)
            self.log.write("open_light_detail", device=device["id"], point=point, gesture="long_press")
            self.wda.long_press(point, float(device.get("open_press_seconds", 0.9)))
            time.sleep(float(device.get("open_wait_seconds", 3)))
            source = self.wda.source()
            if not detail_is_target(self.platform, source, device["name"]):
                raise DemoError(f"Light detail not confirmed: {device['name']}")
            return source
        source = dismiss_restored_detail(self.platform, source, self.wda, self.log)
        source = ensure_dashboard(self.platform, source, self.wda, self.log)
        target = find_target(self.platform, source, device["name"])
        for attempt in range(5):
            if target is not None and target_is_hittable(self.platform, target):
                break
            self.log.write("light_target_scroll", device=device["id"], attempt=attempt + 1)
            scroll_toward_target(self.platform, target, self.wda, source=source, target_name=str(device["name"]))
            time.sleep(2)
            source = self.wda.source()
            target = find_target(self.platform, source, device["name"])
        if target is None:
            raise DemoError(f"Light list item not found: {device['name']}")
        if not target_is_hittable(self.platform, target):
            raise DemoError(f"Light list item did not reach the safe tap region: {device['name']}")
        point = center(target, 0.75 if self.platform == "apple_home" else 0.5)
        self.log.write("open_light_detail", device=device["id"], point=point)
        self.wda.tap(point)
        time.sleep(float(device.get("open_wait_seconds", 3)))
        source = self.wda.source()
        if not detail_is_target(self.platform, source, device["name"]):
            raise DemoError(f"Light detail not confirmed: {device['name']}")
        return source

    def reopen_detail(self, device: dict[str, Any]) -> str:
        """Leave and reopen the exact device page to defeat optimistic UI state."""
        if not self._foreground():
            raise DemoError(f"Foreground mismatch before reopening {device['id']}")
        if device.get("reopen_with_cold_launch", False):
            self.hard_reset(reason=f"fresh state verification for {device['id']}",
                            wait_seconds=float(device.get("reopen_launch_wait_seconds", 5)))
            return self.open_detail(device)
        if self.platform == "google_home":
            assert self.google_home is not None
            source = self.google_home.dashboard()
        else:
            source = dismiss_restored_detail(
                self.platform, self.wda.source(), self.wda, self.log
            )
        if detail_is_target(self.platform, source, device["name"]):
            raise DemoError(f"Device page did not close before reopening {device['id']}")
        reopened = self.open_detail(device)
        if not detail_is_target(self.platform, reopened, device["name"]):
            raise DemoError(f"Device page did not reopen for {device['id']}")
        return reopened

    def strict_source(self, device: dict[str, Any]) -> str:
        return self.state_source(device, allow_subpage=False)

    def state_source(self, device: dict[str, Any], *, allow_subpage: bool) -> str:
        active = self.wda.active_bundle_id()
        if active != self.bundle_id:
            self.log.write(
                "light_foreground_mismatch", device=device["id"],
                expected_bundle_id=self.bundle_id, actual_bundle_id=active,
            )
            if active == "com.apple.springboard" and self.plan.get("corroborate_springboard_foreground", False):
                source = self.corroborate_foreground(device)
                if source is not None:
                    return source
            raise LightForegroundMismatch(
                f"Foreground mismatch for {device['id']}; expected={self.bundle_id}, actual={active!r}"
            )
        source = self.wda.source()
        if not allow_subpage and not detail_is_target(self.platform, source, device["name"]):
            raise DemoError(f"Device page mismatch for {device['id']}")
        return source

    def corroborate_foreground(self, device: dict[str, Any]) -> str | None:
        """Resolve one ambiguous SpringBoard report with a bounded native read.

        No sleep, activation, navigation or recovery is allowed. A confirmed
        background/locked/wrong page observation is never retried here.
        """
        return corroborate_native_foreground(
            self.wda, self.bundle_id, self.plan["controller"].get("application"),
            lambda source: detail_is_target(self.platform, source, device["name"]),
            self.log, device["id"], "light_foreground_corroboration",
        )

    def state(self, device: dict[str, Any], source: str) -> LightState:
        state = read_light_state(source, device["ui"]["state"])
        device_id = str(device["id"])
        if state.color is not None:
            self.confirmed_colors[device_id] = state.color
            return state
        if not device["ui"].get("allow_cached_color", True):
            return state
        confirmed_color = self.confirmed_colors.get(device_id)
        if confirmed_color is None:
            return state
        return LightState(power=state.power, brightness=state.brightness, color=confirmed_color)

    def tap_control(self, source: str, selector: dict[str, Any], description: str) -> dict[str, int]:
        element = select_one(source, selector, description)
        point = control_point(element, selector)
        self.wda.tap(point)
        return point

    def visible_control(self, source: str, selector: dict[str, Any], description: str, *, device_name: str | None = None) -> tuple[str, Any]:
        """Return a visible control, revealing it only when XML proves it is off-screen."""
        matches = select(source, selector)
        if self.platform == "google_home" and len(matches) == 1:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(source)
            app = next((e for e in root.iter() if e.tag == "XCUIElementTypeApplication"), root)
            width, height = int(app.attrib["width"]), int(app.attrib["height"])
            point = center(matches[0])
            if not 0 <= point["x"] < width or not 0 <= point["y"] < height:
                # Use the side of the current viewport, outside the central
                # brightness control, to reveal the color preset strip.
                upper = {"x": round(width * .1), "y": round(height * .35)}
                lower = {"x": upper["x"], "y": round(height * .84)}
                toward_top = point["y"] < 0
                self.wda.drag(upper if toward_top else lower, lower if toward_top else upper, .7)
                time.sleep(2)
                source = self.wda.source()
                if not device_name or not detail_is_target(self.platform, source, device_name):
                    raise DemoError("Google Home identity changed while revealing a light control")
                element = select_one(source, selector, description)
                point = center(element)
                if not 0 <= point["x"] < width or not 0 <= point["y"] < height:
                    raise DemoError(f"Google Home control remains outside the viewport: {description}")
                return source, element
        if len(matches) == 1:
            return source, matches[0]
        if self.platform != "alexa" or matches:
            return source, select_one(source, selector, description)

        all_matches = select(source, {**selector, "visible": False})
        if len(all_matches) != 1:
            return source, select_one(source, selector, description)
        hidden = all_matches[0]
        point = center(hidden)
        if point["y"] < 64:
            start, end = {"x": 188, "y": 230}, {"x": 188, "y": 520}
        elif point["y"] > 630:
            start, end = {"x": 188, "y": 520}, {"x": 188, "y": 230}
        else:
            return source, select_one(source, selector, description)
        self.log.write(
            "light_control_restore_scroll",
            description=description,
            hidden_point=point,
            start=start,
            end=end,
        )
        self.wda.drag(start, end, 0.7)
        time.sleep(2)
        source = self.wda.source()
        return source, select_one(source, selector, description)

    def set_power(self, device: dict[str, Any], target: str) -> bool:
        self.last_gesture_timing = None
        source = self.open_detail(device)
        current = self.state(device, source)
        if current.power == target:
            return False
        if self.plan.get("current_detail_only", False):
            raise DemoError(f"Current-page-only collection cannot change power for {device['id']}")
        if current.power not in {"on", "off"}:
            raise DemoError(f"Power state is unknown for {device['id']}: {current}")
        config = device["ui"]["controls"]["power"]
        source, element = self.visible_control(source, config, "power control", device_name=device["name"])
        gesture = dict((config.get("gestures") or {}).get(target) or {"type": "tap"})
        gesture_type = gesture.get("type", "tap")
        if gesture_type == "tap":
            point = control_point(element, {**config, **gesture})
            command = {"gesture": "tap", "point": point}
            started = self._gesture_start(device, "power", target=target, **command)
            self.wda.tap(point)
            self._gesture_complete(device, "power", started, target=target, **command)
        elif gesture_type in {"drag", "relative_brightness"}:
            start = center(element)
            if gesture_type == "relative_brightness":
                if current.brightness is None:
                    raise DemoError(f"Brightness is unknown for relative power gesture on {device['id']}")
                end = relative_slider_target(
                    element, current.brightness, int(gesture["target_percent"]),
                    orientation=str(gesture["orientation"]),
                    high_at_start=bool(gesture.get("high_at_start", False)),
                )
            else:
                end = slider_target(
                    element,
                    int(gesture["target_percent"]),
                    orientation=str(gesture["orientation"]),
                    high_at_start=bool(gesture.get("high_at_start", False)),
                    edge_margin_fraction=float(gesture.get("edge_margin_fraction", 0.0)),
                    track_start_fraction=float(gesture.get("track_start_fraction", 0.0)),
                    track_end_fraction=float(gesture.get("track_end_fraction", 1.0)),
                )
            command = {"gesture": "drag", "start": start, "end": end}
            started = self._gesture_start(device, "power", target=target, **command)
            self.wda.drag(start, end, float(gesture.get("duration_seconds", 0.8)))
            self._gesture_complete(device, "power", started, target=target, **command)
        else:
            raise DemoError(f"Unsupported power gesture {gesture_type!r} for {device['id']}")
        self.log.write("light_power_command", device=device["id"], target=target, **command)
        self.wait(device, lambda state: state.power == target, float(device["state_timeout_seconds"]), self.log)
        return True

    def dashboard_power_control(self, device: dict[str, Any]) -> tuple[str, Any]:
        """Return the Alexa device-list power state and its direct toggle."""
        if not self._foreground():
            self.wda.launch(self.bundle_id)
            time.sleep(float(self.plan.get("launch_wait_seconds", 3)))
        source = dismiss_restored_detail(self.platform, self.wda.source(), self.wda, self.log)
        source = ensure_dashboard(self.platform, source, self.wda, self.log)
        for state, suffix in (("off", "OFF"), ("on", "ON")):
            matches = select(
                source,
                {
                    "type": "XCUIElementTypeOther",
                    "name": f"toggleButton_{device['name']}={suffix}",
                },
            )
            if len(matches) == 1:
                return state, matches[0]
        raise DemoError(f"Dashboard power toggle not found for {device['id']}")

    def set_dashboard_power(self, device: dict[str, Any], target: str) -> bool:
        self.last_gesture_timing = None
        current, element = self.dashboard_power_control(device)
        if current == target:
            return False
        point = center(element)
        started = self._gesture_start(
            device, "power", target=target, gesture="tap", point=point, surface="dashboard"
        )
        self.wda.tap(point)
        self._gesture_complete(
            device, "power", started, target=target, gesture="tap", point=point, surface="dashboard"
        )
        self.log.write(
            "light_power_command", device=device["id"], target=target,
            gesture="tap", point=point, surface="dashboard",
        )
        deadline = time.time() + float(device["state_timeout_seconds"])
        while time.time() < deadline:
            time.sleep(float(device["poll_seconds"]))
            observed, _ = self.dashboard_power_control(device)
            self.log.write(
                "light_state_poll", device=device["id"], power=observed, surface="dashboard"
            )
            if observed == target:
                return True
        raise DemoError(f"Dashboard power confirmation timed out for {device['id']}")

    def set_brightness(self, device: dict[str, Any], target: int) -> bool:
        self.last_gesture_timing = None
        source = self.open_detail(device)
        state = self.state(device, source)
        if state.power != "on":
            self.set_power(device, "on"); source = self.open_detail(device)
        tolerance = int(device.get("brightness_tolerance", 5))
        state = self.state(device, source)
        if state.brightness is not None and abs(state.brightness - target) <= tolerance:
            return False
        config = device["ui"]["controls"]["brightness"]
        element = select_one(source, config["selector"], "brightness control")
        mode = str(config.get("mode") or "absolute")
        if mode == "relative":
            if state.brightness is None:
                raise DemoError(f"Brightness is unknown for relative slider on {device['id']}")
            start = center(element)
            end = relative_slider_target(
                element, state.brightness, target,
                orientation=config["orientation"],
                high_at_start=bool(config.get("high_at_start", False)),
            )
        elif mode == "from_current":
            if state.brightness is None:
                raise DemoError(f"Brightness is unknown for current-position slider on {device['id']}")
            slider_options = {
                "orientation": config["orientation"],
                "high_at_start": bool(config.get("high_at_start", False)),
                "edge_margin_fraction": float(config.get("edge_margin_fraction", 0.08)),
                "track_start_fraction": float(config.get("track_start_fraction", 0.0)),
                "track_end_fraction": float(config.get("track_end_fraction", 1.0)),
            }
            # Some filled sliders accept a drag only inside the filled region.
            # Translate BOTH endpoints so the current-to-target delta stays
            # unchanged; moving only the start would overshoot the target.
            fill_fraction = float(config.get("drag_start_fill_fraction", 1.0))
            if not 0 < fill_fraction <= 1:
                raise DemoError("drag_start_fill_fraction must be in (0, 1]")
            inset = min(state.brightness, target) * (1.0 - fill_fraction)
            start = slider_target(element, state.brightness - inset, **slider_options)
            end = slider_target(element, target - inset, **slider_options)
            if config.get("drag_avoid_selector"):
                start, end = avoid_slider_overlays(
                    element, start, end, select(source, config["drag_avoid_selector"]),
                    orientation=config["orientation"],
                )
        else:
            start = center(element)
            end = slider_target(
                element,
                target,
                orientation=config["orientation"],
                high_at_start=bool(config.get("high_at_start", False)),
                edge_margin_fraction=float(config.get("edge_margin_fraction", 0.08)),
                track_start_fraction=float(config.get("track_start_fraction", 0.0)),
                track_end_fraction=float(config.get("track_end_fraction", 1.0)),
            )
        self.log.write("light_brightness_command", device=device["id"], target=target, start=start, end=end)
        self.diagnostic_snapshot(
            device, "brightness_before", target=target, observed=state.__dict__, start=start, end=end,
        )
        started = self._gesture_start(
            device, "brightness", target=target, gesture="drag", start=start, end=end
        )
        self.wda.drag(start, end, float(config.get("duration_seconds", 0.8)))
        self._gesture_complete(
            device, "brightness", started, target=target, gesture="drag", start=start, end=end
        )
        self.diagnostic_snapshot(device, "brightness_after", target=target, start=start, end=end)
        if mode == "relative":
            for correction in range(int(config.get("closed_loop_corrections", 0))):
                time.sleep(float(config.get("settle_seconds", device["poll_seconds"])))
                source = self.strict_source(device)
                observed = self.state(device, source)
                self.log.write(
                    "light_brightness_feedback",
                    device=device["id"], target=target,
                    observed=observed.brightness, correction=correction + 1,
                )
                if observed.brightness is not None and abs(observed.brightness - target) <= tolerance:
                    return True
                if observed.brightness is None:
                    continue
                element = select_one(source, config["selector"], "brightness control")
                correction_start = center(element)
                correction_end = relative_slider_target(
                    element, observed.brightness, target,
                    orientation=config["orientation"],
                    high_at_start=bool(config.get("high_at_start", False)),
                )
                self.log.write(
                    "light_brightness_correction",
                    device=device["id"], target=target, observed=observed.brightness,
                    start=correction_start, end=correction_end,
                )
                self.wda.drag(
                    correction_start, correction_end,
                    float(config.get("duration_seconds", 0.8)),
                )
        self.wait(
            device,
            lambda value: value.brightness is not None and abs(value.brightness - target) <= tolerance,
            float(device["state_timeout_seconds"]),
            self.log,
        )
        return True

    def swipe_brightness(self, device: dict[str, Any], direction: str, distance_fraction: float) -> dict[str, Any]:
        self.last_gesture_timing = None
        source = self.open_detail(device)
        state = self.state(device, source)
        if state.power != "on":
            self.set_power(device, "on")
            source = self.open_detail(device)
        config = device["ui"]["controls"]["brightness"]
        element = select_one(source, config["selector"], "brightness control")
        start = center(element)
        length = int(element.attrib["height"] if config["orientation"] == "vertical" else element.attrib["width"])
        distance = max(int(config.get("directional_min_pixels", 60)), round(length * distance_fraction))
        if direction not in {"up", "down"}:
            raise DemoError(f"Unsupported brightness direction: {direction}")
        sign = -1 if direction == "up" else 1
        if config["orientation"] == "vertical":
            end = {"x": start["x"], "y": start["y"] + sign * distance}
        else:
            end = {"x": start["x"] - sign * distance, "y": start["y"]}
        self.log.write(
            "light_brightness_directional_command", device=device["id"],
            direction=direction, distance_fraction=distance_fraction,
            observed_before=state.brightness, start=start, end=end,
        )
        started = self._gesture_start(
            device,
            "brightness_directional",
            direction=direction,
            distance_fraction=distance_fraction,
            gesture="drag",
            start=start,
            end=end,
        )
        self.wda.drag(start, end, float(config.get("duration_seconds", 0.8)))
        self._gesture_complete(
            device,
            "brightness_directional",
            started,
            direction=direction,
            distance_fraction=distance_fraction,
            gesture="drag",
            start=start,
            end=end,
        )
        return {
            "brightness_direction": direction,
            "swipe_fraction": distance_fraction,
            **self.command_timing(),
        }

    def set_color(self, device: dict[str, Any], target: str) -> bool:
        self.last_gesture_timing = None
        source = self.open_detail(device)
        state = self.state(device, source)
        if state.power != "on":
            self.set_power(device, "on"); source = self.open_detail(device)
            state = self.state(device, source)
        if state.color == target:
            return False
        controls = device["ui"]["controls"]
        target_selector = controls["color_options"][target]
        choices: list[Any] = []
        open_attempts = int(controls.get("color_open_attempts", 3))
        for attempt in range(1, open_attempts + 1):
            if attempt > 1:
                source = self.open_detail(device)
            choices = select(source, target_selector)
            if not choices and controls.get("color_open_fallback", True):
                point = self.tap_control(source, controls["color_open"], "color menu")
                self.log.write(
                    "light_color_panel_open",
                    device=device["id"], target=target, attempt=attempt, point=point,
                )
                time.sleep(float(controls.get("color_open_wait_seconds", 2)))
                foreground = self._foreground()
                source = self.wda.source()
                choices = select(source, target_selector) if foreground else []
                self.log.write(
                    "light_color_panel_result",
                    device=device["id"], target=target, attempt=attempt,
                    foreground=foreground, choices=len(choices),
                )
            if len(choices) == 1:
                break
            if len(choices) > 1:
                break
            if attempt < open_attempts:
                self.log.write(
                    "light_color_panel_recover",
                    device=device["id"], target=target, attempt=attempt,
                    active_bundle_id=self.wda.active_bundle_id(),
                )
        if len(choices) != 1:
            raise DemoError(
                f"Expected one {target} color option after {open_attempts} panel attempts, "
                f"found {len(choices)}"
            )
        source, choice = self.visible_control(source, target_selector, f"{target} color option", device_name=device["name"])
        point = center(choice)
        self.log.write("light_color_command", device=device["id"], target=target, point=point)
        started = self._gesture_start(
            device, "color", target=target, gesture="tap", point=point
        )
        self.wda.tap(point)
        self._gesture_complete(
            device, "color", started, target=target, gesture="tap", point=point
        )
        self.wait(device, lambda value: value.color == target, float(device["state_timeout_seconds"]), self.log, allow_subpage=True)
        close_selector = controls.get("color_close")
        if close_selector:
            source = self.wda.source()
            close = select_one(source, close_selector, "color panel close control")
            close_point = control_point(close, close_selector)
            self.wda.tap(close_point)
            time.sleep(float(controls.get("color_close_wait_seconds", 2)))
            source = self.wda.source()
            if not detail_is_target(self.platform, source, device["name"]):
                raise DemoError(f"Color panel did not return to light detail for {device['id']}")
            self.log.write("light_color_panel_closed", device=device["id"], target=target, point=close_point)
        return True

    def wait(
        self,
        device: dict[str, Any],
        predicate: Callable[[LightState], bool],
        timeout: float,
        log: EventLog,
        *,
        allow_subpage: bool = False,
    ) -> LightState:
        deadline, last = time.time() + timeout, LightState()
        while time.time() < deadline:
            time.sleep(float(device["poll_seconds"]))
            if not self._foreground():
                log.write("light_state_poll", device=device["id"], state="foreground_mismatch")
                continue
            source = self.wda.source()
            if not allow_subpage and not detail_is_target(self.platform, source, device["name"]):
                log.write("light_state_poll", device=device["id"], state="device_page_mismatch")
                continue
            try:
                last = self.state(device, source)
            except DemoError as exc:
                log.write("light_state_parse_failed", device=device["id"], error=str(exc))
                continue
            log.write("light_state_poll", device=device["id"], power=last.power, brightness=last.brightness, color=last.color)
            if predicate(last):
                return last
        raise DemoError(f"State confirmation timed out for {device['id']}; last={last}")


class LightCollector:
    def __init__(self, root: Path, plan: dict[str, Any]) -> None:
        validate_plan(plan)
        self.root, self.plan = root, plan
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(root / "batch_events.jsonl")
        self.voice = VoiceStimulus(plan["command_input"]) if plan.get("command_input") else None
        if self.voice:
            self.voice.preflight(plan)
        self.wda = WDA(plan["controller"]["wda_url"], self.log)
        self.ui = LightUI(plan, self.wda, self.log)
        self.rng = random.Random(int(plan["random_seed"]))
        self.cycle_start = int(plan.get("cycle_start", 1))
        colors = list(plan["supported_colors"])
        for _ in range(self.cycle_start - 1):
            light_action_cycle(colors, self.rng)
        self.rows: list[dict[str, Any]] = []
        self.action_names = tuple(plan.get("enabled_actions") or ACTION_NAMES)
        self.counts = {device["id"]: {name: 0 for name in self.action_names} for device in plan["devices"]}
        self.attempts = {device["id"]: {name: 0 for name in self.action_names} for device in plan["devices"]}
        write_json(self.root / "effective_plan.json", self.plan)

    def manifest(self, status: str, pcap: Path) -> None:
        router = self.plan["router"]
        capture_filter = router.get("capture_filter") or f"not host {router['capture_transport_host']}"
        write_json(
            self.root / "batch_manifest.json",
            {
                "experiment": self.plan["experiment"], "status": status, "updated_at": now_iso(),
                "control_platform": self.plan["control_platform"], "target_valid_per_action": self.plan["target_valid_per_action"],
                "random_seed": self.plan["random_seed"], "valid_counts": self.counts, "attempt_counts": self.attempts,
                "cycle_start": self.cycle_start,
                "cycle_end": max((int(row["global_cycle"]) for row in self.rows), default=self.cycle_start - 1),
                "enabled_actions": list(self.action_names),
                "raw_pcap": str(pcap), "samples": len(self.rows), "capture_filter": capture_filter,
                "command_input": self.plan.get("command_input") or {"mode": "ui"},
            },
        )
        write_json(self.root / "sample_windows.json", self.rows)

    @staticmethod
    def expected(intent: LightActionIntent, state: LightState, tolerance: int) -> bool:
        if intent.action == "power_on": return state.power == "on"
        if intent.action == "power_off": return state.power == "off"
        if intent.action == "change_color": return state.power == "on" and state.color == intent.target_value
        return state.power == "on" and state.brightness is not None and abs(state.brightness - int(intent.target_value)) <= tolerance

    @staticmethod
    def directional_brightness(device: dict[str, Any], intent: LightActionIntent) -> bool:
        if intent.action not in {"brightness_up", "brightness_down"}:
            return False
        return str(device["ui"]["controls"]["brightness"].get("mode")) == "directional"

    @staticmethod
    def precondition_expected(
        intent: LightActionIntent, state: LightState, tolerance: int
    ) -> bool:
        if state.power != intent.required_power:
            return False
        if intent.action == "change_color":
            return state.color == intent.source_value
        if intent.action in {"brightness_up", "brightness_down"}:
            return state.brightness is not None and abs(
                state.brightness - int(intent.source_value)
            ) <= tolerance
        return True

    def settle_precondition(
        self, device: dict[str, Any], intent: LightActionIntent, log: EventLog
    ) -> tuple[float, float] | None:
        duration = float(device.get("pre_baseline_settle_seconds", 0))
        if duration <= 0:
            return None
        tolerance = int(device.get("brightness_tolerance", 5))
        settle_intent = intent
        if self.directional_brightness(device, intent):
            observed = self.ui.state(device, self.ui.state_source(device, allow_subpage=False))
            if observed.power != intent.required_power or observed.brightness is None:
                raise DemoError(f"Directional brightness precondition is unreadable: {observed}")
            # Directional control deliberately keeps the actual starting level,
            # rather than normalizing to the randomized absolute source value.
            settle_intent = LightActionIntent(
                intent.action, intent.required_power, observed.brightness, intent.target_value
            )
        started = time.time()
        deadline = time.time() + duration
        log.write(
            "pre_baseline_settle_start", seconds=duration, started_epoch=started
        )
        while time.time() < deadline:
            time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
            source = self.ui.state_source(
                device, allow_subpage=intent.action == "change_color"
            )
            observed = self.ui.state(device, source)
            stable = self.precondition_expected(settle_intent, observed, tolerance)
            log.write(
                "pre_baseline_settle_poll", state=observed.__dict__, stable=stable
            )
            if not stable:
                raise DemoError(f"Precondition changed during settle: {observed}")
        completed = time.time()
        log.write(
            "pre_baseline_settle_complete",
            seconds=duration,
            started_epoch=started,
            completed_epoch=completed,
        )
        return started, completed

    def prepare_precondition(
        self, device: dict[str, Any], intent: LightActionIntent, log: EventLog
    ) -> tuple[float, float] | None:
        self.normalize(device, intent)
        try:
            return self.settle_precondition(device, intent, log)
        except LightForegroundMismatch:
            if not device.get("recover_transient_pre_baseline_foreground", False):
                raise
            # Observe recovery before any UI action. Persistent/locked/unknown
            # foregrounds stay closed; no accepted baseline or command exists yet.
            time.sleep(1)
            active = self.ui.wda.active_bundle_id()
            log.write("pre_baseline_foreground_recheck", actual_bundle_id=active)
            if active != self.ui.bundle_id or self.ui.wda.is_locked():
                raise
            log.write("pre_baseline_foreground_recovery_start")
            self.ui.reopen_detail(device)
            self.normalize(device, intent)
            # Restart the entire settle interval, never join the interrupted polls.
            result = self.settle_precondition(device, intent, log)
            log.write("pre_baseline_foreground_recovery_complete")
            return result

    def normalize(self, device: dict[str, Any], intent: LightActionIntent) -> None:
        self.ui.set_power(device, intent.required_power)
        if intent.action == "change_color":
            self.ui.set_color(device, str(intent.source_value))
        elif self.directional_brightness(device, intent):
            if intent.action == "brightness_down":
                config = device["ui"]["controls"]["brightness"]
                previous = None
                for attempt in range(3):
                    source = self.ui.open_detail(device) if attempt == 0 else self.ui.strict_source(device)
                    state = self.ui.state(device, source)
                    if state.power != "on" or state.brightness is None:
                        raise DemoError(f"Directional brightness preparation is unreadable: {state}")
                    if previous is not None and state.brightness <= previous:
                        raise DemoError(f"Directional brightness preparation did not increase: {previous} -> {state.brightness}")
                    if state.brightness >= int(config.get("directional_down_headroom_percent", 45)):
                        break
                    if attempt == 2:
                        raise DemoError(f"Directional brightness headroom not reached after two preparations: {state}")
                    previous = state.brightness
                    self.ui.swipe_brightness(
                        device, "up", float(config.get("directional_headroom_fraction", 0.4))
                    )
                    time.sleep(float(config.get("settle_seconds", device["poll_seconds"])))
        elif intent.action in {"brightness_up", "brightness_down"}:
            self.ui.set_brightness(device, int(intent.source_value))

    def command(
        self,
        device: dict[str, Any],
        intent: LightActionIntent,
        log: EventLog | None = None,
    ) -> dict[str, Any]:
        voice = getattr(self, "voice", None)
        if voice:
            return voice.play(device, intent.action, intent.target_value, log or self.log)
        if intent.action in {"power_on", "power_off"}:
            issued = self.ui.set_power(device, str(intent.target_value))
        elif intent.action == "change_color":
            issued = self.ui.set_color(device, str(intent.target_value))
        elif self.directional_brightness(device, intent):
            config = device["ui"]["controls"]["brightness"]
            direction = "up" if intent.action == "brightness_up" else "down"
            planned_delta = abs(int(intent.target_value) - int(intent.source_value)) / 100.0
            return self.ui.swipe_brightness(
                device, direction,
                max(float(config.get("directional_min_fraction", 0.25)), planned_delta),
            )
        else:
            issued = self.ui.set_brightness(device, int(intent.target_value))
        if not issued:
            raise DemoError(f"Target state appeared before command was issued: {intent}")
        return self.ui.command_timing()

    def sample(self, device: dict[str, Any], intent: LightActionIntent, cycle: int, pcap: Path) -> None:
        name = intent.action
        self.attempts[device["id"]][name] += 1
        attempt = self.attempts[device["id"]][name]
        sample_id = f"{device['id']}-{name}-{attempt:03d}"
        log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {
            "sample_id": sample_id, "cycle": cycle, "global_cycle": cycle,
            "device_id": device["id"], "device_name": device["name"],
            "device_ip": device.get("ip"), "device_mac": device.get("mac"), "control_platform": self.plan["control_platform"],
            "action": name, "source_value": intent.source_value, "target_value": intent.target_value,
            "random_seed": self.plan["random_seed"], "raw_pcap": str(pcap), "valid": False,
            "command_mode": "host_audio" if self.voice else "ui",
        }
        try:
            settle_window = self.prepare_precondition(device, intent, log)
            if settle_window is not None:
                row["pre_baseline_settle_start_epoch"] = settle_window[0]
                row["pre_baseline_settle_end_epoch"] = settle_window[1]
                row["pre_baseline_settle_seconds"] = settle_window[1] - settle_window[0]
            row["baseline_start_epoch"] = time.time(); log.write("baseline_start", seconds=device["baseline_seconds"])
            time.sleep(float(device["baseline_seconds"]))
            before_source = self.ui.state_source(device, allow_subpage=name == "change_color")
            before = self.ui.state(device, before_source)
            tolerance = int(device.get("brightness_tolerance", 5))
            directional = self.directional_brightness(device, intent)
            if intent.required_power != before.power:
                raise DemoError(f"Pre-command power mismatch: {before}")
            if intent.action == "change_color" and before.color != intent.source_value:
                raise DemoError(f"Pre-command color mismatch: {before}")
            if directional:
                if before.brightness is None:
                    raise DemoError(f"Pre-command brightness is unreadable: {before}")
                row["source_value"] = before.brightness
            elif intent.action in {"brightness_up", "brightness_down"} and (before.brightness is None or abs(before.brightness - int(intent.source_value)) > tolerance):
                raise DemoError(f"Pre-command brightness mismatch: {before}")
            if self.voice:
                voice_result = self.command(device, intent, log)
                row.update(voice_result)
                row["command_issued_epoch"] = voice_result["voice_audio_start_epoch"]
                log.write("command_issued", action=name, target=intent.target_value, mode="host_audio")
            else:
                row["operation_started_epoch"] = time.time()
                log.write(
                    "operation_started",
                    action=name,
                    target=intent.target_value,
                    mode="ui",
                    operation_started_epoch=row["operation_started_epoch"],
                )
                row.update(self.command(device, intent, log))
                row["command_issued_epoch"] = row["gesture_start_epoch"]
                log.write(
                    "command_issued",
                    action=name,
                    target=intent.target_value,
                    mode="ui",
                    command_issued_epoch=row["command_issued_epoch"],
                )
            if directional:
                minimum_change = int(device["ui"]["controls"]["brightness"].get("directional_min_change", 5))
                if name == "brightness_up":
                    predicate = lambda state: state.power == "on" and state.brightness is not None and state.brightness >= int(before.brightness) + minimum_change
                else:
                    predicate = lambda state: state.power == "on" and state.brightness is not None and state.brightness <= int(before.brightness) - minimum_change
            else:
                predicate = lambda state: self.expected(intent, state, tolerance)
            confirmed = self.ui.wait(device, predicate, float(device["state_timeout_seconds"]), log, allow_subpage=name == "change_color")
            if directional:
                row["target_value"] = confirmed.brightness
            row["action_result_epoch"] = time.time(); row["confirmed_state"] = confirmed.__dict__
            deadline, stable, last = time.time() + float(device["tail_seconds"]), True, confirmed
            while time.time() < deadline:
                time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
                try:
                    source = self.ui.state_source(device, allow_subpage=name == "change_color")
                    last = self.ui.state(device, source)
                    if directional:
                        if not predicate(last): stable = False
                    elif not self.expected(intent, last, tolerance): stable = False
                    log.write("tail_state_poll", state=last.__dict__, stable=stable)
                except Exception as exc:
                    stable = False; log.write("tail_state_poll_failed", error=repr(exc))
            row.update({"tail_end_epoch": time.time(), "tail_state": last.__dict__, "tail_state_stable": stable})
            self.ui.diagnostic_snapshot(device, "tail_end", state=last.__dict__, stable=stable)
            reopen_confirmed = True
            reopen_state: LightState | None = None
            if stable and device.get("verify_state_after_reopen"):
                reopen_source = self.ui.reopen_detail(device)
                reopen_state = self.ui.state(device, reopen_source)
                self.ui.diagnostic_snapshot(device, "reopen", state=reopen_state.__dict__)
                reopen_confirmed = (
                    predicate(reopen_state)
                    if directional
                    else self.expected(intent, reopen_state, tolerance)
                )
                row["reopen_state"] = reopen_state.__dict__
                row["reopen_state_confirmed"] = reopen_confirmed
                log.write(
                    "reopen_postcondition",
                    state=reopen_state.__dict__,
                    confirmed=reopen_confirmed,
                )
            row["valid"] = stable and reopen_confirmed
            if not stable:
                row["reason"] = "state_changed_or_unreadable_during_tail"
            elif not reopen_confirmed:
                row["reason"] = f"state_mismatch_after_reopen:{reopen_state}"
            else:
                row["reason"] = (
                    "state_confirmed_tail_stable_and_reopen_confirmed"
                    if device.get("verify_state_after_reopen")
                    else "state_confirmed_and_tail_stable"
                )
        except Exception as exc:
            row.setdefault("tail_end_epoch", time.time())
            row["reason"] = f"sample_error:{exc}"
            log.write("sample_failed", error=repr(exc))
            self.ui.diagnostic_snapshot(device, "sample_failed", error=repr(exc))
        self.rows.append(row)
        if row["valid"]: self.counts[device["id"]][name] += 1
        self.manifest("running", pcap)

    def sample_dashboard_power(
        self, device: dict[str, Any], intent: LightActionIntent, cycle: int, pcap: Path
    ) -> None:
        name = intent.action
        self.attempts[device["id"]][name] += 1
        attempt = self.attempts[device["id"]][name]
        sample_id = f"{device['id']}-{name}-{attempt:03d}"
        log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {
            "sample_id": sample_id, "cycle": cycle, "global_cycle": cycle,
            "device_id": device["id"], "device_name": device["name"],
            "device_ip": device.get("ip"), "device_mac": device.get("mac"),
            "control_platform": self.plan["control_platform"], "action": name,
            "source_value": intent.source_value, "target_value": intent.target_value,
            "random_seed": self.plan["random_seed"], "raw_pcap": str(pcap),
            "valid": False, "command_mode": "ui_dashboard",
        }
        try:
            row["baseline_start_epoch"] = time.time()
            log.write("baseline_start", seconds=device["baseline_seconds"])
            time.sleep(float(device["baseline_seconds"]))
            before, _ = self.ui.dashboard_power_control(device)
            if before != intent.required_power:
                raise DemoError(f"Pre-command power mismatch: {before}")
            row["operation_started_epoch"] = time.time()
            timing_log = self.ui.log
            self.ui.log = log
            try:
                issued = self.ui.set_dashboard_power(device, str(intent.target_value))
                if not issued:
                    raise DemoError(f"Target state appeared before command was issued: {intent}")
                row.update(self.ui.command_timing())
            finally:
                self.ui.log = timing_log
            row["command_issued_epoch"] = row["gesture_start_epoch"]
            row["action_result_epoch"] = time.time()
            time.sleep(float(device["tail_seconds"]))
            observed, _ = self.ui.dashboard_power_control(device)
            stable = observed == intent.target_value
            row.update({
                "tail_end_epoch": time.time(), "tail_state": {"power": observed},
                "tail_state_stable": stable, "valid": stable,
                "reason": "state_confirmed_and_tail_stable" if stable else "state_changed_during_tail",
            })
        except Exception as exc:
            row.update({"tail_end_epoch": time.time(), "reason": f"sample_error:{exc}"})
            log.write("sample_failed", error=repr(exc))
        self.rows.append(row)
        if row["valid"]:
            self.counts[device["id"]][name] += 1
        self.manifest("running", pcap)

    def run_interleaved_power(self, pcap: Path) -> int:
        """Alternate each device's power state while randomizing device order."""
        if set(self.action_names) != {"power_on", "power_off"}:
            raise DemoError("interleave_devices currently supports power_on,power_off only")
        target = int(self.plan["target_valid_per_action"])
        next_action: dict[str, str] = {}
        failure_streak = {device["id"]: 0 for device in self.plan["devices"]}
        for device in self.plan["devices"]:
            if self.plan.get("dashboard_direct_toggles"):
                power, _ = self.ui.dashboard_power_control(device)
            else:
                power = self.ui.state(device, self.ui.open_detail(device)).power
            if power not in {"on", "off"}:
                raise DemoError(f"Initial power state is unknown for {device['id']}: {power}")
            next_action[device["id"]] = "power_off" if power == "on" else "power_on"
            self.log.write(
                "interleaved_initial_state",
                device=device["id"],
                power=power,
                next_action=next_action[device["id"]],
            )

        cycle = self.cycle_start - 1
        while True:
            pending = [
                device for device in self.plan["devices"]
                if any(self.counts[device["id"]][name] < target for name in self.action_names)
            ]
            if not pending:
                self.manifest("complete", pcap)
                return 0
            self.rng.shuffle(pending)
            cycle += 1
            for device in pending:
                device_id = device["id"]
                action = next_action[device_id]
                if self.counts[device_id][action] >= target:
                    action = "power_off" if action == "power_on" else "power_on"
                intent = (
                    LightActionIntent("power_on", "off", None, "on")
                    if action == "power_on"
                    else LightActionIntent("power_off", "on", None, "off")
                )
                before = self.counts[device_id][action]
                if self.plan.get("dashboard_direct_toggles"):
                    self.sample_dashboard_power(device, intent, cycle, pcap)
                else:
                    self.sample(device, intent, cycle, pcap)
                if self.counts[device_id][action] > before:
                    failure_streak[device_id] = 0
                    next_action[device_id] = "power_off" if action == "power_on" else "power_on"
                else:
                    failure_streak[device_id] += 1
                    limit = int(device.get("max_consecutive_failures", self.plan.get("max_consecutive_failures", 3)))
                    self.log.write(
                        "light_failure_streak",
                        device=device_id,
                        action=action,
                        count=failure_streak[device_id],
                        limit=limit,
                    )
                    if failure_streak[device_id] >= limit:
                        self.manifest("stopped_consecutive_failures", pcap)
                        return 3

    def run(self) -> int:
        pcap = self.root / "raw" / "batch.pcap"
        router = self.plan["router"]
        resolve_capture_addresses(self.plan, self.root, log=self.log)
        capture_filter = router.get("capture_filter") or f"not host {router['capture_transport_host']}"
        capture = RouterStreamCapture(user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None,
                                      local_pcap=pcap, log=self.log, identity_file=router.get("identity_file"), capture_filter=capture_filter)
        apply_resolved_identities(
            self.plan, run_identity_preflight(self.plan, self.root, log=self.log), log=self.log
        )
        self.manifest("starting", pcap)
        try:
            if self.plan["control_platform"] == "alexa":
                bundle_id = self.plan["controller"]["application_bundle_id"]
                self.wda.terminate(bundle_id)
                time.sleep(2)
                self.wda.launch(bundle_id)
                time.sleep(float(self.plan.get("launch_wait_seconds", 3)))
            capture.start(); self.manifest("running", pcap)
            if self.plan.get("interleave_devices"):
                return self.run_interleaved_power(pcap)
            target = int(self.plan["target_valid_per_action"])
            colors = list(self.plan["supported_colors"])
            for device in self.plan["devices"]:
                cycle = self.cycle_start - 1
                consecutive_failures = 0
                failure_limit = int(device.get("max_consecutive_failures", self.plan.get("max_consecutive_failures", 3)))
                while any(self.counts[device["id"]][name] < target for name in self.action_names):
                    cycle += 1
                    progress = False
                    for intent in light_action_cycle(colors, self.rng):
                        name = intent.action
                        if name not in self.action_names:
                            continue
                        while self.counts[device["id"]][name] < target and self.attempts[device["id"]][name] < target * 3:
                            before = self.counts[device["id"]][name]
                            self.sample(device, intent, cycle, pcap); progress = True
                            if self.counts[device["id"]][name] > before:
                                consecutive_failures = 0
                                if (
                                    name == "change_color"
                                    and self.plan.get("color_hard_reset_after_valid_sample")
                                    and self.counts[device["id"]][name] < target
                                ):
                                    self.ui.hard_reset(
                                        reason="between_valid_color_samples",
                                        wait_seconds=float(self.plan.get("color_hard_reset_wait_seconds", 8)),
                                    )
                                break
                            else:
                                consecutive_failures += 1
                                self.log.write("light_failure_streak", device=device["id"], action=name, count=consecutive_failures, limit=failure_limit)
                                if consecutive_failures >= failure_limit:
                                    self.manifest("stopped_consecutive_failures", pcap)
                                    return 3
                                if not self.plan.get("retry_same_cycle_on_failure"):
                                    break
                                if name == "change_color" and self.plan.get("color_hard_reset_on_failure"):
                                    self.ui.hard_reset(
                                        reason="failed_color_sample",
                                        wait_seconds=float(self.plan.get("color_hard_reset_wait_seconds", 8)),
                                    )
                    if not progress: break
            complete = all(value >= target for actions in self.counts.values() for value in actions.values())
            self.manifest("complete" if complete else "incomplete", pcap)
            return 0 if complete else 2
        finally:
            capture.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True); parser.add_argument("--plan", required=True)
    parser.add_argument("--target-valid-per-action", type=int); parser.add_argument("--devices")
    parser.add_argument("--actions")
    parser.add_argument("--cycle-start", type=int)
    parser.add_argument("--identity-preflight", choices=("enforce", "advisory", "off"))
    parser.add_argument("--baseline-seconds", type=float)
    parser.add_argument("--tail-seconds", type=float)
    parser.add_argument("--router-interface")
    parser.add_argument("--additional-device-plan", action="append", default=[])
    parser.add_argument("--interleave-devices", action="store_true")
    parser.add_argument("--dashboard-direct-toggles", action="store_true")
    parser.add_argument("--validate-plan-only", action="store_true")
    parser.add_argument("--diagnostic-ui-snapshots", action="store_true")
    parser.add_argument("--voice-assistant", choices=("alexa", "google_home", "siri"))
    parser.add_argument("--voice-profile", default="configs/voice_assistant_profiles.json")
    parser.add_argument("--voice-asset-root", default="runs/collection/voice/voice-assets")
    parser.add_argument("--voice-name")
    parser.add_argument("--voice-device-name", action="append", default=[])
    parser.add_argument("--allow-generate-voice-audio", action="store_true")
    args = parser.parse_args()
    from .plan_config import load_plan
    plan = load_plan(args.plan)
    if args.diagnostic_ui_snapshots:
        plan["diagnostic_ui_snapshots"] = True
    if args.identity_preflight:
        plan["identity_preflight"] = args.identity_preflight
    for extra_path in args.additional_device_plan:
        extra = json.loads(Path(extra_path).read_text(encoding="utf-8-sig"))
        if extra.get("control_platform") != plan.get("control_platform"):
            raise DemoError("Additional device plans must use the same control platform")
        plan["supported_colors"] = [
            color for color in plan.get("supported_colors", [])
            if color in set(extra.get("supported_colors", []))
        ]
        plan["devices"].extend(extra.get("devices", []))
    if args.interleave_devices:
        plan["interleave_devices"] = True
    if args.dashboard_direct_toggles:
        plan["dashboard_direct_toggles"] = True
    if args.router_interface:
        plan["router"]["interface"] = args.router_interface
    if args.target_valid_per_action is not None: plan["target_valid_per_action"] = args.target_valid_per_action
    if args.cycle_start is not None: plan["cycle_start"] = args.cycle_start
    if args.baseline_seconds is not None:
        for device in plan.get("devices", []):
            device["baseline_seconds"] = args.baseline_seconds
    if args.tail_seconds is not None:
        for device in plan.get("devices", []):
            device["tail_seconds"] = args.tail_seconds
    apply_voice_override(
        plan,
        args.voice_assistant,
        args.voice_profile,
        args.voice_asset_root,
        args.voice_name,
        args.allow_generate_voice_audio,
    )
    apply_voice_device_names(plan, args.voice_device_name)
    if args.actions:
        plan["enabled_actions"] = [value.strip() for value in args.actions.split(",") if value.strip()]
    if args.devices:
        wanted = {value.strip() for value in args.devices.split(",") if value.strip()}
        plan["devices"] = [device for device in plan["devices"] if device["id"] in wanted]
        missing = wanted - {device["id"] for device in plan["devices"]}
        if missing: raise DemoError(f"Unknown device ids: {sorted(missing)}")
    if args.validate_plan_only:
        validate_plan(plan)
        print(json.dumps({"valid": True, "platform": plan["control_platform"], "devices": [device["id"] for device in plan["devices"]]}, ensure_ascii=False))
        return 0
    return LightCollector(Path(args.run_root).resolve(), plan).run()


if __name__ == "__main__":
    raise SystemExit(main())
