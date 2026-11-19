#!/usr/bin/env python3
"""Continuously capture Alexa iOS device-control traffic with event windows.

The raw pcap is deliberately batch-scoped.  Each accepted sample is defined by
its timestamp window, rather than by starting and stopping tcpdump per action.
"""

from __future__ import annotations

import argparse
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.capture import RouterStreamCapture
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA
from collection.runtime.ios.iot_light_probe import (
    center,
    ensure_dashboard,
    find_target,
    scroll_toward_target,
    target_is_hittable,
    visible,
)
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.ios.iot_identity_preflight import (
    apply_resolved_identities,
    run_identity_preflight,
)
from collection.runtime.ios.iot_capture_network import resolve_capture_addresses
from collection.voice_assistant.iot_voice import VoiceStimulus, apply_voice_device_names, apply_voice_override


class Collector:
    def __init__(self, root: Path, plan: dict[str, Any], *, wda: WDA | None = None) -> None:
        if plan.get("control_platform") != "alexa":
            raise DemoError("This experimental collector currently supports only control_platform=alexa")
        self.root, self.plan = root, plan
        mode = plan.get("acceptance_mode", "state_confirmed")
        if mode not in {"state_confirmed", "command_traffic"}:
            raise DemoError("Unknown acceptance_mode")
        self.command_traffic = mode == "command_traffic"
        if self.command_traffic:
            from collection.runtime.ios.iot_device_traffic import supports_command_traffic
            if plan.get("command_input") or any(
                d.get("command_evidence") != "native_toggle_selection"
                or not d.get("fresh_precondition_state") or not supports_command_traffic(d)
                for d in plan["devices"]
            ):
                raise DemoError("Alexa command traffic requires explicit native toggle bindings")
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(root / "batch_events.jsonl")
        self.voice = VoiceStimulus(plan["command_input"]) if plan.get("command_input") else None
        if self.voice:
            self.voice.preflight(plan)
        self.sample_index_offset = int(plan.get("sample_index_offset", 0))
        if self.sample_index_offset < 0:
            raise DemoError("sample_index_offset must be non-negative")
        for device in plan["devices"]:
            limit = device.get("max_attempts_per_action")
            if limit is not None and (type(limit) is not int or limit < 1):
                raise DemoError("max_attempts_per_action must be a positive integer")
            if float(device.get("inter_action_cooldown_seconds", 0)) < 0:
                raise DemoError(
                    f"{device['id']} has invalid inter_action_cooldown_seconds"
                )
        self.wda = wda if wda is not None else WDA(
            plan["controller"]["wda_url"], self.log,
            snapshot_max_depth=plan["controller"].get("snapshot_max_depth", 50),
        )
        self.rows: list[dict[str, Any]] = []
        self.counts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        self.attempts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        self.confirmed_states: dict[str, str] = {}
        write_json(self.root / "effective_plan.json", self.plan)

    def manifest(self, status: str, pcap: Path | None = None) -> None:
        router = self.plan["router"]
        capture_filter = router.get("capture_filter") or f"not (host {router['capture_transport_host']} and tcp port 22)"
        write_json(self.root / "batch_manifest.json", {"experiment": self.plan["experiment"], "status": status, "updated_at": now_iso(), "control_platform": "alexa", "target_valid_per_action": self.plan["target_valid_per_action"], "valid_counts": self.counts, "attempt_counts": self.attempts, "raw_pcap": str(pcap) if pcap else None, "samples": len(self.rows), "capture_filter": capture_filter, "command_input": self.plan.get("command_input") or {"mode": "ui"}})
        if getattr(self, "command_traffic", False):
            manifest = json.loads((self.root / "batch_manifest.json").read_text(encoding="utf-8"))
            manifest.update(acceptance_mode="command_traffic", valid_counts={}, command_counts=self.counts)
            write_json(self.root / "batch_manifest.json", manifest)
        write_json(self.root / "sample_windows.json", self.rows)

    @staticmethod
    def state(device: dict[str, Any], source: str) -> str:
        menu = device.get("mode_menu")
        if menu:
            try:
                root = ET.fromstring(source)
            except ET.ParseError:
                return "unknown"
            selected = [e for e in root.iter() if visible(e)
                        and e.get("name") == menu["option_name"]
                        and e.get("value") == menu["checked_value"]]
            if len(selected) != 1:
                return "unknown"
            matches = [state for state, label in menu["state_labels"].items()
                       if selected[0].get("label") == label]
            return matches[0] if len(matches) == 1 else "unknown"
        state_element_name = device.get("state_element_name")
        if state_element_name:
            try:
                root = ET.fromstring(source)
            except ET.ParseError:
                return "unknown"
            for element in root.iter():
                if not visible(element) or element.attrib.get("name") != state_element_name:
                    continue
                observed_values = {
                    str(element.attrib.get(key) or "") for key in ("name", "label", "value")
                }
                for name, labels in device["states"].items():
                    expected_values = labels if isinstance(labels, list) else [labels]
                    if any(str(label) in observed_values for label in expected_values):
                        return name
            return "unknown"
        range_control_name = device.get("range_control_name")
        if range_control_name:
            try:
                root = ET.fromstring(source)
            except ET.ParseError:
                return "unknown"
            for element in root.iter():
                if not visible(element) or element.attrib.get("name") != range_control_name:
                    continue
                value = str(element.attrib.get("value") or "").strip().removesuffix("%")
                try:
                    percent = float(value)
                except ValueError:
                    return "unknown"
                for name, bounds in (device.get("state_percent_ranges") or {}).items():
                    if float(bounds[0]) <= percent <= float(bounds[1]):
                        return name
                return "unknown"
            return "unknown"
        for name, labels in device["states"].items():
            for label in labels if isinstance(labels, list) else [labels]:
                if device.get("state_match") == "name_label" and f"{device['name']}, {label}" in source:
                    return name
                if device.get("state_match", "label") == "label" and (f'label="{label}"' in source or f'value="{label}"' in source):
                    return name
        return "unknown"

    @staticmethod
    def _visible_named(source: str, name: str) -> ET.Element | None:
        try:
            root = ET.fromstring(source)
        except ET.ParseError:
            return None
        for element in root.iter():
            if visible(element) and element.attrib.get("name") == name:
                return element
        return None

    def _detail_is_target(self, device: dict[str, Any], source: str) -> bool:
        marker = self.plan.get("detail_page_marker", "DCPV2::ControlPage")
        if marker not in source:
            return False
        try:
            root = ET.fromstring(source)
        except ET.ParseError:
            return False
        menu = device.get("mode_menu")
        menu_open = bool(menu and self._visible_named(source, menu["dismiss_name"]) is not None)
        return any(
            (visible(element) or menu_open)
            and element.attrib.get("name") == "page-header_Bar"
            and element.attrib.get("label") == device["name"]
            for element in root.iter()
        )

    def _back_once(self, source: str) -> str:
        back = None
        for name in (
            "header-back-button",
            "now_playing_screen_header_back_button",
            "volume_control_slider_header_back_button",
        ):
            back = self._visible_named(source, name)
            if back is not None:
                break
        if back is None:
            return source
        point = center(back)
        self.log.write("navigate_back", point=point)
        self.wda.tap(point)
        time.sleep(float(self.plan["navigation"].get("back_wait_seconds", 2)))
        return self.wda.source()

    def _mode_source(self, device: dict[str, Any], source: str) -> str:
        menu = device.get("mode_menu")
        if not menu:
            return source
        if not self._detail_is_target(device, source):
            raise DemoError("Mode menu requires exact device detail identity")
        if self._visible_named(source, menu["dismiss_name"]) is None:
            control = self._visible_named(source, menu["open_name"])
            if control is None:
                raise DemoError("Mode menu control is not visible")
            self.wda.tap(center(control))
            time.sleep(float(menu.get("open_wait_seconds", 1)))
            source = self.wda.source()
        for poll in range(3):
            if self._detail_is_target(device, source) and self._visible_named(source, menu["dismiss_name"]) is not None:
                return source
            if poll < 2:
                time.sleep(float(menu.get("open_wait_seconds", 1)))
                source = self.wda.source()
        (self.root / "mode-menu-failure.xml").write_text(source, encoding="utf-8")
        raise DemoError("Mode menu did not open on the exact device after bounded readback")

    def _wait_for_detail_page(self, device: dict[str, Any]) -> str:
        """Wait for the exact detail identity while Alexa finishes rendering."""
        initial_wait = float(device.get("open_wait_seconds", 3))
        timeout = float(device.get("detail_page_timeout_seconds", initial_wait))
        poll_seconds = float(device.get("detail_page_poll_seconds", 1))
        if initial_wait < 0 or timeout < initial_wait or poll_seconds <= 0:
            raise DemoError(f"Invalid detail-page wait settings for {device['id']}")
        started = time.monotonic()
        time.sleep(initial_wait)
        source = self.wda.source()
        while not self._detail_is_target(device, source):
            remaining = started + timeout - time.monotonic()
            if remaining <= 0:
                break
            self.log.write(
                "detail_page_confirmation_wait",
                device=device["id"],
                remaining_seconds=remaining,
            )
            time.sleep(min(poll_seconds, remaining))
            source = self.wda.source()
        return source

    def issue_ui_control(
        self,
        device: dict[str, Any],
        source: str,
        from_state: str,
        target_state: str,
        log: EventLog,
    ) -> dict[str, Any]:
        menu = device.get("mode_menu")
        if menu:
            source = self._mode_source(device, source)
            if self.state(device, source) != from_state:
                raise DemoError("Mode source changed before command")
            label = menu["state_labels"].get(target_state)
            options = [e for e in ET.fromstring(source).iter() if visible(e)
                       and e.get("name") == menu["option_name"] and e.get("label") == label]
            if from_state == target_state or label is None or len(options) != 1:
                raise DemoError("Mode target is missing, ambiguous, or unchanged")
            point = center(options[0]); started = time.time()
            log.write("semantic_control_gesture_start", device=device["id"], point=point, epoch=started)
            self.wda.tap(point)
            completed = time.time()
            log.write("semantic_control_gesture_complete", device=device["id"], point=point, epoch=completed)
            return {"gesture_type": "mode_option", "gesture_start_epoch": started,
                    "gesture_complete_epoch": completed, "gesture_start_point": point,
                    "gesture_end_point": point}
        control_name = device.get("control_element_name")
        if control_name:
            control = self._visible_named(source, str(control_name))
            if control is None:
                raise DemoError(f"Alexa control {control_name!r} is not visible for {device['id']}")
            point = center(control)
            started = time.time()
            log.write("semantic_control_gesture_start", device=device["id"], point=point, epoch=started)
            self.wda.tap(point)
            completed = time.time()
            log.write("semantic_control_gesture_complete", device=device["id"], point=point, epoch=completed)
            return {
                "gesture_type": "tap",
                "gesture_start_epoch": started,
                "gesture_complete_epoch": completed,
                "gesture_start_point": point,
                "gesture_end_point": point,
            }

        range_name = device.get("range_control_name")
        control = self._visible_named(source, str(range_name)) if range_name else None
        if control is None:
            raise DemoError(f"Alexa range control {range_name!r} is not visible for {device['id']}")
        fractions = device.get("state_fractions") or {}
        if from_state not in fractions or target_state not in fractions:
            raise DemoError(f"Missing range-control fractions for {device['id']}")
        x = int(control.attrib["x"])
        y = int(control.attrib["y"]) + int(control.attrib["height"]) // 2
        width = int(control.attrib["width"])
        start = {"x": x + int(width * float(fractions[from_state])), "y": y}
        end = {"x": x + int(width * float(fractions[target_state])), "y": y}
        gesture_type = str(device.get("gesture_type") or "drag")
        started = time.time()
        log.write(
            "semantic_range_gesture_start",
            device=device["id"], from_state=from_state, target_state=target_state,
            gesture_type=gesture_type, point_start=start, point_end=end, epoch=started,
        )
        if gesture_type == "tap":
            self.wda.tap(end)
        elif gesture_type == "drag":
            self.wda.drag(start, end, float(device.get("gesture_duration_seconds", 1.0)))
        else:
            raise DemoError(f"Unsupported Alexa range gesture {gesture_type!r} for {device['id']}")
        completed = time.time()
        log.write(
            "semantic_range_gesture_complete",
            device=device["id"], from_state=from_state, target_state=target_state,
            gesture_type=gesture_type, point_start=start, point_end=end, epoch=completed,
        )
        return {
            "gesture_type": gesture_type,
            "gesture_start_epoch": started,
            "gesture_complete_epoch": completed,
            "gesture_start_point": start,
            "gesture_end_point": end,
        }

    def guarded_source(self, device: dict[str, Any], log: EventLog) -> tuple[bool, str]:
        expected_bundle = self.plan["controller"]["application_bundle_id"]
        active_bundle = self.wda.active_bundle_id()
        if active_bundle != expected_bundle:
            if active_bundle == "com.apple.springboard" and (
                getattr(self, "command_traffic", False)
                or self.plan.get("corroborate_springboard_foreground") is True
            ):
                from collection.runtime.mobile_control.wda import corroborate_native_foreground
                source = corroborate_native_foreground(
                    self.wda, expected_bundle, self.plan["controller"].get("application"),
                    lambda value: self._detail_is_target(device, value), log, device["id"],
                    "native_foreground_corroboration",
                )
                if source is not None:
                    return True, self._mode_source(device, source)
            log.write("foreground_guard_failed", expected_bundle=expected_bundle, active_bundle=active_bundle, device=device["id"])
            return False, ""
        source = self.wda.source()
        if device.get("view") == "detail":
            page_valid = self._detail_is_target(device, source)
        else:
            page_valid = self.plan["navigation"]["device_list_marker"] in source and device["name"] in source
        if not page_valid:
            log.write("device_view_guard_failed", device=device["id"])
            return False, source
        return True, self._mode_source(device, source)

    def dismiss_mode_menu(self, device: dict[str, Any], source: str) -> str:
        """Dismiss only this binding's identified menu, including cross-control use."""
        menu = device.get("mode_menu")
        if menu:
            dismiss = self._visible_named(source, menu["dismiss_name"])
            if dismiss is not None:
                if not self._detail_is_target(device, source):
                    raise DemoError("Cannot dismiss mode menu without exact device identity")
                root = ET.fromstring(source)
                left = max(0, int(dismiss.get("x", "0")))
                top = max(0, int(dismiss.get("y", "0")))
                right = min(int(root.get("width", "0")), int(dismiss.get("x", "0")) + int(dismiss.get("width", "0")))
                bottom = min(int(root.get("height", "0")), int(dismiss.get("y", "0")) + int(dismiss.get("height", "0")))
                if right <= left or bottom <= top:
                    raise DemoError("Mode dismiss overlay has no visible viewport intersection")
                self.wda.tap({"x": (left + right) // 2, "y": (top + bottom) // 2})
                time.sleep(float(menu.get("open_wait_seconds", 1)))
                source = self.wda.source()
                if self._visible_named(source, menu["dismiss_name"]) is not None:
                    raise DemoError("Known mode menu did not dismiss")
        return source

    def open_device(self, device: dict[str, Any]) -> str:
        self.wda.launch(self.plan["controller"]["application_bundle_id"])
        time.sleep(float(device.get("launch_wait_seconds", 2)))
        source = self.dismiss_mode_menu(device, self.wda.source())
        detail_marker = self.plan.get("detail_page_marker", "DCPV2::ControlPage")
        if device.get("navigation_mode") == "semantic_detail":
            for _ in range(3):
                marker = str(self.plan["navigation"]["device_list_marker"])
                if self._visible_named(source, marker) is not None:
                    break
                updated = self._back_once(source)
                if updated == source:
                    break
                source = updated
            source = ensure_dashboard("alexa", source, self.wda, self.log)
        else:
            if detail_marker in source:
                self.wda.tap(self.plan["navigation"]["back_tap"])
                time.sleep(float(self.plan["navigation"].get("back_wait_seconds", 2)))
                source = self.wda.source()
            if self.plan["navigation"]["device_list_marker"] not in source:
                raise DemoError(f"Alexa device list is not visible for {device['id']}")
        if device.get("view") == "detail":
            if device.get("navigation_mode") == "semantic_detail":
                target = find_target("alexa", source, device["name"])
                for attempt in range(6):
                    if target is not None and target_is_hittable("alexa", target):
                        break
                    self.log.write("target_not_hittable", device=device["id"], attempt=attempt + 1)
                    scroll_toward_target("alexa", target, self.wda, source=source, target_name=device["name"])
                    time.sleep(2)
                    source = self.wda.source()
                    target = find_target("alexa", source, device["name"])
                if target is None or not target_is_hittable("alexa", target):
                    raise DemoError(f"Alexa device tile is not hittable for {device['id']}")
                point = center(target)
                selector = str(target.attrib["name"])
                self.log.write("open_device_detail", device=device["id"], point=point,
                               accessibility_name=selector)
                self.wda.click_accessibility(selector)
            else:
                self.wda.tap(device["list_tap"])
            source = self._wait_for_detail_page(device)
            if not self._detail_is_target(device, source):
                raise DemoError(f"Alexa device page is not confirmed for {device['id']}")
        return self._mode_source(device, source)

    def wait_state(self, device: dict[str, Any], expected: str, timeout: float, log: EventLog) -> tuple[bool, str, float | None]:
        started, observed = time.time(), "unknown"
        while time.time() - started < timeout:
            time.sleep(float(device["poll_seconds"]))
            guarded, source = self.guarded_source(device, log)
            if not guarded:
                observed = "foreground_or_view_mismatch"
                continue
            observed = self.state(device, source)
            log.write("state_poll", expected=expected, observed=observed)
            if observed == expected:
                return True, observed, time.time() - started
        return False, observed, None

    def observe_tail_state(
        self,
        device: dict[str, Any],
        expected: str,
        duration: float,
        log: EventLog,
    ) -> tuple[bool, str]:
        deadline = time.time() + duration
        observed = expected
        stable = True
        guarded_at_end = True
        while time.time() < deadline:
            time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
            if time.time() > deadline + 0.1:
                break
            guarded, source = self.guarded_source(device, log)
            if not guarded:
                guarded_at_end = False
                continue
            guarded_at_end = True
            observed = self.state(device, source)
            log.write("tail_state_poll", expected=expected, observed=observed)
            if observed in device["states"] and observed != expected:
                stable = False
        return stable and guarded_at_end and observed == expected, observed

    def normalize(self, device: dict[str, Any], expected: str) -> bool:
        for cycle in range(4):
            current = self.state(device, self.open_device(device))
            self.log.write("precondition_state", device=device["id"], expected=expected, observed=current, cycle=cycle + 1)
            if current == expected:
                return True
            if current in device["states"]:
                if device.get("navigation_mode") == "semantic_detail":
                    self.issue_ui_control(device, self.wda.source(), current, expected, self.log)
                else:
                    self.wda.tap(device["control_tap"])
                ok, _, _ = self.wait_state(device, expected, float(device["state_timeout_seconds"]), self.log)
                if ok:
                    return True
            time.sleep(3)
        return False

    def ensure_prerequisites(
        self, device: dict[str, Any], log: EventLog
    ) -> tuple[bool, list[dict[str, Any]]]:
        checks: list[dict[str, Any]] = []
        for prerequisite in device.get("prerequisites") or []:
            required_state = str(prerequisite.get("required_state") or "")
            started = time.time()
            ok = bool(required_state) and self.normalize(prerequisite, required_state)
            check = {
                "device_id": prerequisite.get("id"),
                "device_name": prerequisite.get("name"),
                "required_state": required_state,
                "confirmed": ok,
                "checked_at_epoch": time.time(),
                "elapsed_seconds": time.time() - started,
            }
            checks.append(check)
            log.write("prerequisite_state_check", **check)
            if not ok:
                return False, checks
        return True, checks

    def sample(self, device: dict[str, Any], action: dict[str, Any], pcap: Path) -> None:
        action_name = action["name"]
        self.attempts[device["id"]][action_name] += 1
        attempt = self.attempts[device["id"]][action_name]
        sample_number = self.sample_index_offset + attempt
        sample_id = f"{device['id']}-{action_name}-{sample_number:03d}"
        sample_log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {"sample_id": sample_id, "device_id": device["id"], "device_name": device["name"], "device_ip": device.get("ip"), "device_mac": device.get("mac"), "control_platform": "alexa", "controller_bundle_id": self.plan["controller"]["application_bundle_id"], "action": action_name, "expected_initial_state": action["from"], "expected_state": action["to"], "raw_pcap": str(pcap), "command_mode": "host_audio" if self.voice else "ui", "valid": False}
        prerequisites_ok, prerequisite_checks = self.ensure_prerequisites(device, sample_log)
        row["prerequisite_checks"] = prerequisite_checks
        if not prerequisites_ok:
            row["reason"] = "prerequisite_state_not_confirmed"
            self.rows.append(row); self.manifest("running", pcap); return
        state_known = False
        if device.get("fresh_precondition_state"):
            guarded, source = (self.guarded_source(device, sample_log)
                               if device.get("reuse_current_detail") else (False, ""))
            if not guarded:
                source = self.open_device(device)
            observed_before = self.state(device, source)
            sample_log.write(
                "fresh_precondition_state",
                expected=action["from"],
                observed=observed_before,
            )
            state_known = observed_before == action["from"]
            if not state_known and not device.get("allow_precondition_normalization", True):
                row["reason"] = f"fresh_initial_state_mismatch:{observed_before}"
                self.confirmed_states.pop(device["id"], None)
                self.rows.append(row); self.manifest("running", pcap); return
        elif self.confirmed_states.get(device["id"]) == action["from"]:
            guarded, source = self.guarded_source(device, sample_log)
            observed_before = self.state(device, source) if guarded else "foreground_or_view_mismatch"
            sample_log.write("precondition_recheck", expected=action["from"], observed=observed_before)
            state_known = observed_before == action["from"]
        if not state_known and not self.normalize(device, action["from"]):
            row["reason"] = "initial_state_not_confirmed"
            self.rows.append(row); self.manifest("running", pcap); return
        if not state_known:
            guarded, source = self.guarded_source(device, sample_log)
            observed_before = self.state(device, source) if guarded else "foreground_or_view_mismatch"
            sample_log.write("fresh_precondition_state", expected=action["from"], observed=observed_before,
                             after_normalization=True)
            if observed_before != action["from"]:
                row["reason"] = "normalized_initial_state_changed"
                self.rows.append(row); self.manifest("running", pcap); return
        row["baseline_start_epoch"] = time.time(); sample_log.write("baseline_start", seconds=device["baseline_seconds"])
        time.sleep(float(device["baseline_seconds"]))
        guarded, _ = self.guarded_source(device, sample_log)
        if not guarded:
            row.update({"tail_end_epoch": time.time(), "reason": "foreground_or_view_mismatch_before_command"})
            self.confirmed_states.pop(device["id"], None)
            self.rows.append(row); self.manifest("running", pcap); return
        if self.voice:
            voice_result = self.voice.play(device, action_name, action.get("to"), sample_log)
            row.update(voice_result)
            row["command_issued_epoch"] = voice_result["voice_audio_start_epoch"]
            sample_log.write("command_issued", action=action_name, mode="host_audio")
        else:
            if device.get("navigation_mode") == "semantic_detail":
                source = self.wda.source()
                if getattr(self, "command_traffic", False) and self.state(device, source) != action["from"]:
                    row.update(tail_end_epoch=time.time(), reason="source_changed_before_command")
                    self.rows.append(row); self.manifest("running", pcap)
                    return
                gesture = self.issue_ui_control(device, source, action["from"], action["to"], sample_log)
                row.update(gesture)
                row["command_issued_epoch"] = gesture["gesture_start_epoch"]
                sample_log.write("command_issued", action=action_name, mode="ui", gesture=gesture["gesture_type"])
            else:
                row["command_issued_epoch"] = time.time(); sample_log.write("command_issued", action=action_name, mode="ui", point=device["control_tap"])
                self.wda.tap(device["control_tap"])
        if getattr(self, "command_traffic", False):
            # State changes during this window are observations, not rejection.
            row.update(source_value=action["from"], target_value=action["to"],
                       observed_before=observed_before, source_state_confirmed=True,
                       selected_native_control={"name": device["control_element_name"]},
                       state_confirmed=False, command_capture_complete=False,
                       action_result_epoch=time.time())
            deadline = time.time() + max(30, float(device["tail_seconds"]))
            while time.time() < deadline:
                time.sleep(min(float(device["poll_seconds"]), max(0, deadline - time.time())))
                guarded, source = self.guarded_source(device, sample_log)
                if not guarded:
                    row.update(tail_end_epoch=time.time(), reason="foreground_or_view_changed_during_command_capture")
                    self.rows.append(row)
                    self.manifest("running", pcap)
                    raise DemoError("Target accessory page changed during command capture")
                row["observed_after"] = self.state(device, source)
                sample_log.write("traffic_tail_observation", state=row["observed_after"])
            row.update(tail_end_epoch=time.time(), command_capture_complete=True,
                       reason="command_captured_state_unconfirmed")
            self.rows.append(row)
            self.counts[device["id"]][action_name] += 1
            self.confirmed_states.pop(device["id"], None)
            sample_log.write("sample_end", valid=False, command_capture_complete=True)
            self.manifest("running", pcap)
            return
        ok, observed, latency = self.wait_state(device, action["to"], float(device["state_timeout_seconds"]), sample_log)
        row.update({"state_confirmed": ok, "observed_state": observed, "latency_seconds": latency, "action_result_epoch": time.time()})
        sample_log.write("action_result", valid=ok, observed_state=observed, latency_seconds=latency)
        tail_stable, tail_observed = self.observe_tail_state(
            device,
            action["to"],
            float(device["tail_seconds"]),
            sample_log,
        )
        row["tail_end_epoch"] = time.time()
        reopen_confirmed = True
        reopen_observed: str | None = None
        if ok and tail_stable and device.get("verify_state_after_reopen"):
            reopened_source = self.open_device(device)
            reopen_observed = self.state(device, reopened_source)
            reopen_confirmed = reopen_observed == action["to"]
            sample_log.write(
                "reopen_postcondition",
                expected=action["to"],
                observed=reopen_observed,
                confirmed=reopen_confirmed,
            )
            row["reopen_state_confirmed"] = reopen_confirmed
            row["reopen_observed_state"] = reopen_observed
        valid = ok and tail_stable and reopen_confirmed
        if not ok:
            reason = f"state_timeout:{observed}"
        elif not tail_stable:
            reason = f"state_changed_during_tail:{tail_observed}"
        elif not reopen_confirmed:
            reason = f"state_mismatch_after_reopen:{reopen_observed}"
        else:
            reason = "state_confirmed_and_tail_stable"
        row["tail_state_stable"] = tail_stable
        row["tail_observed_state"] = tail_observed; row["valid"] = valid; row["reason"] = reason
        sample_log.write("sample_end", valid=valid, reason=row["reason"])
        self.rows.append(row)
        if valid:
            self.counts[device["id"]][action_name] += 1
            self.confirmed_states[device["id"]] = action["to"]
        else:
            self.confirmed_states.pop(device["id"], None)
        self.manifest("running", pcap)

    def run(self) -> int:
        raw_pcap = self.root / "raw" / "batch.pcap"
        router = self.plan["router"]
        resolve_capture_addresses(self.plan, self.root, log=self.log)
        capture_filter = router.get("capture_filter") or f"not (host {router['capture_transport_host']} and tcp port 22)"
        capture = RouterStreamCapture(user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None, local_pcap=raw_pcap, log=self.log, identity_file=router.get("identity_file"), capture_filter=capture_filter)
        apply_resolved_identities(
            self.plan, run_identity_preflight(self.plan, self.root, log=self.log), log=self.log
        )
        self.manifest("starting", raw_pcap)
        try:
            capture.start(); self.manifest("running", raw_pcap)
            target = int(self.plan["target_valid_per_action"])
            for device in self.plan["devices"]:
                attempt_limit = device.get("max_attempts_per_action", target * 3)
                while any(self.counts[device["id"]][a["name"]] < target for a in device["actions"]):
                    progress = False
                    for action in device["actions"]:
                        action_name = action["name"]
                        if (
                            self.counts[device["id"]][action_name] < target
                            and self.attempts[device["id"]][action_name] < attempt_limit
                        ):
                            self.sample(device, action, raw_pcap); progress = True
                            pending = any(
                                self.counts[device["id"]][item["name"]] < target
                                and self.attempts[device["id"]][item["name"]] < attempt_limit
                                for item in device["actions"]
                            )
                            cooldown = float(
                                device.get("inter_action_cooldown_seconds", 0)
                            )
                            if pending and cooldown > 0:
                                self.log.write(
                                    "inter_action_cooldown",
                                    device=device["id"],
                                    completed_action=action_name,
                                    seconds=cooldown,
                                )
                                time.sleep(cooldown)
                    if not progress:
                        break
            # A checked mode menu can hide the back/list controls needed by
            # the next device's collector. Close only a declared, identity-
            # guarded sheet; this never changes the appliance's selected mode.
            for device in self.plan["devices"]:
                if device.get("mode_menu"):
                    self.dismiss_mode_menu(device, self.wda.source())
            complete = all(value >= target for values in self.counts.values() for value in values.values())
            self.manifest(("command_capture_complete" if getattr(self, "command_traffic", False)
                           else "complete") if complete else "incomplete", raw_pcap)
            return 0 if complete else 2
        except Exception as exc:
            self.log.write("collector_error", error_type=type(exc).__name__, detail=str(exc))
            self.manifest("failed", raw_pcap)
            raise
        finally:
            capture.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--target-valid-per-action", type=int)
    parser.add_argument("--inter-action-cooldown-seconds", type=float)
    parser.add_argument("--devices")
    parser.add_argument("--voice-assistant", choices=("alexa", "google_home", "siri"))
    parser.add_argument("--voice-profile", default="configs/voice_assistant_profiles.json")
    parser.add_argument("--voice-asset-root", default="runs/collection/voice/voice-assets")
    parser.add_argument("--voice-name")
    parser.add_argument("--voice-device-name", action="append", default=[])
    parser.add_argument("--allow-generate-voice-audio", action="store_true")
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
    apply_voice_override(
        plan,
        args.voice_assistant,
        args.voice_profile,
        args.voice_asset_root,
        args.voice_name,
        args.allow_generate_voice_audio,
    )
    apply_voice_device_names(plan, args.voice_device_name)
    if args.devices:
        wanted = {value.strip() for value in args.devices.split(",") if value.strip()}
        plan["devices"] = [device for device in plan["devices"] if device["id"] in wanted]
        if wanted != {device["id"] for device in plan["devices"]}:
            raise DemoError(f"Unknown device ids: {sorted(wanted - {device['id'] for device in plan['devices']})}")
    return Collector(Path(args.run_root).resolve(), plan).run()


if __name__ == "__main__":
    raise SystemExit(main())
