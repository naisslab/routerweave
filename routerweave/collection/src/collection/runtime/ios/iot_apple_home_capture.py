#!/usr/bin/env python3
"""Collect timestamp-labelled Apple Home actions in one continuous router pcap."""

from __future__ import annotations

import argparse
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.capture import RouterStreamCapture
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.ios.iot_identity_preflight import (
    apply_resolved_identities,
    run_identity_preflight,
)
from collection.runtime.ios.iot_capture_network import resolve_capture_addresses
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA
from collection.voice_assistant.iot_voice import VoiceStimulus, apply_voice_device_names, apply_voice_override


def _truthy(value: str | None) -> bool:
    return str(value).lower() == "true"


class AppleHomeCollector:
    def __init__(self, root: Path, plan: dict[str, Any], *, wda: WDA | None = None) -> None:
        if plan.get("control_platform") != "apple_home":
            raise DemoError("Expected control_platform=apple_home")
        self.root, self.plan = root, plan
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(root / "batch_events.jsonl")
        self.voice = VoiceStimulus(plan["command_input"]) if plan.get("command_input") else None
        if self.voice:
            self.voice.preflight(plan)
        self.wda = wda if wda is not None else WDA(plan["controller"]["wda_url"], self.log)
        self.rows: list[dict[str, Any]] = []
        self.counts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        self.attempts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        self.confirmed_states: dict[str, str] = {}
        write_json(self.root / "effective_plan.json", self.plan)

    def manifest(self, status: str, pcap: Path | None = None) -> None:
        router = self.plan["router"]
        capture_filter = router.get("capture_filter") or f"not host {router['capture_transport_host']}"
        write_json(
            self.root / "batch_manifest.json",
            {
                "experiment": self.plan["experiment"],
                "status": status,
                "updated_at": now_iso(),
                "control_platform": "apple_home",
                "target_valid_per_action": self.plan["target_valid_per_action"],
                "valid_counts": self.counts,
                "attempt_counts": self.attempts,
                "raw_pcap": str(pcap) if pcap else None,
                "samples": len(self.rows),
                "capture_filter": capture_filter,
                "command_input": self.plan.get("command_input") or {"mode": "ui"},
            },
        )
        write_json(self.root / "sample_windows.json", self.rows)

    @staticmethod
    def _parse(source: str) -> ET.Element:
        try:
            return ET.fromstring(source)
        except ET.ParseError as exc:
            raise DemoError(f"Invalid WDA source XML: {exc}") from exc

    @staticmethod
    def _center(element: ET.Element) -> dict[str, int]:
        return {
            "x": int(element.attrib["x"]) + int(element.attrib["width"]) // 2,
            "y": int(element.attrib["y"]) + int(element.attrib["height"]) // 2,
        }

    def _visible_named(self, source: str, name: str) -> ET.Element | None:
        for element in self._parse(source).iter():
            if _truthy(element.attrib.get("visible")) and element.attrib.get("name") == name:
                return element
        return None

    def _tile(self, device: dict[str, Any], source: str) -> ET.Element | None:
        if device.get("tile_name"):
            return self._visible_named(source, device["tile_name"])
        prefix = f"{device['name']}, "
        for element in self._parse(source).iter("XCUIElementTypeCell"):
            if _truthy(element.attrib.get("visible")) and element.attrib.get("label", "").startswith(prefix):
                return element
        return None

    @staticmethod
    def state(device: dict[str, Any], tile: ET.Element | None) -> str:
        if tile is None:
            return "unknown"
        label = tile.attrib.get("label", "")
        for state, labels in device["states"].items():
            for value in labels if isinstance(labels, list) else [labels]:
                if label == f"{device['name']}, {value}":
                    return state
        return "unknown"

    def _detail_slider(self, device: dict[str, Any], source: str) -> ET.Element | None:
        config = device.get("detail_slider") or {}
        expected_label = str(config.get("label") or "")
        for element in self._parse(source).iter("XCUIElementTypeOther"):
            if not _truthy(element.attrib.get("visible")):
                continue
            if not str(element.attrib.get("name") or "").endswith(".LargeSlider"):
                continue
            if expected_label and element.attrib.get("label") != expected_label:
                continue
            return element
        return None

    def _detail_sheet(self, source: str) -> ET.Element | None:
        for element in self._parse(source).iter("XCUIElementTypeScrollView"):
            if (
                _truthy(element.attrib.get("visible"))
                and element.attrib.get("name") == "AccessoryControl.SheetView"
            ):
                return element
        return None

    def dismiss_restored_detail(self, source: str, log: EventLog) -> str:
        close = self._visible_named(
            source, self.plan.get("detail_close_name", "关闭")
        )
        if close is not None and self._visible_named(source, "QuickControlSwitch") is not None:
            point = self._center(close)
            log.write("dismiss_restored_switch_detail", point=point)
            self.wda.tap(point)
        else:
            sheet = self._detail_sheet(source)
            if sheet is None:
                return source
            x = int(sheet.attrib["x"]) + max(20, int(int(sheet.attrib["width"]) * 0.08))
            y = int(sheet.attrib["y"])
            height = int(sheet.attrib["height"])
            start = {"x": x, "y": y + int(height * 0.15)}
            end = {"x": x, "y": y + int(height * 0.90)}
            log.write(
                "dismiss_restored_accessory_sheet",
                point_start=start,
                point_end=end,
            )
            self.wda.drag(start, end, 0.9)
        time.sleep(float(self.plan.get("detail_close_wait_seconds", 2)))
        return self.wda.source()

    def _detail_matches(self, device: dict[str, Any], source: str) -> bool:
        slider = self._detail_slider(device, source)
        if slider is None:
            return False
        return any(
            _truthy(element.attrib.get("visible"))
            and element.attrib.get("name") == "AccessoryControl.SheetView"
            and element.attrib.get("label") == device["name"]
            for element in self._parse(source).iter("XCUIElementTypeStaticText")
        )

    def _detail_state(self, device: dict[str, Any], source: str) -> str:
        if not self._detail_matches(device, source):
            return "unknown"
        if device.get("detail_button"):
            button = self._visible_named(source, device["detail_button"]["name"])
            value = button.get("value", "") if button is not None else ""
            return next((state for state, values in device["detail_button"]["state_values"].items()
                         if value in values), "unknown")
        slider = self._detail_slider(device, source)
        value_ranges = (device.get("detail_slider") or {}).get("state_value_ranges") or {}
        if slider is not None and value_ranges:
            match = re.search(r"(-?\d+(?:\.\d+)?)\s*%", str(slider.attrib.get("value") or ""))
            if match:
                percentage = float(match.group(1))
                for state, bounds in value_ranges.items():
                    if (
                        isinstance(bounds, list)
                        and len(bounds) == 2
                        and float(bounds[0]) <= percentage <= float(bounds[1])
                    ):
                        return str(state)
        visible_labels = {
            str(element.attrib.get("label") or "")
            for element in self._parse(source).iter("XCUIElementTypeStaticText")
            if _truthy(element.attrib.get("visible"))
            and element.attrib.get("name") == "AccessoryControl.SheetView"
        }
        for state, labels in device["states"].items():
            for value in labels if isinstance(labels, list) else [labels]:
                if value in visible_labels:
                    return state
        return "unknown"

    def observed_state(self, device: dict[str, Any], source: str) -> str:
        if device.get("state_view") == "detail_slider":
            return self._detail_state(device, source)
        return self.state(device, self._tile(device, source))

    def ensure_dashboard(self, device: dict[str, Any], log: EventLog) -> tuple[bool, str]:
        bundle_id = self.plan["controller"]["application_bundle_id"]
        if self.wda.active_bundle_id() != bundle_id:
            self.wda.launch(bundle_id)
            time.sleep(float(self.plan.get("launch_wait_seconds", 2)))
        if self.wda.active_bundle_id() != bundle_id:
            log.write("foreground_guard_failed", expected_bundle=bundle_id, active_bundle=self.wda.active_bundle_id())
            return False, ""
        source = self.wda.source()
        source = self.dismiss_restored_detail(source, log)
        tile = self._tile(device, source)
        dashboard = self._visible_named(source, self.plan.get("dashboard_name", "我的家"))
        if dashboard is None or tile is None:
            log.write("device_view_guard_failed", device=device["id"])
            return False, source
        return True, source

    def ensure_device_view(self, device: dict[str, Any], log: EventLog) -> tuple[bool, str]:
        if device.get("state_view") != "detail_slider":
            return self.ensure_dashboard(device, log)
        bundle_id = self.plan["controller"]["application_bundle_id"]
        if self.wda.active_bundle_id() != bundle_id:
            self.wda.launch(bundle_id)
            time.sleep(float(self.plan.get("launch_wait_seconds", 2)))
        if self.wda.active_bundle_id() != bundle_id:
            log.write("foreground_guard_failed", expected_bundle=bundle_id, active_bundle=self.wda.active_bundle_id())
            return False, ""
        source = self.wda.source()
        if self._detail_matches(device, source):
            return True, source
        source = self.dismiss_restored_detail(source, log)
        tile = self._tile(device, source)
        dashboard = self._visible_named(source, self.plan.get("dashboard_name", "我的家"))
        if dashboard is None or tile is None:
            log.write("device_view_guard_failed", device=device["id"], expected_view="detail_slider")
            return False, source
        point = {
            "x": int(tile.attrib["x"]) + int(int(tile.attrib["width"]) * 0.75),
            "y": int(tile.attrib["y"]) + int(tile.attrib["height"]) // 2,
        }
        log.write("open_device_detail", device=device["id"], point=point)
        self.wda.tap(point)
        time.sleep(float(device.get("detail_open_wait_seconds", 3)))
        source = self.wda.source()
        if not self._detail_matches(device, source):
            log.write("device_view_guard_failed", device=device["id"], expected_view="detail_slider")
            return False, source
        return True, source

    @staticmethod
    def control_point(tile: ET.Element) -> dict[str, int]:
        # Home's icon is the direct action target; the rest of a tile opens details.
        return {"x": int(tile.attrib["x"]) + 31, "y": int(tile.attrib["y"]) + 31}

    def issue_detail_slider(
        self,
        device: dict[str, Any],
        source: str,
        from_state: str,
        target_state: str,
        log: EventLog,
    ) -> dict[str, Any]:
        if device.get("detail_button"):
            if not self._detail_matches(device, source):
                raise DemoError("Exact detail identity is missing")
            button = self._visible_named(source, device["detail_button"]["name"])
            if button is None or self.observed_state(device, source) != from_state:
                raise DemoError("Detail button source state is not confirmed")
            started = time.time()
            self.wda.tap(self._center(button))
            log.write("detail_button_command", device=device["id"], from_state=from_state,
                      target_state=target_state, epoch=started)
            return {"gesture_type": "tap", "gesture_start_epoch": started,
                    "gesture_complete_epoch": time.time()}
        slider = self._detail_slider(device, source)
        if slider is None:
            raise DemoError(f"Detail slider is not visible for {device['id']}")
        config = device.get("detail_slider") or {}
        fractions = config.get("state_fractions") or {}
        if from_state not in fractions or target_state not in fractions:
            raise DemoError(f"Missing detail-slider fractions for {device['id']}")
        x = int(slider.attrib["x"]) + int(slider.attrib["width"]) // 2
        y = int(slider.attrib["y"])
        height = int(slider.attrib["height"])
        start = {"x": x, "y": y + int(height * float(fractions[from_state]))}
        end = {"x": x, "y": y + int(height * float(fractions[target_state]))}
        gesture_type = str(config.get("gesture_type") or "drag")
        started = time.time()
        log.write(
            "detail_slider_gesture_start",
            device=device["id"], from_state=from_state, target_state=target_state,
            gesture_type=gesture_type, point_start=start, point_end=end, epoch=started,
        )
        if gesture_type == "tap":
            self.wda.tap(end)
        elif gesture_type == "drag":
            self.wda.drag(start, end, float(config.get("duration_seconds", 1.0)))
        else:
            raise DemoError(f"Unsupported detail-slider gesture {gesture_type!r} for {device['id']}")
        completed = time.time()
        log.write(
            "detail_slider_gesture_complete",
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

    def wait_state(self, device: dict[str, Any], expected: str, timeout: float, log: EventLog) -> tuple[bool, str, float | None]:
        started, observed = time.time(), "unknown"
        while time.time() - started < timeout:
            time.sleep(float(device["poll_seconds"]))
            if self.wda.active_bundle_id() != self.plan["controller"]["application_bundle_id"]:
                observed = "foreground_mismatch"
                log.write("state_poll", expected=expected, observed=observed)
                continue
            source = self.wda.source()
            observed = self.observed_state(device, source)
            log.write("state_poll", expected=expected, observed=observed)
            if observed == expected:
                return True, observed, time.time() - started
        return False, observed, None

    def observe_tail(
        self, device: dict[str, Any], expected: str, log: EventLog, *,
        duration_seconds: float | None = None, poll_event: str = "tail_state_poll",
        settle_window: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        duration = float(device["tail_seconds"]) if duration_seconds is None else duration_seconds
        started = time.time()
        deadline = started + duration
        hard_deadline = started + duration * (2 if settle_window is not None else 1)
        if settle_window is not None:
            settle_window.update(start_epoch=started, restart_count=0)
        observed, stable, final_guard = expected, True, True
        while time.time() < min(deadline, hard_deadline):
            time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
            active_bundle = self.wda.active_bundle_id()
            if active_bundle != self.plan["controller"]["application_bundle_id"]:
                final_guard = False
                observed = "foreground_mismatch"
                if settle_window is None:
                    stable = False
                else:
                    # Observe passively until the known app/state returns. No
                    # gesture or popup recovery is attempted during this gap.
                    settle_window["start_epoch"] = None
                    deadline = hard_deadline
                log.write(poll_event, expected=expected, observed=observed,
                          active_bundle_id=active_bundle, observed_epoch=time.time())
                continue
            final_guard = True
            source = self.wda.source()
            observed = self.observed_state(device, source)
            observed_epoch = time.time()
            if settle_window is not None and settle_window["start_epoch"] is None and observed == expected:
                settle_window["start_epoch"] = observed_epoch
                settle_window["restart_count"] += 1
                deadline = min(observed_epoch + duration, hard_deadline)
                log.write("pre_baseline_settle_window_restart", start_epoch=observed_epoch,
                          restart_count=settle_window["restart_count"])
            log.write(poll_event, expected=expected, observed=observed, observed_epoch=observed_epoch)
            if observed != expected:
                stable = False
        complete_window = True
        if settle_window is not None:
            window_start = settle_window["start_epoch"]
            complete_window = window_start is not None and time.time() - window_start >= duration
        return stable and final_guard and observed == expected and complete_window, observed

    def normalize(self, device: dict[str, Any], expected: str) -> bool:
        for cycle in range(4):
            guarded, source = self.ensure_device_view(device, self.log)
            tile = self._tile(device, source) if guarded else None
            observed = self.observed_state(device, source) if guarded else "unknown"
            self.log.write("precondition_state", device=device["id"], expected=expected, observed=observed, cycle=cycle + 1)
            if observed == expected:
                return True
            if observed in device["states"]:
                if device.get("state_view") == "detail_slider":
                    self.issue_detail_slider(device, source, observed, expected, self.log)
                elif tile is not None:
                    point = self.control_point(tile)
                    self.log.write("precondition_command", device=device["id"], point=point)
                    self.wda.tap(point)
                else:
                    time.sleep(3)
                    continue
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
        sample_id = f"{device['id']}-{action_name}-{attempt + int(self.plan.get('sample_index_offset', 0)):03d}"
        sample_log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {
            "sample_id": sample_id,
            "device_id": device["id"],
            "device_name": device["name"],
            "device_ip": device.get("ip"),
            "device_mac": device.get("mac"),
            "control_platform": "apple_home",
            "controller_bundle_id": self.plan["controller"]["application_bundle_id"],
            "action": action_name,
            "expected_initial_state": action["from"],
            "expected_state": action["to"],
            "raw_pcap": str(pcap),
            "command_mode": "host_audio" if self.voice else "ui",
            "valid": False,
        }
        prerequisites_ok, prerequisite_checks = self.ensure_prerequisites(device, sample_log)
        row["prerequisite_checks"] = prerequisite_checks
        if not prerequisites_ok:
            row["reason"] = "prerequisite_state_not_confirmed"
            self.rows.append(row); self.manifest("running", pcap); return
        guarded, source = self.ensure_device_view(device, sample_log)
        state_known = guarded and self.observed_state(device, source) == action["from"]
        if device.get("fresh_precondition_state"):
            sample_log.write("fresh_precondition_state", expected=action["from"],
                             observed=self.observed_state(device, source) if guarded else "unknown")
            if not state_known and not device.get("allow_precondition_normalization", True):
                row["reason"] = "fresh_precondition_mismatch"
                self.rows.append(row); self.manifest("running", pcap); return
        if not state_known and not self.normalize(device, action["from"]):
            row["reason"] = "initial_state_not_confirmed"
            self.rows.append(row); self.manifest("running", pcap); return
        settle_seconds = float(device.get("pre_baseline_settle_seconds", 0))
        if settle_seconds > 0:
            row["pre_baseline_settle_start_epoch"] = time.time()
            row["preparation_observation_start_epoch"] = row["pre_baseline_settle_start_epoch"]
            settle_window: dict[str, Any] = {}
            sample_log.write("pre_baseline_settle_start", seconds=settle_seconds, expected=action["from"])
            stable, observed = self.observe_tail(
                device, action["from"], sample_log,
                duration_seconds=settle_seconds, poll_event="pre_baseline_state_poll",
                settle_window=settle_window,
            )
            if settle_window.get("start_epoch") is not None:
                row["pre_baseline_settle_start_epoch"] = settle_window["start_epoch"]
            row["pre_baseline_restart_count"] = settle_window["restart_count"]
            row["pre_baseline_settle_end_epoch"] = time.time()
            row["pre_baseline_state_stable"] = stable
            sample_log.write("pre_baseline_settle_end", stable=stable, observed=observed)
            if not stable:
                row["reason"] = f"pre_baseline_state_unstable:{observed}"
                self.confirmed_states.pop(device["id"], None)
                self.rows.append(row); self.manifest("running", pcap); return
        row["baseline_start_epoch"] = time.time()
        sample_log.write("baseline_start", seconds=device["baseline_seconds"])
        time.sleep(float(device["baseline_seconds"]))
        guarded, source = self.ensure_device_view(device, sample_log)
        tile = self._tile(device, source) if guarded else None
        if not guarded or self.observed_state(device, source) != action["from"]:
            row.update({"tail_end_epoch": time.time(), "reason": "pre_command_state_or_view_mismatch"})
            self.confirmed_states.pop(device["id"], None)
            self.rows.append(row); self.manifest("running", pcap); return
        if self.voice:
            voice_result = self.voice.play(device, action_name, action.get("to"), sample_log)
            row.update(voice_result)
            row["command_issued_epoch"] = voice_result["voice_audio_start_epoch"]
            sample_log.write("command_issued", action=action_name, mode="host_audio")
        elif device.get("state_view") == "detail_slider":
            gesture = self.issue_detail_slider(device, source, action["from"], action["to"], sample_log)
            row.update(gesture)
            row["command_issued_epoch"] = gesture["gesture_start_epoch"]
            sample_log.write("command_issued", action=action_name, mode="ui", gesture="detail_slider")
        else:
            if tile is None:
                row.update({"tail_end_epoch": time.time(), "reason": "pre_command_control_missing"})
                self.rows.append(row); self.manifest("running", pcap); return
            point = self.control_point(tile)
            row["command_issued_epoch"] = time.time()
            sample_log.write("command_issued", action=action_name, mode="ui", point=point)
            self.wda.tap(point)
        ok, observed, latency = self.wait_state(device, action["to"], float(device["state_timeout_seconds"]), sample_log)
        row.update({"state_confirmed": ok, "observed_state": observed, "latency_seconds": latency, "action_result_epoch": time.time()})
        tail_stable, tail_observed = self.observe_tail(device, action["to"], sample_log)
        valid = ok and tail_stable
        if valid and device.get("verify_state_after_reopen"):
            self.dismiss_restored_detail(self.wda.source(), sample_log)
            reopened, fresh_source = self.ensure_device_view(device, sample_log)
            reopened_state = self.observed_state(device, fresh_source) if reopened else "unknown"
            confirmed = reopened_state == action["to"]
            row.update(reopen_state_confirmed=confirmed, reopen_observed_state=reopened_state)
            sample_log.write("reopen_postcondition", expected=action["to"], observed=reopened_state,
                             confirmed=confirmed)
            valid = confirmed
        reason = "state_confirmed_and_tail_stable" if valid else (f"state_timeout:{observed}" if not ok else f"state_changed_during_tail:{tail_observed}")
        row.update({"tail_end_epoch": time.time(), "tail_state_stable": tail_stable, "tail_observed_state": tail_observed, "valid": valid, "reason": reason})
        sample_log.write("sample_end", valid=valid, reason=reason)
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
        capture_filter = router.get("capture_filter") or f"not host {router['capture_transport_host']}"
        capture = RouterStreamCapture(
            user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None,
            local_pcap=raw_pcap, log=self.log, identity_file=router.get("identity_file"),
            capture_filter=capture_filter,
        )
        apply_resolved_identities(
            self.plan, run_identity_preflight(self.plan, self.root, log=self.log), log=self.log
        )
        self.manifest("starting", raw_pcap)
        try:
            capture.start(); self.manifest("running", raw_pcap)
            target = int(self.plan["target_valid_per_action"])
            for device in self.plan["devices"]:
                consecutive_failures = 0
                failure_limit = int(device.get("max_consecutive_failures", self.plan.get("max_consecutive_failures", 3)))
                while any(self.counts[device["id"]][a["name"]] < target for a in device["actions"]):
                    progress = False
                    for action in device["actions"]:
                        name = action["name"]
                        if self.counts[device["id"]][name] < target and self.attempts[device["id"]][name] < target * 3:
                            before = self.counts[device["id"]][name]
                            self.sample(device, action, raw_pcap); progress = True
                            if self.counts[device["id"]][name] > before:
                                consecutive_failures = 0
                            else:
                                consecutive_failures += 1
                                self.log.write(
                                    "apple_home_failure_streak",
                                    device=device["id"], action=name,
                                    count=consecutive_failures, limit=failure_limit,
                                )
                                if consecutive_failures >= failure_limit:
                                    self.manifest("stopped_consecutive_failures", raw_pcap)
                                    return 3
                    if not progress:
                        break
            complete = all(value >= target for values in self.counts.values() for value in values.values())
            self.manifest("complete" if complete else "incomplete", raw_pcap)
            return 0 if complete else 2
        finally:
            capture.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--target-valid-per-action", type=int)
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
        missing = wanted - {device["id"] for device in plan["devices"]}
        if missing:
            raise DemoError(f"Unknown device ids: {sorted(missing)}")
    return AppleHomeCollector(Path(args.run_root).resolve(), plan).run()


if __name__ == "__main__":
    raise SystemExit(main())
