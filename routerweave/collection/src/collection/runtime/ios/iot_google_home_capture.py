#!/usr/bin/env python3
"""Capture validated Google Home dashboard actions with one continuous router PCAP."""

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
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.ios.iot_identity_preflight import (
    apply_resolved_identities,
    run_identity_preflight,
)
from collection.runtime.ios.iot_capture_network import resolve_capture_addresses
from collection.runtime.ios.iot_light_ui import percentage, select
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA, corroborate_native_foreground


STATE_ALIASES = {
    "on": {"开", "已开", "开启", "已开启"},
    "off": {"关", "已关", "关闭", "已关闭"},
    "locked": {"已上锁", "上锁"},
    "unlocked": {"已解锁", "解锁", "已开锁", "开锁"},
}


def element_center(element: ET.Element, x_fraction: float = 0.5) -> dict[str, int]:
    return {
        "x": int(element.attrib["x"]) + round(int(element.attrib["width"]) * x_fraction),
        "y": int(element.attrib["y"]) + int(element.attrib["height"]) // 2,
    }


def find_device_tile(source: str, device_name: str) -> ET.Element | None:
    root = ET.fromstring(source)
    prefix = f"{device_name},"
    matches = [
        element for element in root.iter()
        if element.attrib.get("name", "").startswith("deviceTileCell_")
        and element.attrib.get("label", "").startswith(prefix)
        and element.attrib.get("visible", "true").lower() == "true"
    ]
    if len(matches) > 1:
        raise DemoError(f"Multiple Google Home tiles match {device_name!r}")
    return matches[0] if matches else None


def normalized_state(element: ET.Element) -> str | None:
    raw = str(element.attrib.get("value") or "").strip()
    for state, aliases in STATE_ALIASES.items():
        if raw in aliases:
            return state
    return None


class GoogleHomeUI:
    def __init__(self, wda: WDA, log: EventLog, bundle_id: str) -> None:
        self.wda, self.log, self.bundle_id = wda, log, bundle_id

    @staticmethod
    def guard_authentication(source: str) -> None:
        if any(e.get("name") == "2FAPinView" and e.get("visible", "").lower() == "true"
               for e in ET.fromstring(source).iter()):
            raise PermissionError("Google Home requires manual device PIN verification")

    def dashboard(self) -> str:
        if self.wda.active_bundle_id() != self.bundle_id:
            self.wda.launch(self.bundle_id)
            time.sleep(2)
        source = self.wda.source()
        self.guard_authentication(source)
        root = ET.fromstring(source)
        optional_prompts = (
            ("设置新的语音助理，获享更自然的对话和控制体验", None, "assistant_setup"),
            ("弹出式窗口，添加地址，获享更好的 Google Home 使用体验",
             "contextualCampaignBottomSheetTitleLabel", "address_setup"),
        )
        visible = [e for e in root.iter() if e.get("visible") == "true"]
        defer = [e for e in visible if e.get("name") == "actionBarSecondaryButton"
                 and e.get("label") == "以后再说" and e.get("enabled") == "true"]
        matched = [(title, kind) for title, name, kind in optional_prompts
                   if len([e for e in visible if e.get("label") == title
                           and (name is None or e.get("name") == name)]) == 1]
        if len(matched) == 1 and len(defer) == 1:
            prompt_title, prompt_kind = matched[0]
            self.log.write(f"google_home_defer_{prompt_kind}")
            self.wda.click_accessibility("actionBarSecondaryButton")
            time.sleep(2)
            source = self.wda.source()
            self.guard_authentication(source)
            if any(e.get("label") == prompt_title and e.get("visible") == "true"
                   for e in ET.fromstring(source).iter()):
                raise DemoError(f"Google Home {prompt_kind} prompt did not close")
        if any(e.get("name") == "contextualCampaignBottomSheetTitleLabel"
               and e.get("visible") == "true" for e in ET.fromstring(source).iter()):
            raise DemoError("Unresolved Google Home campaign prompt blocks the dashboard")
        for _ in range(5):
            if "HomeRootViewController_mainContentView" in source:
                break
            closed = False
            for close_name in ("genericRemoteViewDismissButton", "closeButton", "关闭"):
                if f'name="{close_name}"' not in source and f'label="{close_name}"' not in source:
                    continue
                try:
                    self.wda.click_accessibility(close_name)
                    time.sleep(2)
                    source = self.wda.source()
                    closed = True
                    break
                except Exception as exc:
                    self.log.write("google_home_close_failed", selector=close_name, error=repr(exc))
            if not closed:
                break
        if "HomeRootViewController_mainContentView" not in source:
            raise DemoError("Google Home dashboard is not visible")
        return source

    def visible_tile(self, device: dict[str, Any]) -> tuple[str, ET.Element]:
        source = self.dashboard()
        self.guard_device_list_connection(source)
        visible_favorites = any(e.get("name") == "editFavoritesButtonAccessibilityID" and e.get("visible") == "true"
                                for e in ET.fromstring(source).iter())
        if "deviceTileGridCollectionView" not in source or visible_favorites:
            self.wda.click_accessibility("所有设备")
            time.sleep(2)
            source = self.wda.source()

        self.guard_device_list_connection(source)

        # Google Home preserves the dashboard's previous scroll position.  A
        # missing tile therefore does not imply that it is farther down: the
        # dashboard may already be near the bottom.  Rewind to the top first,
        # then make one deterministic top-to-bottom pass.
        tile = find_device_tile(source, str(device["name"]))
        hidden = [e for e in ET.fromstring(source).iter()
                  if e.get("name", "").startswith("deviceTileCell_")
                  and e.get("label", "").startswith(f"{device['name']},")]
        _, lower = self.scroll_points(source, toward_top=True)
        known_below = len(hidden) == 1 and float(hidden[0].get("y", 0)) >= lower["y"]
        if tile is None and not known_below:
            for attempt in range(8):
                previous_layout = self.tile_layout(source)
                start, end = self.scroll_points(source, toward_top=True)
                self.log.write(
                    "google_home_scroll_reset", device=device["id"],
                    attempt=attempt + 1, start=start, end=end,
                )
                self.wda.drag(start, end, 0.7)
                time.sleep(1)
                source = self.wda.source()
                self.guard_device_list_connection(source)
                tile = find_device_tile(source, str(device["name"]))
                if tile is not None:
                    break
                if previous_layout and self.tile_layout(source) == previous_layout:
                    break

        for attempt in range(12):
            tile = find_device_tile(source, str(device["name"]))
            if tile is not None:
                y = element_center(tile)["y"]
                upper, lower = self.scroll_points(source, toward_top=True)
                if upper["y"] <= y <= lower["y"]:
                    return source, tile
                start, end = self.scroll_points(source, toward_top=y < upper["y"])
            else:
                start, end = self.scroll_points(source, toward_top=False)
            self.log.write("google_home_scroll", device=device["id"], attempt=attempt + 1, start=start, end=end)
            self.wda.drag(start, end, 0.7)
            time.sleep(2)
            source = self.wda.source()
            self.guard_device_list_connection(source)
        raise DemoError(f"Google Home tile is not safely hittable: {device['name']}")

    @staticmethod
    def guard_device_list_connection(source: str) -> None:
        if any(e.get("visible") == "true"
               and e.get("name") == "statusViewTitle"
               and e.get("label") == "Stream removed (Socket closed)"
               for e in ET.fromstring(source).iter()):
            raise DemoError("Google Home device list connection error: Stream removed (Socket closed)")

    @staticmethod
    def tile_layout(source: str) -> tuple:
        return tuple(sorted((e.get("name"), e.get("x"), e.get("y"))
                            for e in ET.fromstring(source).iter()
                            if e.get("name", "").startswith("deviceTileCell_")
                            and e.get("visible") == "true"))

    @staticmethod
    def scroll_points(source: str, *, toward_top: bool) -> tuple[dict[str, int], dict[str, int]]:
        root = ET.fromstring(source)
        viewport = next((e for e in root.iter() if e.tag == "XCUIElementTypeApplication"), root)
        width, height = int(viewport.attrib["width"]), int(viewport.attrib["height"])
        if min(width, height) <= 0:
            raise DemoError("Google Home viewport bounds are invalid")
        upper = {"x": width // 2, "y": round(height * 0.32)}
        lower = {"x": width // 2, "y": round(height * 0.84)}
        return (upper, lower) if toward_top else (lower, upper)

    @staticmethod
    def detail_is_target(source: str, device: dict[str, Any]) -> bool:
        root = ET.fromstring(source)
        visible = [e for e in root.iter() if e.get("visible", "").lower() == "true"]
        dismiss = [e for e in visible if e.get("name") == "genericRemoteViewDismissButton"]
        titles = [e for e in visible if e.tag == "XCUIElementTypeStaticText" and e.get("name") == device["name"]]
        if len(dismiss) != 1 or len(titles) != 1:
            return False
        if "Header" in titles[0].get("traits", ""):
            return True
        try:
            top = int(dismiss[0].attrib["y"])
            bottom = top + int(dismiss[0].attrib["height"])
            title_top = int(titles[0].attrib["y"])
            title_bottom = title_top + int(titles[0].attrib["height"])
            return top <= title_top < title_bottom <= bottom
        except (KeyError, ValueError):
            return False

    def open_detail(self, device: dict[str, Any]) -> str:
        if self.wda.active_bundle_id() != self.bundle_id:
            raise DemoError("Google Home is not foreground")
        source = self.wda.source()
        self.guard_authentication(source)
        if self.detail_is_target(source, device):
            return source
        _, tile = self.visible_tile(device)
        self.wda.long_press(element_center(tile), float(device.get("open_press_seconds", 0.9)))
        time.sleep(float(device.get("open_wait_seconds", 2)))
        source = self.wda.source()
        if not self.detail_is_target(source, device):
            raise DemoError(f"Google Home detail identity not confirmed: {device['name']}")
        return source

    def state(self, device: dict[str, Any]) -> str:
        active = self.wda.active_bundle_id()
        if active != self.bundle_id:
            self.log.write("google_home_foreground_mismatch", device=device["id"],
                           actual_bundle_id=active, expected_bundle_id=self.bundle_id)
            binding = device.get("detail_binding", {})
            if active == "com.apple.springboard" and binding.get("corroborate_springboard_foreground") is True:
                source = corroborate_native_foreground(
                    self.wda, self.bundle_id, "Google Home",
                    lambda xml: self.detail_is_target(xml, device),
                    self.log, device["id"], "google_home_foreground_corroboration",
                )
                if source is not None:
                    self.guard_authentication(source)
                    return self.bound_detail_state(device, source)
            raise DemoError(f"Google Home is not foreground: actual={active!r}")
        if device.get("detail_binding"):
            return self.bound_detail_state(device)
        if device.get("device_type") == "smart_curtain":
            source = self.open_detail(device)
            controls = [e for e in ET.fromstring(source).iter()
                        if e.get("name") == device.get("range_control_name", "continuousSlider")
                        and e.get("visible", "").lower() == "true"]
            if len(controls) != 1:
                raise DemoError("Google Home curtain percentage is not unique")
            value = percentage(controls[0].get("value"))
            matches = [state for state, bounds in device["state_percent_ranges"].items()
                       if value is not None and float(bounds[0]) <= value <= float(bounds[1])]
            return matches[0] if len(matches) == 1 else "unknown"
        if device.get("device_type") == "smart_lock":
            source = self.wda.source()
            self.guard_authentication(source)
            root = ET.fromstring(source)
            metadata_states = [
                normalized_state(element)
                for element in root.iter()
                if element.tag == "XCUIElementTypeStaticText"
                and element.attrib.get("name") == "metadataTitle"
                and element.attrib.get("visible", "").lower() == "true"
            ]
            metadata_states = [state for state in metadata_states if state in {"locked", "unlocked"}]
            if len(metadata_states) == 1 and self.detail_is_target(source, device):
                return metadata_states[0]
        _, tile = self.visible_tile(device)
        state = normalized_state(tile)
        if state is None:
            raise DemoError(f"Unknown state for {device['name']}: {tile.attrib.get('value')!r}")
        return state

    @staticmethod
    def unique_control(source: str, selector: dict[str, Any]) -> ET.Element:
        matches = select(source, selector)
        if len(matches) != 1 or matches[0].get("enabled") != "true":
            raise DemoError(f"Detail control is not unique and enabled: {selector}")
        return matches[0]

    def bound_detail_source(self, device: dict[str, Any]) -> str:
        source = self.wda.source()
        self.guard_authentication(source)
        binding = device["detail_binding"]
        dismiss = binding.get("menu_dismiss_selector")
        if dismiss and select(source, dismiss):
            # A mode sheet hides the native header. Its exact underlying
            # accessory title is still mandatory before dismissing the sheet.
            titles = [e for e in ET.fromstring(source).iter()
                      if e.tag == "XCUIElementTypeStaticText" and e.get("name") == device["name"]]
            if len(titles) != 1:
                raise DemoError("Mode sheet has no unique target accessory identity")
            self.wda.tap(element_center(self.unique_control(source, dismiss)))
            time.sleep(1)
        return self.open_detail(device)

    def bound_detail_state(self, device: dict[str, Any], source: str | None = None) -> str:
        if source is None:
            source = self.bound_detail_source(device)
        binding = device["detail_binding"]
        native = [state for state, selector in binding.get("state_selectors", {}).items()
                  if len(select(source, selector)) == 1]
        return native[0] if len(native) == 1 else "unknown"

    def diagnostic_snapshot(self, device: dict[str, Any], stage: str, *, force: bool = False) -> None:
        if not force and not device.get("detail_binding", {}).get("diagnostic_ui_snapshots", False):
            return
        root = self.log.path.parent / "ui_snapshots"
        stem = f"{device['id']}-{stage}-{time.time_ns()}"
        try:
            root.mkdir(parents=True, exist_ok=True)
            (root / f"{stem}.xml").write_text(self.wda.source(), encoding="utf-8")
            self.wda.screenshot(root / f"{stem}.png")
            self.log.write("google_home_diagnostic_snapshot", stage=stage, source=str(root / f"{stem}.xml"))
        except Exception as exc:
            self.log.write("google_home_diagnostic_snapshot_failed", stage=stage, error=repr(exc))

    def _timed_tap(self, point: dict[str, int]) -> dict[str, Any]:
        started = time.time()
        self.wda.tap(point)
        return {
            "point": point,
            "gesture_start_epoch": started,
            "gesture_complete_epoch": time.time(),
            "gesture_action_kind": "tap",
        }

    def issue(self, device: dict[str, Any], target_state: str | None = None) -> dict[str, Any]:
        if self.wda.active_bundle_id() != self.bundle_id:
            raise DemoError("Google Home is not foreground")
        if device.get("detail_binding"):
            binding = device["detail_binding"]
            if target_state not in binding["controls"]:
                raise DemoError("No explicit detail control for requested state")
            source = self.bound_detail_source(device)
            if binding.get("menu_open_selector"):
                self.wda.tap(element_center(self.unique_control(source, binding["menu_open_selector"])))
                time.sleep(1)
                for attempt in range(8):
                    source = self.wda.source()
                    self.guard_authentication(source)
                    active = self.wda.active_bundle_id()
                    titles = [e for e in ET.fromstring(source).iter()
                              if e.tag == "XCUIElementTypeStaticText" and e.get("name") == device["name"]]
                    sheets = select(source, binding["menu_condition_selector"])
                    targets = select(source, binding["controls"][target_state])
                    ready = (len(sheets) == 1 and len(targets) == 1
                             and targets[0].get("enabled") == "true")
                    self.log.write("google_home_mode_menu_poll", device=device["id"],
                                   attempt=attempt + 1, actual_bundle_id=active,
                                   title_count=len(titles), sheet_count=len(sheets),
                                   target_count=len(targets), ready=ready)
                    if active != self.bundle_id or len(titles) != 1 or len(sheets) > 1 or len(targets) > 1:
                        raise DemoError("Target mode menu is not confirmed")
                    if ready:
                        break
                    if attempt < 7:
                        time.sleep(0.5)
                else:
                    raise DemoError("Target mode menu is not confirmed")
            target = self.unique_control(source, binding["controls"][target_state])
            self.diagnostic_snapshot(device, "before_command")
            timing = self._timed_tap(element_center(target))
            timing["selected_native_control"] = {"type": target.tag,
                "name": target.get("name"), "label": target.get("label")}
            self.log.write("google_home_detail_control", device=device["id"], target_state=target_state, **timing)
            return timing
        if device.get("device_type") == "smart_curtain":
            if target_state not in {"open", "closed"}:
                raise DemoError(f"Curtain command needs an explicit target state: {target_state!r}")
            source = self.open_detail(device)
            name = device["state_controls"][target_state]
            controls = [e for e in ET.fromstring(source).iter()
                        if e.tag == "XCUIElementTypeButton" and e.get("name") == name
                        and e.get("visible", "").lower() == "true" and e.get("enabled") == "true"]
            if len(controls) != 1:
                raise DemoError(f"Expected one enabled curtain control {name!r}, found {len(controls)}")
            timing = self._timed_tap(element_center(controls[0]))
            self.log.write("google_home_curtain_control_tap", device=device["id"],
                           target_state=target_state, control=name, **timing)
            return timing
        if device.get("device_type") == "smart_lock":
            if target_state not in {"locked", "unlocked"}:
                raise DemoError(f"Smart-lock command needs an explicit target state: {target_state!r}")
            control_names = {"解锁", "开锁"} if target_state == "unlocked" else {"锁定", "上锁"}
            source = self.wda.source()
            self.guard_authentication(source)
            root = ET.fromstring(source)
            controls = [
                element for element in root.iter()
                if element.tag == "XCUIElementTypeButton"
                and element.attrib.get("visible", "").lower() == "true"
                and element.attrib.get("name") in control_names
            ]
            if len(controls) == 1 and self.detail_is_target(source, device):
                point = element_center(controls[0])
                control_name = str(controls[0].attrib.get("name") or "")
                timing = self._timed_tap(point)
                self.log.write(
                    "google_home_lock_control_tap", device=device["id"],
                    target_state=target_state, control=control_name, point=point,
                    entry="existing_detail",
                )
                return timing

            _, tile = self.visible_tile(device)
            point = element_center(tile, float(device.get("tap_x_fraction", 0.45)))
            self.wda.tap(point)
            self.log.write("google_home_tile_tap", device=device["id"], point=point)
            started = time.time()
            deadline = started + float(device.get("control_wait_seconds", 16))
            controls = []
            retried_tile_tap = False
            while time.time() < deadline:
                time.sleep(float(device.get("control_poll_seconds", 2)))
                source = self.wda.source()
                root = ET.fromstring(source)
                controls = [
                    element for element in root.iter()
                    if element.tag == "XCUIElementTypeButton"
                    and element.attrib.get("visible", "").lower() == "true"
                    and element.attrib.get("name") in control_names
                ]
                if len(controls) == 1 and self.detail_is_target(source, device):
                    break
                # The first dashboard tap can occasionally be ignored while
                # Google Home refreshes the lock tile. Retry only after the
                # source proves that the exact dashboard tile is still shown.
                if (
                    not retried_tile_tap
                    and time.time() - started >= 4
                    and "HomeRootViewController_mainContentView" in source
                ):
                    dashboard_tile = find_device_tile(source, str(device["name"]))
                    if dashboard_tile is not None:
                        retry_point = element_center(
                            dashboard_tile, float(device.get("tap_x_fraction", 0.45))
                        )
                        self.wda.tap(retry_point)
                        self.log.write(
                            "google_home_lock_tile_tap_retried",
                            device=device["id"], point=retry_point,
                        )
                        retried_tile_tap = True
            if len(controls) != 1 or not self.detail_is_target(source, device):
                raise DemoError(
                    f"Expected one visible control in {sorted(control_names)!r} for {device['id']}, "
                    f"found {len(controls)}"
                )
            point = element_center(controls[0])
            control_name = str(controls[0].attrib.get("name") or "")
            timing = self._timed_tap(point)
            self.log.write(
                "google_home_lock_control_tap", device=device["id"],
                target_state=target_state, control=control_name, point=point,
                entry="opened_detail",
            )
            return timing

        _, tile = self.visible_tile(device)
        point = element_center(tile, float(device.get("tap_x_fraction", 0.45)))
        timing = self._timed_tap(point)
        self.log.write("google_home_tile_tap", device=device["id"], point=point)
        return timing

    def wait_state(self, device: dict[str, Any], expected: str, timeout: float, log: EventLog) -> str:
        deadline, last = time.time() + timeout, None
        while time.time() < deadline:
            time.sleep(float(device.get("poll_seconds", 5)))
            try:
                last = self.state(device)
                log.write("state_poll", state=last, expected=expected)
                if last == expected:
                    return last
            except PermissionError:
                raise
            except Exception as exc:
                log.write("state_poll_failed", error=repr(exc))
        raise DemoError(f"State confirmation timed out for {device['id']}: expected={expected}, last={last}")


class Collector:
    def __init__(self, root: Path, plan: dict[str, Any]) -> None:
        self.root, self.plan = root, plan
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = EventLog(root / "batch_events.jsonl")
        self.wda = WDA(plan["controller"]["wda_url"], self.log)
        self.ui = GoogleHomeUI(self.wda, self.log, plan["controller"]["application_bundle_id"])
        self.rows: list[dict[str, Any]] = []
        if plan.get("acceptance_mode", "state_confirmed") not in {"command_traffic", "state_confirmed"}:
            raise DemoError("Unknown IoT sample acceptance mode")
        self.command_traffic = plan.get("acceptance_mode") == "command_traffic"
        from collection.runtime.ios.iot_device_traffic import supports_command_traffic
        if self.command_traffic and any(not supports_command_traffic(d) for d in plan["devices"]):
            raise DemoError("Command-traffic capture requires explicit supported native controls")
        self.cycle_start = int(plan.get("cycle_start", 1))
        if self.cycle_start <= 0:
            raise DemoError("cycle_start must be positive")
        self.counts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        self.attempts = {d["id"]: {a["name"]: 0 for a in d["actions"]} for d in plan["devices"]}
        write_json(self.root / "effective_plan.json", plan)

    def manifest(self, status: str, pcap: Path) -> None:
        write_json(self.root / "batch_manifest.json", {
            "experiment": self.plan["experiment"], "status": status, "updated_at": now_iso(),
            "control_platform": "google_home", "target_valid_per_action": self.plan["target_valid_per_action"],
            "valid_counts": {} if self.command_traffic else self.counts,
            "command_counts": self.counts if self.command_traffic else {},
            "acceptance_mode": "command_traffic" if self.command_traffic else "state_confirmed",
            "attempt_counts": self.attempts, "raw_pcap": str(pcap),
            "samples": len(self.rows), "capture_filter": self.plan["router"].get("capture_filter"),
            "cycle_start": self.cycle_start,
            "cycle_end": max((int(row["global_cycle"]) for row in self.rows), default=self.cycle_start - 1),
        })
        write_json(self.root / "sample_windows.json", self.rows)

    def set_state(self, device: dict[str, Any], expected: str, log: EventLog) -> None:
        current = self.ui.state(device)
        if current == expected:
            return
        if device.get("allow_precondition_normalization") is False:
            raise DemoError(f"Precondition mismatch without normalization: expected={expected}, observed={current}")
        self.ui.issue(device, expected)
        self.ui.wait_state(device, expected, float(device["state_timeout_seconds"]), log)

    def sample(self, device: dict[str, Any], action: dict[str, Any], cycle: int, pcap: Path) -> None:
        if self.command_traffic:
            self.sample_command_traffic(device, action, cycle, pcap)
            return
        name = action["name"]
        self.attempts[device["id"]][name] += 1
        attempt = self.attempts[device["id"]][name]
        sample_id = f"{device['id']}-{name}-{attempt:03d}"
        log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row: dict[str, Any] = {
            "sample_id": sample_id, "cycle": cycle, "global_cycle": cycle,
            "device_id": device["id"], "device_name": device["name"], "device_ip": device.get("ip"),
            "device_mac": device.get("mac"), "control_platform": "google_home", "action": name,
            "source_value": action["from"], "target_value": action["to"], "raw_pcap": str(pcap), "valid": False,
        }
        try:
            self.set_state(device, action["from"], log)
            row["baseline_start_epoch"] = time.time()
            log.write("baseline_start", seconds=device["baseline_seconds"])
            time.sleep(float(device["baseline_seconds"]))
            if self.ui.state(device) != action["from"]:
                raise DemoError("Pre-command state changed")
            row["operation_started_epoch"] = time.time()
            timing = self.ui.issue(device, action["to"])
            row.update({
                **{key: timing[key] for key in (
                    "gesture_start_epoch", "gesture_complete_epoch", "gesture_action_kind"
                )},
                "command_issued_epoch": timing["gesture_start_epoch"],
                "command_attempts": [{"attempt": 1, **timing}],
                "command_timing_quality": "observed_controller_request",
                "command_timing_source": "wda_request_boundary",
            })
            log.write(
                "command_issued", action=name, target=action["to"],
                command_issued_epoch=row["command_issued_epoch"],
            )
            confirmed = self.ui.wait_state(device, action["to"], float(device["state_timeout_seconds"]), log)
            row["action_result_epoch"] = time.time()
            row["confirmed_state"] = {"state": confirmed}
            deadline, stable, last = time.time() + float(device["tail_seconds"]), True, confirmed
            while time.time() < deadline:
                time.sleep(min(float(device["poll_seconds"]), max(0.0, deadline - time.time())))
                try:
                    last = self.ui.state(device)
                    if last != action["to"]:
                        stable = False
                    log.write("tail_state_poll", state=last, stable=stable)
                except Exception as exc:
                    stable = False
                    log.write("tail_state_poll_failed", error=repr(exc))
                    self.ui.diagnostic_snapshot(device, "tail_poll_failed", force=True)
            row["tail_end_epoch"] = time.time()
            reopen_confirmed = True
            if stable and device.get("verify_state_after_reopen"):
                self.ui.dashboard()
                if device.get("device_type") == "smart_lock":
                    _, tile = self.ui.visible_tile(device)
                    self.wda.tap(element_center(tile, float(device.get("tap_x_fraction", 0.45))))
                    time.sleep(float(device.get("open_wait_seconds", 2)))
                reopened = self.ui.state(device)
                reopen_confirmed = reopened == action["to"]
                row.update({"reopen_state": {"state": reopened}, "reopen_state_confirmed": reopen_confirmed})
                log.write("reopen_postcondition", state=reopened, confirmed=reopen_confirmed)
            row.update({"tail_state": {"state": last},
                        "tail_state_stable": stable, "valid": stable and reopen_confirmed,
                        "reason": "state_confirmed_tail_stable_and_reopen_confirmed" if stable and reopen_confirmed else "state_changed_or_unreadable_during_tail_or_reopen"})
        except Exception as exc:
            row.setdefault("tail_end_epoch", time.time())
            row["reason"] = f"sample_error:{exc}"
            log.write("sample_failed", error=repr(exc))
            self.ui.diagnostic_snapshot(device, "sample_failed", force=True)
        self.rows.append(row)
        if row["valid"]:
            self.counts[device["id"]][name] += 1
        self.manifest("running", pcap)

    def sample_command_traffic(self, device: dict[str, Any], action: dict[str, Any], cycle: int, pcap: Path) -> None:
        """Capture one explicit control once; retain state uncertainty separately."""
        name = action["name"]
        self.attempts[device["id"]][name] += 1
        sample_id = f"{device['id']}-{name}-{self.attempts[device['id']][name]:03d}"
        log = EventLog(self.root / "events" / f"{sample_id}.jsonl")
        row = {"sample_id": sample_id, "cycle": cycle, "global_cycle": cycle,
               "device_id": device["id"], "device_name": device["name"],
               "device_ip": device["ip"], "device_mac": device["mac"],
               "control_platform": "google_home", "action": name,
               "source_value": action["from"], "target_value": action["to"],
               "raw_pcap": str(pcap), "valid": False, "state_confirmed": False,
               "command_capture_complete": False}
        try:
            source = self.ui.open_detail(device)
            option_selection = device.get("command_evidence") == "native_option_selection"
            if option_selection:
                if self.ui.state(device) != "on":
                    raise DemoError("Fan option capture requires native power on")
                # Source is an explicitly issued option, not an observed fan grade.
                row["source_option_selection"] = self.ui.issue(device, action["from"])
                time.sleep(1)
                current = self.wda.source()
                self.ui.guard_authentication(current)
                row["source_selection_sheet_dismissed"] = not select(current, device["detail_binding"]["menu_condition_selector"])
                if not row["source_selection_sheet_dismissed"] or not self.ui.detail_is_target(current, device):
                    raise DemoError("Source option selection did not return to exact accessory page")
                row["source_state_confirmed"] = False
            row["baseline_start_epoch"] = time.time()
            row["observed_before"] = self.ui.state(device)
            log.write("baseline_start", seconds=max(5, float(device["baseline_seconds"])))
            time.sleep(max(5, float(device["baseline_seconds"])))
            timing = self.ui.issue(device, action["to"])
            row.update(timing, command_issued_epoch=timing["gesture_start_epoch"],
                       action_result_epoch=timing["gesture_complete_epoch"],
                       command_timing_source="wda_request_boundary",
                       command_timing_quality="observed_controller_request",
                       command_attempts=[{"attempt": 1, **timing}])
            if option_selection:
                time.sleep(1)
                current = self.wda.source()
                self.ui.guard_authentication(current)
                binding = device["detail_binding"]
                row["selection_sheet_dismissed"] = not select(current, binding["menu_condition_selector"])
                if not row["selection_sheet_dismissed"] or not self.ui.detail_is_target(current, device):
                    raise DemoError("Native option selection did not return to exact accessory page")
            log.write("command_issued", action=name, **timing)
            deadline = time.time() + max(30, float(device["tail_seconds"]))
            while time.time() < deadline:
                time.sleep(min(float(device["poll_seconds"]), max(0, deadline-time.time())))
                current = self.wda.source()
                self.ui.guard_authentication(current)
                if not self.ui.detail_is_target(current, device):
                    raise DemoError("Target accessory page changed during command capture")
                if option_selection and self.ui.state(device) != "on":
                    raise DemoError("Fan command page no longer shows power on")
                log.write("traffic_tail_observation", state=self.ui.state(device))
            row.update(tail_end_epoch=time.time(), command_capture_complete=True,
                       observed_after=self.ui.state(device), reason="command_captured_state_unconfirmed")
            self.counts[device["id"]][name] += 1
        except Exception as exc:
            row.update(tail_end_epoch=time.time(), reason=f"sample_error:{exc}",
                       authentication_required=isinstance(exc, PermissionError))
            log.write("sample_failed", error=repr(exc))
            self.ui.diagnostic_snapshot(device, "command_sample_failed", force=True)
        self.rows.append(row)
        self.manifest("running", pcap)

    def run(self) -> int:
        pcap = self.root / "raw" / "batch.pcap"
        router = self.plan["router"]
        resolve_capture_addresses(self.plan, self.root, log=self.log)
        capture = RouterStreamCapture(
            user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None,
            local_pcap=pcap, log=self.log, identity_file=router.get("identity_file"),
            capture_filter=router.get("capture_filter") or f"not host {router['capture_transport_host']}",
        )
        target = int(self.plan["target_valid_per_action"])
        apply_resolved_identities(
            self.plan, run_identity_preflight(self.plan, self.root, log=self.log), log=self.log
        )
        write_json(self.root / "effective_plan.json", self.plan)
        self.manifest("starting", pcap)
        try:
            capture.start()
            self.manifest("running", pcap)
            for device in self.plan["devices"]:
                cycle, failures = self.cycle_start - 1, 0
                while any(self.counts[device["id"]][a["name"]] < target for a in device["actions"]):
                    cycle += 1
                    for action in device["actions"]:
                        name = action["name"]
                        if self.counts[device["id"]][name] >= target:
                            continue
                        before = self.counts[device["id"]][name]
                        self.sample(device, action, cycle, pcap)
                        failures = 0 if self.counts[device["id"]][name] > before else failures + 1
                        if failures >= int(device.get("max_consecutive_failures", 2)):
                            self.manifest("stopped_consecutive_failures", pcap)
                            return 3
            self.manifest("command_capture_complete" if self.command_traffic else "complete", pcap)
            return 0
        finally:
            capture.stop()
            if self.command_traffic:
                from collection.runtime.ios.iot_device_traffic import review_command_traffic
                write_json(self.root / "command_traffic_review.json", review_command_traffic(self.root))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--target-valid-per-action", type=int)
    parser.add_argument("--cycle-start", type=int)
    parser.add_argument("--identity-preflight", choices=("enforce", "advisory", "off"))
    args = parser.parse_args()
    from .plan_config import load_plan
    plan = load_plan(args.plan)
    if args.identity_preflight:
        plan["identity_preflight"] = args.identity_preflight
    if args.target_valid_per_action is not None:
        plan["target_valid_per_action"] = args.target_valid_per_action
    if args.cycle_start is not None:
        plan["cycle_start"] = args.cycle_start
    if plan.get("control_platform") != "google_home":
        raise DemoError("Expected control_platform=google_home")
    return Collector(Path(args.run_root).resolve(), plan).run()


if __name__ == "__main__":
    raise SystemExit(main())
