#!/usr/bin/env python3
"""Open an IoT light control page and preserve WDA evidence without changing state."""

from __future__ import annotations

import argparse
import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError
from collection.runtime.artifacts import now_iso, write_json
from collection.runtime.mobile_control.wda import WdaDeviceController as WDA


PLATFORMS = {
    "apple_home": {"bundle_id": "com.apple.Home", "target_name": "meross"},
    "alexa": {"bundle_id": "com.amazon.echo", "target_name": "meross"},
    "google_home": {"bundle_id": "com.google.Chromecast", "target_name": "meross"},
}


def visible(element: ET.Element) -> bool:
    return element.attrib.get("visible", "").lower() == "true"


def center(element: ET.Element, horizontal_fraction: float = 0.5) -> dict[str, int]:
    return {
        "x": int(element.attrib["x"]) + int(int(element.attrib["width"]) * horizontal_fraction),
        "y": int(element.attrib["y"]) + int(element.attrib["height"]) // 2,
    }


def target_is_hittable(platform: str, element: ET.Element) -> bool:
    point = center(element)
    if platform == "alexa":
        # Alexa's device list remains visible underneath its fixed header and
        # bottom navigation/overlays.  XCUITest can therefore report a tile as
        # visible even though a tap on its lower half is intercepted.  Keep the
        # tile centre inside the proven middle section of the scroll view.
        return 205 <= point["y"] <= 480
    return 80 <= point["y"] <= 630


def scroll_toward_target(
    platform: str, target: ET.Element | None, wda: WDA,
    *, source: str | None = None, target_name: str | None = None,
) -> None:
    if platform == "alexa" and source is not None:
        root = ET.fromstring(source)
        if target is None and target_name:
            hints = [e for e in root.iter()
                     if e.tag == "XCUIElementTypeButton"
                     and e.get("name") == f"ListSwipeTouchable_{target_name}"]
            if len(hints) > 1:
                raise DemoError("Alexa scroll target identity is ambiguous")
            target = hints[0] if hints else None
        lists = [e for e in root.iter()
                 if e.tag == "XCUIElementTypeScrollView" and visible(e)
                 and any(child.get("name", "").startswith("ListSwipeTouchable_")
                         for child in e.iter())]
        if len(lists) != 1:
            raise DemoError("Alexa device-list scroll bounds are not unique")
        try:
            x, y, width, height = (int(lists[0].attrib[k])
                                  for k in ("x", "y", "width", "height"))
        except (KeyError, ValueError) as exc:
            raise DemoError("Alexa device-list scroll bounds are invalid") from exc
        if min(x, y) < 0 or min(width, height) <= 0:
            raise DemoError("Alexa device-list scroll bounds are invalid")
        upper = {"x": x + width // 2, "y": y + int(height * 0.17)}
        lower = {"x": x + width // 2, "y": y + int(height * 0.72)}
        # A hidden exact list row is a direction hint, never a tappable target.
        toward_top = target is not None and center(target)["y"] < upper["y"]
        wda.drag(upper if toward_top else lower, lower if toward_top else upper, 0.7)
        return
    if platform == "alexa" and target is not None and center(target)["y"] < 205:
        wda.drag({"x": 188, "y": 230}, {"x": 188, "y": 520}, 0.7)
        return
    start_y = 520 if platform == "alexa" else 580
    wda.drag({"x": 188, "y": start_y}, {"x": 188, "y": 230}, 0.7)


def summarize(source: str) -> list[dict[str, Any]]:
    root = ET.fromstring(source)
    rows: list[dict[str, Any]] = []
    interesting_types = {
        "XCUIElementTypeButton",
        "XCUIElementTypeCell",
        "XCUIElementTypeSlider",
        "XCUIElementTypeAdjustable",
        "XCUIElementTypeStaticText",
    }
    for element in root.iter():
        if not visible(element) or element.tag not in interesting_types:
            continue
        rows.append(
            {
                "type": element.tag,
                "name": element.attrib.get("name"),
                "label": element.attrib.get("label"),
                "value": element.attrib.get("value"),
                "x": element.attrib.get("x"),
                "y": element.attrib.get("y"),
                "width": element.attrib.get("width"),
                "height": element.attrib.get("height"),
            }
        )
    return rows


def find_target(platform: str, source: str, target_name: str) -> ET.Element | None:
    root = ET.fromstring(source)
    target_lower = target_name.lower()
    preferred = "XCUIElementTypeCell" if platform == "apple_home" else "XCUIElementTypeButton"
    candidates: list[ET.Element] = []
    for element in root.iter():
        if platform == "apple_home" and element.tag == "XCUIElementTypeCell":
            label = str(element.attrib.get("label") or "")
            if visible(element) and (label == target_name or label.startswith(f"{target_name}, ")):
                return element
        if platform == "alexa" and element.tag == "XCUIElementTypeButton":
            if visible(element) and element.attrib.get("name") == f"ListSwipeTouchable_{target_name}":
                return element
        text = " ".join(
            str(element.attrib.get(key) or "") for key in ("name", "label", "value")
        ).lower()
        if visible(element) and target_lower in text:
            candidates.append(element)
    if platform == "alexa":
        return None
    for element in candidates:
        if element.tag == preferred:
            if platform == "alexa" and not element.attrib.get("name", "").startswith("ListSwipeTouchable_"):
                continue
            return element
    return candidates[0] if candidates else None


def visible_exact(source: str, name: str) -> ET.Element | None:
    for element in ET.fromstring(source).iter():
        if visible(element) and (element.attrib.get("name") == name or element.attrib.get("label") == name):
            return element
    return None


def visible_text_exact_ci(source: str, text: str) -> ET.Element | None:
    expected = text.casefold()
    for element in ET.fromstring(source).iter():
        if not visible(element):
            continue
        if any(str(element.attrib.get(key) or "").casefold() == expected for key in ("name", "label", "value")):
            return element
    return None


def dismiss_restored_detail(platform: str, source: str, wda: WDA, log: EventLog) -> str:
    if platform == "apple_home":
        sheets = [
            element for element in ET.fromstring(source).iter()
            if element.tag == "XCUIElementTypeScrollView"
            and element.attrib.get("name") == "AccessoryControl.SheetView"
            and visible(element)
        ]
        if len(sheets) > 1:
            raise DemoError("Apple Home restored accessory sheet is ambiguous")
        if len(sheets) == 1 and visible_exact(source, "关闭") is None:
            sheet = sheets[0]
            x, y = int(sheet.attrib["x"]), int(sheet.attrib["y"])
            width, height = int(sheet.attrib["width"]), int(sheet.attrib["height"])
            if width <= 0 or height <= 0:
                raise DemoError("Apple Home accessory sheet bounds are invalid")
            edge_x = x + max(1, int(width * 0.08))
            start = {"x": edge_x, "y": y + int(height * 0.15)}
            end = {"x": edge_x, "y": y + int(height * 0.90)}
            log.write("dismiss_restored_accessory_sheet", platform=platform,
                      point_start=start, point_end=end)
            wda.drag(start, end, 0.9)
            time.sleep(2)
            source = wda.source()
            if any(
                element.tag == "XCUIElementTypeScrollView"
                and element.attrib.get("name") == "AccessoryControl.SheetView"
                and visible(element)
                for element in ET.fromstring(source).iter()
            ):
                raise DemoError("Apple Home accessory sheet did not close")
            return source
    if platform == "alexa" and visible_exact(source, "mosaic.bottom-sheet.modal_dismiss_overlay") is not None:
        log.write("dismiss_restored_bottom_sheet", platform=platform)
        wda.click_accessibility("mosaic.bottom-sheet.modal_dismiss_overlay")
        time.sleep(2)
        return wda.source()
    if platform == "alexa" and "DCPV2::ControlPage" in source:
        log.write("dismiss_restored_detail", platform=platform, point={"x": 30, "y": 42})
        wda.tap({"x": 30, "y": 42})
        time.sleep(3)
        return wda.source()
    if (
        platform == "apple_home"
        and visible_exact(source, "Home.Tab.家庭") is None
        and visible_exact(source, "视频") is not None
    ):
        point = center(visible_exact(source, "视频"))
        log.write("reveal_apple_home_camera_controls", platform=platform, point=point)
        wda.tap(point)
        time.sleep(1)
        source = wda.source()
    apple_close = visible_exact(source, "Done")
    if apple_close is None:
        apple_close = visible_exact(source, "关闭")
    if platform == "apple_home" and apple_close is not None and visible_exact(source, "Home.Tab.家庭") is None:
        close = visible_exact(source, "关闭")
        if close is None:
            raise DemoError("Apple Home detail is open but its close button is not uniquely discoverable")
        point = center(close)
        log.write("dismiss_restored_detail", platform=platform, point=point)
        wda.tap(point)
        time.sleep(2)
        return wda.source()
    return source


def ensure_dashboard(platform: str, source: str, wda: WDA, log: EventLog) -> str:
    if platform != "alexa":
        return source
    for attempt in range(3):
        if (
            visible_exact(source, "TestID-Collapse-Button") is not None
            and visible_exact(source, "DevicePageSearchButton") is not None
        ):
            filter_button = visible_exact(source, "DevicePageDeviceTypeFilterButton")
            if filter_button is not None and center(filter_button)["y"] > 250:
                log.write("collapse_alexa_groups_header")
                wda.drag({"x": 188, "y": 520}, {"x": 188, "y": 300}, 0.7)
                time.sleep(2)
                source = wda.source()
            return source
        chat_close = visible_exact(source, "alexa.chat.dismiss")
        if chat_close is None:
            chat_close = visible_exact(source, "dismiss")
        chat_input = visible_exact(source, "Message Alexa")
        if chat_input is None:
            chat_input = visible_exact(source, "alexa.chat.messageInput")
        if chat_close is not None and chat_input is not None:
            point = center(chat_close)
            log.write("dismiss_alexa_chat", attempt=attempt + 1, point=point)
            wda.tap(point)
            time.sleep(2)
            source = wda.source()
            continue
        back = visible_exact(source, "header-back-button")
        if back is not None:
            point = center(back)
            log.write("navigate_alexa_back", attempt=attempt + 1, point=point)
            wda.tap(point)
            time.sleep(3)
            source = wda.source()
            continue
        devices = visible_exact(source, "Devices")
        if devices is not None:
            point = center(devices)
            log.write("open_alexa_devices", attempt=attempt + 1, point=point)
            wda.tap(point)
            time.sleep(3)
            source = wda.source()
            continue
        break
    raise DemoError("Alexa Devices page could not be confirmed")


def detail_is_target(platform: str, source: str, target_name: str) -> bool:
    target = visible_text_exact_ci(source, target_name)
    if target is None:
        return False
    if platform == "apple_home":
        root = ET.fromstring(source)
        current_sheet = any(
            element.tag == "XCUIElementTypeScrollView"
            and element.get("name") == "AccessoryControl.SheetView"
            and visible(element)
            for element in root.iter()
        )
        current_slider = any(
            element.tag == "XCUIElementTypeOther"
            and element.get("name", "").startswith("AccessoryControl.service-")
            and element.get("name", "").endswith(".incremental.LargeSlider")
            and visible(element)
            for element in root.iter()
        )
        return (
            visible_exact(source, "QuickControlSwitch") is not None
            or visible_exact(source, "QuickControlSlider") is not None
            or (current_sheet and current_slider)
        )
    if platform == "google_home":
        if visible_exact(source, "lightControllerView") is not None:
            return True
        from collection.runtime.ios.iot_google_home_capture import GoogleHomeUI
        sliders = [e for e in ET.fromstring(source).iter()
                   if e.get("name") == "verticalPillSliderContainer" and visible(e)]
        return len(sliders) == 1 and GoogleHomeUI.detail_is_target(source, {"name": target_name})
    return "DCPV2::ControlPage" in source


def run(platform: str, root: Path, wda_url: str, target_name: str) -> int:
    config = PLATFORMS[platform]
    root.mkdir(parents=True, exist_ok=True)
    log = EventLog(root / "events.jsonl")
    wda = WDA(wda_url, log)
    bundle_id = config["bundle_id"]
    if platform == "alexa":
        wda.terminate(bundle_id)
        time.sleep(2)
    wda.launch(bundle_id)
    time.sleep(3)
    source = dismiss_restored_detail(platform, wda.source(), wda, log)
    source = ensure_dashboard(platform, source, wda, log)
    (root / "dashboard.xml").write_text(source, encoding="utf-8")
    wda.screenshot(root / "dashboard.png")
    target = find_target(platform, source, target_name)
    for attempt in range(4):
        if target is not None and target_is_hittable(platform, target):
            break
        log.write("target_not_visible", attempt=attempt + 1, target_name=target_name)
        scroll_toward_target(platform, target, wda, source=source, target_name=target_name)
        time.sleep(2)
        source = wda.source()
        target = find_target(platform, source, target_name)
    if target is None or not target_is_hittable(platform, target):
        status = "target_not_found" if target is None else "target_not_hittable"
        write_json(root / "probe.json", {"status": status, "platform": platform, "target_name": target_name})
        return 2
    point = center(target, 0.75 if platform == "apple_home" else 0.5)
    log.write("open_light_detail", platform=platform, target_name=target_name, point=point)
    wda.tap(point)
    time.sleep(3)
    detail = wda.source()
    (root / "detail.xml").write_text(detail, encoding="utf-8")
    wda.screenshot(root / "detail.png")
    confirmed = detail_is_target(platform, detail, target_name)
    write_json(
        root / "probe.json",
        {
            "status": "complete" if confirmed else "detail_not_confirmed",
            "created_at": now_iso(),
            "platform": platform,
            "bundle_id": bundle_id,
            "target_name": target_name,
            "open_point": point,
            "dashboard_controls": summarize(source),
            "detail_controls": summarize(detail),
        },
    )
    return 0 if confirmed else 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--target-name")
    parser.add_argument("--wda-url", default="http://127.0.0.1:8100")
    args = parser.parse_args()
    target_name = args.target_name or PLATFORMS[args.platform]["target_name"]
    return run(args.platform, Path(args.out).resolve(), args.wda_url, target_name)


if __name__ == "__main__":
    raise SystemExit(main())
