"""Read a device's native control state from a WDA screen whose identity was verified."""

from collections.abc import Callable
import math
import time
import xml.etree.ElementTree as ET


def read_native_state(source: str, device: dict) -> str:
    try:
        root = ET.fromstring(source)
    except ET.ParseError:
        return "unknown"
    elements = [e for e in root.iter() if e.get("visible", "").lower() == "true"]
    menu = device.get("mode_menu")
    if menu:
        selected = [e for e in elements if e.get("name") == menu["option_name"]
                    and e.get("value") == menu["checked_value"]]
        if len(selected) != 1:
            return "unknown"
        matches = {state for state, label in menu["state_labels"].items()
                   if label == selected[0].get("label")}
    elif device.get("range_control_name"):
        controls = [e for e in elements if e.get("name") == device["range_control_name"]]
        if len(controls) != 1:
            return "unknown"
        try:
            value = float(controls[0].get("value", "").strip().removesuffix("%"))
        except ValueError:
            return "unknown"
        matches = {state for state, (low, high) in device["state_percent_ranges"].items()
                   if float(low) <= value <= float(high)}
    else:
        name = device.get("state_element_name")
        if name:
            elements = [e for e in elements if e.get("name") == name]
            if len(elements) != 1:
                return "unknown"
        values = {e.get(field) for e in elements for field in ("name", "label", "value")}
        matches = set()
        for state, labels in device["states"].items():
            for label in labels if isinstance(labels, list) else [labels]:
                text = f"{device['name']}, {label}" if device.get("state_match") == "name_label" else str(label)
                if text in values:
                    matches.add(state)
    return matches.pop() if len(matches) == 1 else "unknown"


def observe_transition(read_guarded_state: Callable[[], str], *, target: str,
                       timeout: float, tail: float, poll: float) -> dict:
    """Poll the bound device view after a command, then observe its target-state tail."""
    if not target or target == "unknown":
        raise ValueError("expected a concrete target state")
    if not all(math.isfinite(value) and value > 0 for value in (timeout, tail, poll)):
        raise ValueError("timeout, tail and poll must be positive finite seconds")
    deadline = time.monotonic() + timeout
    while True:
        observed = read_guarded_state()
        now = time.monotonic()
        if now <= deadline and observed == target:
            break
        if now >= deadline:
            return {"state_confirmed": False, "observed_state": observed}
        time.sleep(min(poll, deadline - now))
    result_epoch = time.time()
    tail_end = now + tail
    stable = True
    while True:
        time.sleep(min(poll, max(0, tail_end - time.monotonic())))
        observed = read_guarded_state()
        stable = stable and observed == target
        if time.monotonic() >= tail_end:
            return {"state_confirmed": True, "observed_state": target,
                    "action_result_epoch": result_epoch, "tail_end_epoch": time.time(),
                    "tail_state_stable": stable, "tail_observed_state": observed}
