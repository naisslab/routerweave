"""UI-source helpers for deterministic Apple Home and Alexa light control."""

from __future__ import annotations

import re
import random
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

from collection.runtime.errors import DemoError


@dataclass(frozen=True)
class LightState:
    power: str = "unknown"
    brightness: int | None = None
    color: str | None = None


@dataclass(frozen=True)
class BrightnessTransition:
    source: int
    target: int


@dataclass(frozen=True)
class ColorTransition:
    source: str
    target: str


@dataclass(frozen=True)
class LightActionIntent:
    action: str
    required_power: str
    source_value: str | int | None
    target_value: str | int | None


def is_visible(element: ET.Element) -> bool:
    return element.attrib.get("visible", "").lower() == "true"


def select(source: str, spec: dict[str, Any]) -> list[ET.Element]:
    """Return UI elements matching a small, serializable selector language."""
    root = ET.fromstring(source)
    rows: list[ET.Element] = []
    for element in root.iter():
        if spec.get("visible", True) and not is_visible(element):
            continue
        if spec.get("type") and element.tag != spec["type"]:
            continue
        if spec.get("name") is not None and element.attrib.get("name") != str(spec["name"]):
            continue
        if spec.get("label") is not None and element.attrib.get("label") != str(spec["label"]):
            continue
        if spec.get("value") is not None and element.attrib.get("value") != str(spec["value"]):
            continue
        if spec.get("index") is not None and element.attrib.get("index") != str(spec["index"]):
            continue
        if spec.get("name_prefix") and not element.attrib.get("name", "").startswith(str(spec["name_prefix"])):
            continue
        if spec.get("label_prefix") and not element.attrib.get("label", "").startswith(str(spec["label_prefix"])):
            continue
        combined = " ".join(str(element.attrib.get(key) or "") for key in ("name", "label", "value"))
        if spec.get("text_contains") and str(spec["text_contains"]).lower() not in combined.lower():
            continue
        if spec.get("traits_contains") and str(spec["traits_contains"]).lower() not in element.attrib.get("traits", "").lower():
            continue
        rows.append(element)
    return rows


def select_one(source: str, spec: dict[str, Any], description: str) -> ET.Element:
    rows = select(source, spec)
    if len(rows) != 1:
        raise DemoError(f"Expected one {description}, found {len(rows)}")
    return rows[0]


def center(element: ET.Element) -> dict[str, int]:
    return {
        "x": int(element.attrib["x"]) + int(element.attrib["width"]) // 2,
        "y": int(element.attrib["y"]) + int(element.attrib["height"]) // 2,
    }


def control_point(element: ET.Element, spec: dict[str, Any]) -> dict[str, int]:
    x, y = int(element.attrib["x"]), int(element.attrib["y"])
    width, height = int(element.attrib["width"]), int(element.attrib["height"])
    horizontal = float(spec.get("horizontal_fraction", 0.5))
    vertical = float(spec.get("vertical_fraction", 0.5))
    if not 0 <= horizontal <= 1 or not 0 <= vertical <= 1:
        raise DemoError(f"Control fractions must be inside 0..1: {spec}")
    return {"x": round(x + width * horizontal), "y": round(y + height * vertical)}


def percentage(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"(?<!\d)(100|[1-9]?\d)\s*(?:%|percent\b)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def random_brightness_transition(direction: str, rng: random.Random) -> BrightnessTransition:
    """Choose a reproducible, visually meaningful transition on 5% steps."""
    low_values = tuple(range(10, 50, 5))
    high_values = tuple(range(55, 95, 5))
    pairs = [(low, high) for low in low_values for high in high_values if 20 <= high - low <= 40]
    if direction == "up":
        source, target = rng.choice(pairs)
    elif direction == "down":
        low, high = rng.choice(pairs)
        source, target = high, low
    else:
        raise DemoError(f"Unsupported brightness direction: {direction}")
    return BrightnessTransition(source=source, target=target)


def random_color_target(colors: list[str], current: str | None, rng: random.Random) -> str:
    choices = [color for color in colors if color != current]
    if not choices:
        raise DemoError("Color action needs at least one target different from the current color")
    return rng.choice(choices)


def random_color_transition(colors: list[str], rng: random.Random) -> ColorTransition:
    if len(set(colors)) < 2:
        raise DemoError("Color transition needs at least two distinct supported colors")
    source, target = rng.sample(list(dict.fromkeys(colors)), 2)
    return ColorTransition(source=source, target=target)


def light_action_cycle(colors: list[str], rng: random.Random) -> list[LightActionIntent]:
    """Build one five-sample cycle with deterministic random parameters."""
    color = random_color_transition(colors, rng)
    brightness_up = random_brightness_transition("up", rng)
    brightness_down = random_brightness_transition("down", rng)
    return [
        LightActionIntent("power_on", "off", None, "on"),
        LightActionIntent("change_color", "on", color.source, color.target),
        LightActionIntent("brightness_up", "on", brightness_up.source, brightness_up.target),
        LightActionIntent("brightness_down", "on", brightness_down.source, brightness_down.target),
        LightActionIntent("power_off", "on", None, "off"),
    ]


def slider_target(
    element: ET.Element,
    target_percent: int,
    *,
    orientation: str,
    high_at_start: bool,
    edge_margin_fraction: float = 0.08,
    track_start_fraction: float = 0.0,
    track_end_fraction: float = 1.0,
) -> dict[str, int]:
    """Resolve a target coordinate inside a slider without using screen constants."""
    if not 0 <= target_percent <= 100:
        raise DemoError(f"Brightness is outside 0..100: {target_percent}")
    if orientation not in {"horizontal", "vertical"}:
        raise DemoError(f"Unsupported slider orientation: {orientation}")
    if not 0 <= track_start_fraction < track_end_fraction <= 1:
        raise DemoError("Slider track fractions must satisfy 0 <= start < end <= 1")
    x, y = int(element.attrib["x"]), int(element.attrib["y"])
    width, height = int(element.attrib["width"]), int(element.attrib["height"])
    fraction = target_percent / 100.0
    if high_at_start:
        fraction = 1.0 - fraction
    fraction = edge_margin_fraction + fraction * (1.0 - 2.0 * edge_margin_fraction)
    fraction = track_start_fraction + fraction * (track_end_fraction - track_start_fraction)
    if orientation == "horizontal":
        return {"x": round(x + width * fraction), "y": y + height // 2}
    return {"x": x + width // 2, "y": round(y + height * fraction)}


def avoid_slider_overlays(
    element: ET.Element,
    start: dict[str, int],
    end: dict[str, int],
    overlays: list[ET.Element],
    *,
    orientation: str,
) -> tuple[dict[str, int], dict[str, int]]:
    """Move the drag across its track, preserving its longitudinal delta."""
    axis, cross, length, breadth = (
        ("y", "x", "height", "width") if orientation == "vertical"
        else ("x", "y", "width", "height")
    )
    low = int(element.attrib[cross])
    high = low + int(element.attrib[breadth])
    # Stay away from the control's outer edge as well as native overlays.
    margin = (high - low) * 0.1
    lanes = [(low + margin, high - margin)]
    path_low, path_high = sorted((start[axis], end[axis]))
    blocked = []
    for overlay in overlays:
        along = int(overlay.attrib[axis])
        if along > path_high or along + int(overlay.attrib[length]) < path_low:
            continue
        left = int(overlay.attrib[cross])
        right = left + int(overlay.attrib[breadth])
        if right < low or left > high:
            continue
        blocked.append((left, right))
        lanes = [piece for a, b in lanes for piece in
                 ((a, min(b, left - margin)), (max(a, right + margin), b))
                 if piece[1] - piece[0] >= 2]
    if not any(a <= start[cross] <= b for a, b in blocked):
        return start, end
    if not lanes:
        raise DemoError("No unobstructed slider drag lane in current native bounds")
    a, b = max(lanes, key=lambda lane: lane[1] - lane[0])
    point = round((a + b) / 2)
    return {**start, cross: point}, {**end, cross: point}


def relative_slider_target(
    element: ET.Element,
    current_percent: int,
    target_percent: int,
    *,
    orientation: str,
    high_at_start: bool,
) -> dict[str, int]:
    if not 0 <= current_percent <= 100 or not 0 <= target_percent <= 100:
        raise DemoError("Relative slider percentages must be inside 0..100")
    if orientation not in {"horizontal", "vertical"}:
        raise DemoError(f"Unsupported slider orientation: {orientation}")
    start = center(element)
    length = int(element.attrib["width"] if orientation == "horizontal" else element.attrib["height"])
    delta = round(length * (target_percent - current_percent) / 100.0)
    if high_at_start:
        delta = -delta
    if orientation == "horizontal":
        return {"x": start["x"] + delta, "y": start["y"]}
    return {"x": start["x"], "y": start["y"] + delta}


def _mapped_value(raw: str, mapping: dict[str, list[str] | str]) -> str:
    raw_lower = raw.strip().lower()
    for state, candidates in mapping.items():
        for candidate in candidates if isinstance(candidates, list) else [candidates]:
            if raw_lower == str(candidate).strip().lower():
                return state
    return "unknown"


def read_light_state(source: str, config: dict[str, Any]) -> LightState:
    power = "unknown"
    brightness: int | None = None
    color: str | None = None
    if config.get("power"):
        spec = config["power"]
        element = select_one(source, spec["selector"], "power-state control")
        raw = str(element.attrib.get(spec.get("attribute", "value")) or "")
        power = _mapped_value(raw, spec["mapping"])
        if power == "unknown" and spec.get("percentage_is_on") and percentage(raw) is not None:
            power = "on"
    if config.get("brightness"):
        spec = config["brightness"]
        element = select_one(source, spec["selector"], "brightness control")
        raw = str(element.attrib.get(spec.get("attribute", "value")) or "")
        brightness = percentage(raw)
    for name, spec in config.get("colors", {}).items():
        matches = select(source, spec["selector"])
        if len(matches) > 1:
            raise DemoError(f"Color selector {name!r} is ambiguous: {len(matches)} elements")
        if not matches:
            continue
        element = matches[0]
        attribute = spec.get("selected_attribute", "traits")
        selected_value = str(spec.get("selected_value", "Selected"))
        if selected_value.lower() in str(element.attrib.get(attribute) or "").lower():
            if color is not None:
                raise DemoError(f"Multiple colors are selected: {color!r} and {name!r}")
            color = name
    return LightState(power=power, brightness=brightness, color=color)
