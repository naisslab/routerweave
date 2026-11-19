"""Platform-neutral structured UI and device observations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping

from .status import Platform


_MISSING = object()


@dataclass(frozen=True, slots=True)
class ElementNode:
    """A semantic element reference returned by a platform adapter.

    ``bounds`` is retained only as evidence and for adapter-internal activation.
    Selectors cannot query it, which prevents coordinates becoming a task rule.
    """

    handle: str
    role: str = ""
    resource_id: str = ""
    accessibility_id: str = ""
    text: str = ""
    label: str = ""
    value: str = ""
    visible: bool = True
    enabled: bool = True
    clickable: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)
    bounds: tuple[int, int, int, int] | None = None

    def __post_init__(self) -> None:
        # Adapters commonly reuse mutable parser dictionaries. Evidence must be
        # a point-in-time snapshot or STATE_CHANGED checks become meaningless.
        object.__setattr__(self, "attributes", deepcopy(dict(self.attributes)))

    @property
    def semantic_text(self) -> str:
        parts: list[str] = []
        seen: set[str] = set()
        for value in (self.text, self.label, self.value):
            part = value.strip() if value else ""
            normalized = " ".join(part.casefold().split())
            if part and normalized not in seen:
                parts.append(part)
                seen.add(normalized)
        return " ".join(parts)


@dataclass(frozen=True, slots=True)
class Observation:
    platform: Platform
    observed_at: float
    app_id: str | None = None
    elements: tuple[ElementNode, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    generation: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "elements", tuple(self.elements))
        state = deepcopy(dict(self.state))
        if self.elements:
            ui_state = state.setdefault("ui", {})
            if isinstance(ui_state, dict):
                ui_state.setdefault("fingerprint", _semantic_ui_fingerprint(self.elements))
                ui_state.setdefault(
                    "layout_fingerprint", _layout_ui_fingerprint(self.elements)
                )
                ui_state.setdefault("element_count", len(self.elements))
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "errors", tuple(self.errors))

    def state_value(self, path: str) -> Any:
        found, value = self.lookup_state(path)
        return value if found else None

    def lookup_state(self, path: str) -> tuple[bool, Any]:
        current: Any = self.state
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                return False, _MISSING
            current = current[part]
        return True, current


def _semantic_ui_fingerprint(elements: tuple[ElementNode, ...]) -> str:
    """Hash semantic UI facts without persisting device coordinates or handles."""

    facts = [
        {
            "role": node.role,
            "resource_id": node.resource_id,
            "accessibility_id": node.accessibility_id,
            "text": " ".join(node.semantic_text.casefold().split()),
            "visible": node.visible,
            "enabled": node.enabled,
            "clickable": node.clickable,
            "selected": bool(node.attributes.get("selected", False)),
            "checked": bool(node.attributes.get("checked", False)),
        }
        for node in elements
        if node.visible
    ]
    facts.sort(key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))
    payload = json.dumps(facts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def _layout_ui_fingerprint(elements: tuple[ElementNode, ...]) -> str:
    """Hash current semantic layout without exposing coordinates as task data."""

    facts = [
        {
            "role": node.role,
            "resource_id": node.resource_id,
            "accessibility_id": node.accessibility_id,
            "text": " ".join(node.semantic_text.casefold().split()),
            "bounds": list(node.bounds) if node.bounds is not None else None,
        }
        for node in elements
        if node.visible
    ]
    facts.sort(key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))
    payload = json.dumps(facts, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()
