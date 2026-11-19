"""Bounded semantic candidate selection for feed and catalog content."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import re
from typing import Any, Mapping, Sequence

from .interruption_policy import is_blocking_surface
from .observation import ElementNode


@dataclass(frozen=True, slots=True)
class SemanticCandidateSelection:
    selected: ElementNode | None
    candidates: tuple[ElementNode, ...]
    detail: str


def select_semantic_candidate(
    elements: Sequence[ElementNode],
    parameters: Mapping[str, Any],
) -> SemanticCandidateSelection:
    """Choose one live element using semantic filters and normalized geometry.

    Geometry is only a bounded adapter-side filter. The action stores no fixed
    tap coordinate and always derives the hit point from the current hierarchy.
    """

    include = _compile_required(parameters, "include_pattern")
    exclude = _compile_optional(parameters, "exclude_pattern")
    exclude_identity = _compile_optional(parameters, "exclude_identity_pattern")
    role = _compile_optional(parameters, "role_pattern")
    resource_id = _compile_optional(parameters, "resource_id_pattern")
    accessibility_id = _compile_optional(parameters, "accessibility_id_pattern")
    require_clickable = bool(parameters.get("require_clickable", True))
    min_width_ratio = _ratio(parameters, "min_width_ratio", 0.0)
    max_width_ratio = _ratio(parameters, "max_width_ratio", 1.0)
    min_height_ratio = _ratio(parameters, "min_height_ratio", 0.0)
    max_height_ratio = _ratio(parameters, "max_height_ratio", 1.0)
    min_top_ratio = _ratio(parameters, "min_top_ratio", 0.0)
    max_bottom_ratio = _ratio(parameters, "max_bottom_ratio", 1.0)
    require_unobstructed = bool(parameters.get("require_unobstructed", True))
    avoid_semantic_texts = tuple(
        str(value)
        for value in parameters.get("avoid_semantic_texts", ())
        if str(value).strip()
    )
    avoid_similarity_threshold = _ratio(
        parameters,
        "avoid_similarity_threshold",
        0.97,
    )

    # Off-screen carousel and tab items can retain large coordinates in an
    # accessibility snapshot.  They are not part of the live viewport and
    # must not dilute normalized card geometry.
    bounded = [node for node in elements if node.bounds and node.visible]
    right_edge = max((node.bounds[2] for node in bounded if node.bounds), default=0)
    bottom_edge = max((node.bounds[3] for node in bounded if node.bounds), default=0)
    if right_edge <= 0 or bottom_edge <= 0:
        return SemanticCandidateSelection(None, (), "live viewport bounds are unavailable")
    blockers = tuple(
        node
        for node in bounded
        if node.visible and node.enabled and is_blocking_surface(node)
    )
    if require_unobstructed and blockers:
        blocker = blockers[0]
        identity = blocker.resource_id or blocker.accessibility_id or blocker.role
        return SemanticCandidateSelection(
            None,
            (),
            f"blocking surface {identity!r} must be resolved before candidate activation",
        )

    matches: list[ElementNode] = []
    for node in bounded:
        if not node.visible or not node.enabled:
            continue
        if require_clickable and not node.clickable:
            continue
        if resource_id and not resource_id.search(node.resource_id):
            continue
        if accessibility_id and not accessibility_id.search(node.accessibility_id):
            continue
        semantic_text = str(node.attributes.get("descendant_text") or node.semantic_text)
        if any(
            _semantic_similarity(semantic_text, previous)
            >= avoid_similarity_threshold
            for previous in avoid_semantic_texts
        ):
            continue
        component_identity = " ".join(
            part
            for part in (
                node.resource_id,
                node.accessibility_id,
                node.role,
                str(node.attributes.get("class") or ""),
                str(node.attributes.get("type") or ""),
            )
            if part
        )
        if exclude_identity and exclude_identity.search(component_identity):
            continue
        if not include.search(semantic_text):
            continue
        if exclude and exclude.search(semantic_text):
            continue
        role_text = " ".join(
            part
            for part in (
                node.role,
                str(node.attributes.get("class") or ""),
                str(node.attributes.get("type") or ""),
            )
            if part
        )
        if role and not role.search(role_text):
            continue
        assert node.bounds is not None
        left, top, right, bottom = node.bounds
        width_ratio = max(0, right - left) / right_edge
        height_ratio = max(0, bottom - top) / bottom_edge
        if not min_width_ratio <= width_ratio <= max_width_ratio:
            continue
        if not min_height_ratio <= height_ratio <= max_height_ratio:
            continue
        if top / bottom_edge < min_top_ratio or bottom / bottom_edge > max_bottom_ratio:
            continue
        matches.append(node)

    matches.sort(
        key=lambda node: (
            node.bounds[1] if node.bounds else 0,
            node.bounds[0] if node.bounds else 0,
            node.resource_id,
            node.accessibility_id,
            node.handle,
        )
    )
    if not matches:
        return SemanticCandidateSelection(None, (), "no live semantic candidate matched")
    policy = str(parameters.get("selection_policy") or "first_visible").casefold()
    if policy not in {"first_visible", "nearest_point", "seeded_random"}:
        raise ValueError(f"unsupported semantic candidate selection policy {policy!r}")
    selected = matches[0]
    detail = f"selected first of {len(matches)} visible semantic candidates"
    if policy == "nearest_point":
        target_x = _ratio(parameters, "x_ratio", 0.5)
        target_y = _ratio(parameters, "y_ratio", 0.5)
        selected = min(
            matches,
            key=lambda node: (
                (
                    ((node.bounds[0] + node.bounds[2]) / 2 / right_edge) - target_x
                )
                ** 2
                + (
                    ((node.bounds[1] + node.bounds[3]) / 2 / bottom_edge) - target_y
                )
                ** 2,
                node.bounds[1],
                node.bounds[0],
            ),
        )
        detail = (
            f"selected nearest of {len(matches)} visible semantic candidates "
            f"to ({target_x:.3f}, {target_y:.3f})"
        )
    elif policy == "seeded_random":
        try:
            selection_seed = int(parameters["selection_seed"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "selection_seed must be an integer for seeded_random selection"
            ) from exc
        selected_index = selection_seed % len(matches)
        selected = matches[selected_index]
        detail = (
            f"selected index {selected_index} of {len(matches)} visible semantic "
            f"candidates using seed {selection_seed}"
        )
    return SemanticCandidateSelection(
        selected,
        tuple(matches),
        detail,
    )


def _compile_required(parameters: Mapping[str, Any], name: str) -> re.Pattern[str]:
    value = str(parameters.get(name) or "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return re.compile(value, re.IGNORECASE)


def _compile_optional(
    parameters: Mapping[str, Any],
    name: str,
) -> re.Pattern[str] | None:
    value = str(parameters.get(name) or "").strip()
    return re.compile(value, re.IGNORECASE) if value else None


def _ratio(parameters: Mapping[str, Any], name: str, default: float) -> float:
    try:
        value = float(parameters.get(name, default))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be between zero and one")
    return value


def _semantic_similarity(left: str, right: str) -> float:
    """Treat small live metadata changes as the same semantic content card."""

    def normalize(value: str) -> str:
        normalized = value.casefold()
        normalized = re.sub(r"\d+(?:\.\d+)?(?:万)?", "#", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    return SequenceMatcher(None, normalize(left), normalize(right)).ratio()
