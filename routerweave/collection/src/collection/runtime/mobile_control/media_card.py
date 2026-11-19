"""Select a current long-form media card from semantic duration/title evidence."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Sequence

from .observation import ElementNode


_DURATION = re.compile(r"(?<!\d)(?:(\d{1,2}):)?([0-5]?\d):([0-5]\d)(?!\d)")


@dataclass(frozen=True, slots=True)
class MediaCardSelection:
    selected: ElementNode | None
    duration_seconds: int | None
    candidate_count: int
    anchor: ElementNode | None
    detail: str


def select_media_card(
    elements: Sequence[ElementNode],
    *,
    minimum_duration_seconds: int = 60,
    exclude_pattern: str = "",
) -> MediaCardSelection:
    """Choose a title aligned with a visible duration label in the live UI."""

    if minimum_duration_seconds < 0:
        raise ValueError("minimum_duration_seconds cannot be negative")
    excluded = re.compile(exclude_pattern, re.IGNORECASE) if exclude_pattern else None
    visible = [node for node in elements if node.visible and node.enabled and node.bounds]
    durations: list[tuple[int, ElementNode]] = []
    for node in visible:
        seconds = duration_seconds(node.semantic_text)
        if seconds is not None and seconds >= minimum_duration_seconds:
            durations.append((seconds, node))
    candidates: list[tuple[int, float, int, int, ElementNode, ElementNode]] = []
    for seconds, duration in durations:
        assert duration.bounds is not None
        dx1, dy1, dx2, dy2 = duration.bounds
        for title in visible:
            if title is duration or duration_seconds(title.semantic_text) is not None:
                continue
            if title.role not in {"statictext", "textview", "label"}:
                continue
            text = title.semantic_text.strip()
            if len(text) < 2:
                continue
            assert title.bounds is not None
            tx1, ty1, tx2, _ = title.bounds
            y_delta = ty1 - dy1
            if not 4 <= y_delta <= 140:
                continue
            # Right-aligned duration text can extend beyond the title's glyph
            # bounds. Require horizontal overlap without pairing adjacent cards.
            if max(dx1, tx1) >= min(dx2, tx2):
                continue
            activation_target = _smallest_clickable_container(
                visible,
                title,
                duration,
            ) or title
            target_context = " | ".join(
                (
                    title.semantic_text,
                    str(activation_target.attributes.get("descendant_text") or ""),
                )
            )
            if excluded and excluded.search(target_context):
                continue
            candidates.append(
                (seconds, y_delta, ty1, tx1, activation_target, title)
            )
    if not candidates:
        return MediaCardSelection(
            None,
            None,
            0,
            None,
            "no visible title could be paired with a long-form duration label",
        )
    candidates.sort(key=lambda item: (-item[0], item[1], item[2], item[3], item[5].handle))
    seconds, _, _, _, selected, title = candidates[0]
    target_detail = (
        f"smallest clickable {selected.role} container"
        if selected is not title
        else "title hit point"
    )
    return MediaCardSelection(
        selected,
        seconds,
        len(candidates),
        title,
        f"selected {target_detail} for title paired with {seconds}-second media duration",
    )


def _smallest_clickable_container(
    elements: Sequence[ElementNode],
    title: ElementNode,
    duration: ElementNode,
) -> ElementNode | None:
    """Return the tightest live semantic container holding both card anchors."""

    assert title.bounds is not None and duration.bounds is not None
    title_center = _center(title.bounds)
    duration_center = _center(duration.bounds)
    containers = [
        node
        for node in elements
        if node.clickable
        and node.bounds is not None
        and _contains(node.bounds, title_center)
        and _contains(node.bounds, duration_center)
    ]
    if not containers:
        return None
    role_rank = {"cell": 0, "button": 1, "image": 2}
    containers.sort(
        key=lambda node: (
            _area(node.bounds),
            role_rank.get(node.role, 3),
            node.handle,
        )
    )
    return containers[0]


def _center(bounds: tuple[int, int, int, int]) -> tuple[float, float]:
    left, top, right, bottom = bounds
    return ((left + right) / 2.0, (top + bottom) / 2.0)


def _contains(
    bounds: tuple[int, int, int, int],
    point: tuple[float, float],
) -> bool:
    left, top, right, bottom = bounds
    x, y = point
    return left <= x <= right and top <= y <= bottom


def _area(bounds: tuple[int, int, int, int]) -> int:
    left, top, right, bottom = bounds
    return max(0, right - left) * max(0, bottom - top)


def duration_seconds(text: str) -> int | None:
    # Only a dedicated duration label is media evidence. Publication timestamps
    # embedded in metadata must not turn a nearby album title into a video card.
    match = _DURATION.fullmatch((text or "").strip())
    if not match:
        return None
    hours = int(match.group(1) or 0)
    return hours * 3600 + int(match.group(2)) * 60 + int(match.group(3))
