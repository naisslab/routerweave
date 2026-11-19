"""Seeded task-family activity plans ported from the proven collection policies."""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
import random
from typing import Iterable


@dataclass(frozen=True, slots=True)
class HumanActivityDecision:
    """One reproducible decision to execute inside a sustained task window."""

    at_seconds: float
    label: str
    hold_seconds: tuple[float, ...] = ()
    gesture_duration_ms: int = 0
    x_ratio: float = 0.5
    end_x_ratio: float = 0.5
    start_y_ratio: float = 0.75
    end_y_ratio: float = 0.25
    end_x_delta_px: int = 0
    repeat_count: int = 1
    delay_after_previous_seconds: float | None = None
    feed_direction: str = "up"


@dataclass(frozen=True, slots=True)
class _WeightedRange:
    weight: float
    minimum: float
    maximum: float


@dataclass(frozen=True, slots=True)
class _Choice:
    label: str
    weight: float
    min_remaining_seconds: float = 0.0
    hold_range: tuple[float, float] | None = None


_SHORT_FIRST = (
    _WeightedRange(0.55, 1.0, 2.5),
    _WeightedRange(0.35, 2.5, 5.0),
    _WeightedRange(0.10, 5.0, 9.0),
)
_SHORT_INTERVAL = (
    _WeightedRange(0.45, 1.5, 3.5),
    _WeightedRange(0.40, 3.5, 6.5),
    _WeightedRange(0.15, 7.0, 11.0),
)
_SHORT_GESTURE = (
    _WeightedRange(0.55, 280, 420),
    _WeightedRange(0.35, 430, 580),
    _WeightedRange(0.10, 590, 720),
)


def plan_human_activity(
    task_family: str,
    duration_seconds: float,
    seed: int,
    *,
    allow_pause: bool = True,
    allow_switch: bool = True,
    allow_detail: bool = True,
    allow_detail_scroll: bool = True,
    allow_feed_refresh: bool = False,
    allow_bidirectional_feed: bool = False,
    browsing_activity_style: str = "standard",
) -> tuple[HumanActivityDecision, ...]:
    """Compile the old weighted behavior models into one deterministic schedule."""

    if duration_seconds <= 0:
        return ()
    rng = random.Random(int(seed))
    if task_family == "short_video":
        return _plan_short_video(rng, duration_seconds)
    if task_family == "music":
        choices = [_Choice("continue_playback", 0.65)]
        if allow_switch:
            choices.append(_Choice("next_track", 0.25, 20.0))
        if allow_pause:
            choices.append(_Choice("pause_resume", 0.10, 40.0, (8.0, 20.0)))
        return _plan_sparse(
            rng,
            duration_seconds,
            first_range=(120.0, 240.0),
            interval_range=(240.0, 480.0),
            max_events=20,
            choices=choices,
        )
    if task_family == "long_video":
        choices = [_Choice("stay_current_video", 0.58)]
        if allow_pause:
            choices.append(_Choice("pause_resume", 0.20, 35.0, (8.0, 25.0)))
        if allow_switch:
            choices.append(_Choice("switch_video", 0.10, 70.0))
        return _plan_sparse(
            rng,
            duration_seconds,
            first_range=(90.0, 180.0),
            interval_range=(180.0, 420.0),
            max_events=20,
            choices=choices,
        )
    if task_family == "live_stream":
        choices = [_Choice("stay_current_room", 0.73)]
        if allow_pause:
            choices.append(_Choice("pause_resume", 0.12, 35.0, (8.0, 20.0)))
        if allow_switch:
            choices.append(_Choice("switch_room", 0.15, 70.0))
        schedule = _plan_sparse(
            rng,
            duration_seconds,
            first_range=(120.0, 240.0),
            interval_range=(240.0, 480.0),
            max_events=20,
            choices=choices,
        )
        room_slots = (
            (0.25, 0.25),
            (0.75, 0.25),
            (0.25, 0.48),
            (0.75, 0.48),
        )
        previous_slot = (0.75, 0.25)
        randomized: list[HumanActivityDecision] = []
        for decision in schedule:
            if decision.label != "switch_room":
                randomized.append(decision)
                continue
            candidates = tuple(slot for slot in room_slots if slot != previous_slot)
            selected = rng.choice(candidates)
            randomized.append(
                replace(
                    decision,
                    x_ratio=selected[0],
                    start_y_ratio=selected[1],
                )
            )
            previous_slot = selected
        return tuple(randomized)
    if task_family == "browsing":
        return _plan_browsing(
            rng,
            duration_seconds,
            allow_detail=allow_detail,
            allow_detail_scroll=allow_detail_scroll,
            allow_feed_refresh=allow_feed_refresh,
            allow_bidirectional_feed=allow_bidirectional_feed,
            activity_style=browsing_activity_style,
        )
    raise ValueError(f"unsupported human activity family {task_family!r}")


def _plan_short_video(
    rng: random.Random,
    duration_seconds: float,
) -> tuple[HumanActivityDecision, ...]:
    at_seconds = _sample_weighted_range(rng, _SHORT_FIRST)
    delay_after_previous_seconds = at_seconds
    decisions: list[HumanActivityDecision] = []
    while at_seconds < duration_seconds and len(decisions) < 1000:
        settle = rng.uniform(0.4, 0.9)
        decisions.append(
            HumanActivityDecision(
                at_seconds=round(at_seconds, 3),
                label="advance_short_video",
                hold_seconds=(round(settle, 3),),
                gesture_duration_ms=int(
                    round(_sample_weighted_range(rng, _SHORT_GESTURE))
                ),
                x_ratio=round(rng.uniform(0.45, 0.55), 4),
                start_y_ratio=round(rng.uniform(0.80, 0.90), 4),
                end_y_ratio=round(rng.uniform(0.16, 0.28), 4),
                end_x_delta_px=rng.randint(-35, 35),
                delay_after_previous_seconds=round(delay_after_previous_seconds, 3),
            )
        )
        delay_after_previous_seconds = _sample_weighted_range(rng, _SHORT_INTERVAL)
        at_seconds += settle + delay_after_previous_seconds
    return tuple(decisions)


def _plan_sparse(
    rng: random.Random,
    duration_seconds: float,
    *,
    first_range: tuple[float, float],
    interval_range: tuple[float, float],
    max_events: int,
    choices: Iterable[_Choice],
) -> tuple[HumanActivityDecision, ...]:
    available = tuple(choice for choice in choices if choice.weight > 0)
    at_seconds = rng.uniform(*first_range)
    decisions: list[HumanActivityDecision] = []
    while at_seconds < duration_seconds and len(decisions) < max_events:
        remaining = duration_seconds - at_seconds
        eligible = tuple(
            choice
            for choice in available
            if choice.min_remaining_seconds <= remaining
        )
        if not eligible:
            break
        choice = _weighted_choice(rng, eligible)
        holds = ()
        if choice.hold_range is not None:
            holds = (round(rng.uniform(*choice.hold_range), 3),)
        decisions.append(
            HumanActivityDecision(round(at_seconds, 3), choice.label, holds)
        )
        at_seconds += sum(holds) + rng.uniform(*interval_range)
    return tuple(decisions)


def _plan_browsing(
    rng: random.Random,
    duration_seconds: float,
    *,
    allow_detail: bool,
    allow_detail_scroll: bool,
    allow_feed_refresh: bool,
    allow_bidirectional_feed: bool,
    activity_style: str,
) -> tuple[HumanActivityDecision, ...]:
    # Android browsing has verified semantic detail entry. Keep its sustained
    # behavior inside content pages: the feed is navigation context, not the
    # reading activity being labeled. Platforms without verified detail entry
    # retain the feed-only policy.
    if activity_style not in {"standard", "rapid_feed"}:
        raise ValueError(f"unsupported browsing activity style {activity_style!r}")
    rapid_feed = activity_style == "rapid_feed"
    choices = (
        (
            (
                [_Choice("open_content_then_back", 0.62, 40.0), _Choice("scroll_feed", 0.32)]
                + ([_Choice("refresh_feed", 0.06)] if allow_feed_refresh else [])
                if rapid_feed
                else [_Choice("open_content_then_back", 0.82, 90.0), _Choice("scroll_feed", 0.12)]
                + ([_Choice("refresh_feed", 0.06)] if allow_feed_refresh else [])
            )
        )
        if allow_detail and (allow_feed_refresh or allow_bidirectional_feed)
        else [_Choice("open_content_then_back", 1.0, 90.0)]
        if allow_detail
        else (
            [
            _Choice("read_current_view", 0.47, hold_range=(8.0, 26.0)),
            _Choice("scroll_feed", 0.53, hold_range=(1.8, 4.5)),
            ]
            + ([_Choice("refresh_feed", 0.08)] if allow_feed_refresh else [])
        )
    )
    at_seconds = rng.uniform(3.0, 7.0) if rapid_feed else rng.uniform(6.0, 14.0)
    decisions: list[HumanActivityDecision] = []
    can_scroll_down = False
    while at_seconds < duration_seconds and len(decisions) < 120:
        remaining = duration_seconds - at_seconds
        eligible = tuple(
            choice for choice in choices if choice.min_remaining_seconds <= remaining
        )
        if not eligible:
            break
        choice = _weighted_choice(rng, eligible)
        holds: tuple[float, ...]
        duration_ms = 0
        feed_direction = "up"
        if choice.label == "read_current_view":
            holds = (round(rng.uniform(8.0, 26.0), 3),)
        elif choice.label == "scroll_feed":
            holds = (round(rng.uniform(1.8, 4.5), 3),)
            duration_ms = 760
            if allow_bidirectional_feed and can_scroll_down and rng.random() < 0.30:
                feed_direction = "down"
                can_scroll_down = False
            else:
                can_scroll_down = True
        elif choice.label == "refresh_feed":
            holds = ()
            can_scroll_down = False
        else:
            variant = (
                _weighted_choice(
                    rng,
                    (
                        _Choice("detail_read_only", 0.15),
                        _Choice("detail_scroll_once", 0.45),
                        _Choice("detail_scroll_twice", 0.40),
                    ),
                ).label
                if allow_detail_scroll
                else "detail_read_only"
            )
            if variant == "detail_read_only":
                holds = (
                    round(rng.uniform(8.0, 18.0), 3)
                    if rapid_feed
                    else round(rng.uniform(18.0, 45.0), 3)
                ,)
                duration_ms = 0
            elif variant == "detail_scroll_once":
                holds = (
                    round(rng.uniform(10.0, 24.0), 3),
                    round(rng.uniform(12.0, 35.0), 3),
                )
                duration_ms = 780
            else:
                holds = (
                    round(rng.uniform(8.0, 18.0), 3),
                    round(rng.uniform(8.0, 22.0), 3),
                    round(rng.uniform(10.0, 30.0), 3),
                )
                duration_ms = 820
            choice = _Choice(variant, 1.0)
            if allow_bidirectional_feed and can_scroll_down and rng.random() < 0.25:
                feed_direction = "down"
                can_scroll_down = False
            else:
                can_scroll_down = True
        decisions.append(
            HumanActivityDecision(
                round(at_seconds, 3),
                choice.label,
                holds,
                duration_ms,
                feed_direction=feed_direction,
            )
        )
        at_seconds += sum(holds) + (
            rng.uniform(3.0, 9.0) if rapid_feed else rng.uniform(14.0, 38.0)
        )
    return tuple(decisions)


def _weighted_choice(rng: random.Random, choices: tuple[_Choice, ...]) -> _Choice:
    total = sum(choice.weight for choice in choices)
    marker = rng.random() * total
    current = 0.0
    for choice in choices:
        current += choice.weight
        if marker <= current:
            return choice
    return choices[-1]


def _sample_weighted_range(
    rng: random.Random,
    choices: tuple[_WeightedRange, ...],
) -> float:
    total = sum(choice.weight for choice in choices)
    marker = rng.random() * total
    current = 0.0
    selected = choices[-1]
    for choice in choices:
        current += choice.weight
        if marker <= current:
            selected = choice
            break
    return rng.uniform(selected.minimum, selected.maximum)
