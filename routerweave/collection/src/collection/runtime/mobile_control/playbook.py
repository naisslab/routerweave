"""Composable semantic task definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .condition import Condition, ConditionKind
from .status import ObservationLevel


@dataclass(frozen=True, slots=True)
class WaitPolicy:
    timeout_seconds: float = 8.0
    poll_interval_seconds: float = 0.25
    initial_grace_seconds: float = 0.0
    consecutive_matches: int = 1
    observation_level: ObservationLevel = ObservationLevel.STRUCTURED

    def validate(self) -> None:
        if self.timeout_seconds < 0 or self.poll_interval_seconds <= 0:
            raise ValueError("wait timeout must be non-negative and poll interval positive")
        if self.initial_grace_seconds < 0 or self.consecutive_matches < 1:
            raise ValueError("invalid wait grace or consecutive match count")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 2

    def validate(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")


@dataclass(frozen=True, slots=True)
class ScheduledActivity:
    """One preplanned human-like decision inside a sustained task window."""

    at_seconds: float
    label: str
    steps: tuple["Step", ...] = ()
    delay_after_previous_seconds: float | None = None
    guard: Condition | None = None

    def validate(self) -> None:
        if self.at_seconds < 0:
            raise ValueError("scheduled activity time cannot be negative")
        if (
            self.delay_after_previous_seconds is not None
            and self.delay_after_previous_seconds < 0
        ):
            raise ValueError("activity delay after previous completion cannot be negative")
        if not self.label.strip():
            raise ValueError("scheduled activity label is required")
        for step in self.steps:
            if step.sustain is not None and step.sustain.activities:
                raise ValueError("scheduled activities cannot contain another activity schedule")
            step.validate()


@dataclass(frozen=True, slots=True)
class SustainPolicy:
    """Keep a verified state true for a bounded task-owned interval."""

    duration_seconds: float
    poll_interval_seconds: float = 2.0
    max_consecutive_misses: int = 2
    max_recoveries: int = 1
    max_consecutive_activity_failures: int = 0
    activities: tuple[ScheduledActivity, ...] = ()
    count_from_playbook_start: bool = False

    def validate(self) -> None:
        if self.duration_seconds <= 0 or self.poll_interval_seconds <= 0:
            raise ValueError("sustain duration and poll interval must be positive")
        if (
            self.max_consecutive_misses < 1
            or self.max_recoveries < 0
            or self.max_consecutive_activity_failures < 0
        ):
            raise ValueError("invalid sustain miss or recovery limit")
        previous = -1.0
        for activity in self.activities:
            activity.validate()
            if activity.at_seconds <= previous:
                raise ValueError("scheduled activity times must be strictly increasing")
            if activity.at_seconds >= self.duration_seconds:
                raise ValueError("scheduled activity must occur before sustain deadline")
            previous = activity.at_seconds


@dataclass(frozen=True, slots=True)
class Step:
    step_id: str
    semantic_action: str | None
    success: Condition
    parameters: Mapping[str, Any] = field(default_factory=dict)
    wait: WaitPolicy = field(default_factory=WaitPolicy)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    skip_if_satisfied: bool = True
    recovery: tuple["Step", ...] = ()
    safe_retry_after_recovery: bool = False
    observation_signals: tuple[str, ...] = ()
    bypass_interruptions: bool = False
    sustain: SustainPolicy | None = None
    skip_when: Condition | None = None

    def validate(self) -> None:
        if not self.step_id:
            raise ValueError("step_id is required")
        self.wait.validate()
        self.retry.validate()
        if self.skip_when is not None and (self.sustain is not None or self.skip_when.kind is ConditionKind.TRUE):
            raise ValueError("conditional action omission needs a state condition and cannot sustain")
        if self.safe_retry_after_recovery and (
            not self.recovery or self.retry.max_attempts < 2
        ):
            raise ValueError(
                "safe retry after recovery requires recovery steps and at least two attempts"
            )
        if any(not signal.strip() for signal in self.observation_signals):
            raise ValueError("observation signals cannot be empty")
        if self.sustain is not None:
            self.sustain.validate()
            if self.bypass_interruptions:
                raise ValueError("sustained steps cannot bypass interruption safety")
        for recovery_step in self.recovery:
            recovery_step.validate()


@dataclass(frozen=True, slots=True)
class Playbook:
    playbook_id: str
    version: int
    steps: tuple[Step, ...]
    cleanup: tuple[Step, ...] = ()
    stop_on_failure: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.playbook_id or self.version < 1 or not self.steps:
            raise ValueError("playbook id, positive version, and steps are required")
        ids: set[str] = set()
        main_steps = tuple(_walk_steps(self.steps))
        cleanup_steps = tuple(_walk_steps(self.cleanup))
        for step in (*main_steps, *cleanup_steps):
            step.validate()
            if step.step_id in ids:
                raise ValueError(f"duplicate step id {step.step_id!r}")
            ids.add(step.step_id)
        if any(step.bypass_interruptions for step in main_steps):
            raise ValueError("main-flow steps cannot bypass interruption safety")


def _walk_steps(steps: tuple[Step, ...]):
    for step in steps:
        yield step
        yield from _walk_steps(step.recovery)
        if step.sustain is not None:
            for activity in step.sustain.activities:
                yield from _walk_steps(activity.steps)
