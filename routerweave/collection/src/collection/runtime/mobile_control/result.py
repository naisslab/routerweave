"""Immutable execution evidence returned by the task engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .condition import ConditionResult
from .interruption import InterruptionResult
from .platform import CommandResult
from .status import FailureKind, OutcomeStatus


@dataclass(frozen=True, slots=True)
class AttemptResult:
    attempt: int
    strategy_id: str | None
    command: CommandResult | None
    condition: ConditionResult | None
    outcome: OutcomeStatus
    detail: str
    started_at: float
    finished_at: float
    reconciled: bool = False
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ActivityResult:
    label: str
    planned_at_seconds: float
    started_at: float
    finished_at: float
    outcome: OutcomeStatus
    steps: tuple["StepResult", ...] = ()

    @property
    def successful(self) -> bool:
        return self.outcome is OutcomeStatus.SUCCESS


@dataclass(frozen=True, slots=True)
class SustainResult:
    outcome: OutcomeStatus
    started_at: float
    finished_at: float
    checks: int
    recoveries: int
    detail: str
    last_condition: ConditionResult | None = None
    errors: tuple[str, ...] = ()
    activities: tuple[ActivityResult, ...] = ()


@dataclass(frozen=True, slots=True)
class StepResult:
    step_id: str
    outcome: OutcomeStatus
    attempts: tuple[AttemptResult, ...]
    started_at: float
    finished_at: float
    detail: str = ""
    failure_kind: FailureKind | None = None
    recovery_results: tuple["StepResult", ...] = ()
    interruptions: tuple[InterruptionResult, ...] = ()
    verification: ConditionResult | None = None
    sustain: SustainResult | None = None

    @property
    def successful(self) -> bool:
        return self.outcome in (OutcomeStatus.SUCCESS, OutcomeStatus.SKIPPED)


@dataclass(frozen=True, slots=True)
class RunResult:
    playbook_id: str
    outcome: OutcomeStatus
    steps: tuple[StepResult, ...]
    cleanup: tuple[StepResult, ...]
    started_at: float
    finished_at: float
    detail: str = ""
    event_errors: tuple[str, ...] = ()

    @property
    def successful(self) -> bool:
        return self.outcome is OutcomeStatus.SUCCESS
