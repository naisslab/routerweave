"""Declarative rules for UI that blocks the task's real page."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

from .observation import Observation
from .platform import CommandResult


class InterruptionKind(StrEnum):
    BENIGN = "benign"
    PERMISSION = "permission"
    AUTHENTICATION = "authentication"
    PAYMENT = "payment"
    CAPTCHA = "captcha"
    UNKNOWN = "unknown"


class InterruptionStatus(StrEnum):
    RESOLVED = "resolved"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class InterruptionRule:
    rule_id: str
    kind: InterruptionKind
    marker_selector_key: str
    resolution_selector_key: str | None = None
    auto_resolve: bool = False
    timeout_seconds: float = 4.0
    max_occurrences: int = 1
    step_ids: tuple[str, ...] = ()
    wait_for_dismissal: bool = False
    required_foreground_app_id: str = ""
    occurrence_scope: str = "step"

    def validate(self) -> None:
        if not self.rule_id or not self.marker_selector_key:
            raise ValueError("interruption rule id and marker selector are required")
        if self.wait_for_dismissal and (
            self.kind is not InterruptionKind.BENIGN
            or self.auto_resolve
            or self.resolution_selector_key is not None
        ):
            raise ValueError("passive dismissal requires a benign rule without an activation")
        if self.auto_resolve and not self.resolution_selector_key:
            raise ValueError("auto-resolved interruption requires a resolution selector")
        if self.auto_resolve and self.kind in {
            InterruptionKind.AUTHENTICATION,
            InterruptionKind.PAYMENT,
            InterruptionKind.CAPTCHA,
            InterruptionKind.UNKNOWN,
        }:
            raise ValueError(f"unsafe interruption kind {self.kind} cannot be auto-resolved")
        if self.timeout_seconds <= 0 or self.max_occurrences < 1:
            raise ValueError("interruption timeout and occurrence count must be positive")
        if any(not step_id.strip() for step_id in self.step_ids):
            raise ValueError("interruption step ids cannot be empty")
        if self.occurrence_scope not in {"step", "session"}:
            raise ValueError("interruption occurrence scope must be step or session")

    def applies_to(self, step_id: str) -> bool:
        """Empty scope means every step; retry suffixes retain the base step id."""

        base_step_id = step_id.split(":", 1)[0]
        return not self.step_ids or any(
            base_step_id == scoped or base_step_id.startswith(scoped + "-")
            for scoped in self.step_ids
        )


@dataclass(frozen=True, slots=True)
class InterruptionResult:
    rule_id: str
    kind: InterruptionKind
    status: InterruptionStatus
    detail: str
    command: CommandResult | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InterruptionSweep:
    observation: Observation
    results: tuple[InterruptionResult, ...]
    blocked: bool
