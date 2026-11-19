"""Platform evidence contract used by the unified collection lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class PlatformEvidenceResult:
    platform: str
    evidence_type: str
    ready: bool
    artifacts: Mapping[str, str] = field(default_factory=dict)
    metrics: Mapping[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    formal_ready: bool = False



@dataclass(frozen=True, slots=True)
class AttributionResult:
    ready: bool
    formal_ready: bool
    artifacts: dict[str, str]
    metrics: dict[str, Any]
    errors: tuple[str, ...] = ()
