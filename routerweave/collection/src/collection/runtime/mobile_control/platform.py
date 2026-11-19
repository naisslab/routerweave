"""Thin platform adapter protocol and command result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, runtime_checkable

from .capability import CapabilityCatalog, CapabilityReport
from .observation import ElementNode, Observation
from .status import ActionMethod, CommandStatus, ObservationLevel, Platform


@dataclass(frozen=True, slots=True)
class CommandResult:
    status: CommandStatus
    method: ActionMethod
    command_id: str
    detail: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class MobilePlatformAdapter(Protocol):
    @property
    def platform(self) -> Platform: ...

    @property
    def capabilities(self) -> CapabilityCatalog: ...

    def probe_capabilities(self) -> CapabilityReport: ...

    def observe(
        self,
        level: ObservationLevel,
        reason: str,
        signals: frozenset[str] = frozenset(),
    ) -> Observation: ...

    def query_elements(
        self,
        capability: str,
        parameters: Mapping[str, Any],
        reason: str,
    ) -> Observation: ...

    def execute_direct(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult: ...

    def execute_element(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult: ...

    def activate_element(self, element: ElementNode, parameters: Mapping[str, Any]) -> CommandResult: ...

    def execute_gesture(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult: ...

    def execute_visual(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult: ...

    def capture_screenshot(self) -> bytes: ...
