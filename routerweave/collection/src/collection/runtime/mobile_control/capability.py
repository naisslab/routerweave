"""Explicit bottom-layer capability contracts and health evidence."""

from __future__ import annotations

from collections.abc import Iterator, Set
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

from .status import ActionMethod


class CapabilityKind(StrEnum):
    CONTROL = "control"
    OBSERVATION = "observation"
    VERIFICATION = "verification"


class CapabilityHealth(StrEnum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    name: str
    kind: CapabilityKind
    method: ActionMethod | None
    description: str
    coordinate_free: bool = True

    def validate(self) -> None:
        if not self.name or not self.description:
            raise ValueError("capability name and description are required")
        if self.kind is CapabilityKind.CONTROL and self.method is None:
            raise ValueError(f"control capability {self.name!r} requires an action method")
        if self.kind is not CapabilityKind.CONTROL and self.method is not None:
            raise ValueError(f"non-control capability {self.name!r} cannot declare an action method")


class CapabilityCatalog(Set[str]):
    """Queryable, documented capabilities exposed by one adapter."""

    def __init__(self, descriptors: tuple[CapabilityDescriptor, ...]) -> None:
        by_name: dict[str, CapabilityDescriptor] = {}
        for descriptor in descriptors:
            descriptor.validate()
            if descriptor.name in by_name:
                raise ValueError(f"duplicate capability {descriptor.name!r}")
            by_name[descriptor.name] = descriptor
        self._by_name = by_name

    @classmethod
    def control_names(cls, *names: str) -> "CapabilityCatalog":
        def method_for(name: str) -> ActionMethod:
            if name.startswith("element."):
                return ActionMethod.ELEMENT
            if name.startswith("screen.") or name.startswith("gesture."):
                return ActionMethod.GESTURE
            if name.startswith("visual."):
                return ActionMethod.VISUAL
            return ActionMethod.DIRECT

        return cls(
            tuple(
                CapabilityDescriptor(name, CapabilityKind.CONTROL, method_for(name), name)
                for name in names
            )
        )

    def __contains__(self, value: object) -> bool:
        return value in self._by_name

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_name)

    def __len__(self) -> int:
        return len(self._by_name)

    def descriptor(self, name: str) -> CapabilityDescriptor:
        return self._by_name[name]

    @property
    def descriptors(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(self._by_name.values())


@dataclass(frozen=True, slots=True)
class CapabilityProbe:
    capability: str
    health: CapabilityHealth
    detail: str
    duration_seconds: float
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    adapter: str
    probes: tuple[CapabilityProbe, ...]

    @property
    def usable(self) -> frozenset[str]:
        return frozenset(
            probe.capability
            for probe in self.probes
            if probe.health in (CapabilityHealth.AVAILABLE, CapabilityHealth.DEGRADED)
        )

    @property
    def unavailable(self) -> frozenset[str]:
        return frozenset(
            probe.capability
            for probe in self.probes
            if probe.health is CapabilityHealth.UNAVAILABLE
        )
