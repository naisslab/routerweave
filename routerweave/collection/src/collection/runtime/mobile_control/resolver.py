"""Resolve semantic actions to the strongest available platform mechanism."""

from __future__ import annotations

from dataclasses import dataclass

from .binding import ActionStrategy, AppBinding
from .capability import CapabilityCatalog
from .observation import ElementNode, Observation
from .perception import ElementFinder, FindStatus
from .status import ActionMethod


METHOD_ORDER = {
    ActionMethod.DIRECT: 0,
    ActionMethod.ELEMENT: 1,
    ActionMethod.GESTURE: 2,
    ActionMethod.VISUAL: 3,
}


@dataclass(frozen=True, slots=True)
class ResolvedStrategy:
    strategy: ActionStrategy
    element: ElementNode | None = None


@dataclass(frozen=True, slots=True)
class Resolution:
    resolved: tuple[ResolvedStrategy, ...]
    unavailable: tuple[str, ...]
    ambiguous: tuple[str, ...]


class ActionResolver:
    def __init__(self, finder: ElementFinder | None = None) -> None:
        self._finder = finder or ElementFinder()

    def resolve(
        self,
        semantic_action: str,
        binding: AppBinding,
        capabilities: CapabilityCatalog,
        observation: Observation,
    ) -> Resolution:
        action = binding.actions.get(semantic_action)
        if action is None:
            return Resolution((), (f"no binding for action {semantic_action!r}",), ())
        ordered = sorted(
            enumerate(action.strategies),
            key=lambda pair: (METHOD_ORDER[pair[1].method], -pair[1].priority, pair[0]),
        )
        resolved: list[ResolvedStrategy] = []
        unavailable: list[str] = []
        ambiguous: list[str] = []
        for _, strategy in ordered:
            if strategy.method is ActionMethod.ELEMENT:
                if strategy.capability:
                    if strategy.capability not in capabilities:
                        unavailable.append(
                            f"{strategy.strategy_id}: capability "
                            f"{strategy.capability!r} unsupported"
                        )
                        continue
                    descriptor = capabilities.descriptor(strategy.capability)
                    if descriptor.method is not ActionMethod.ELEMENT:
                        unavailable.append(
                            f"{strategy.strategy_id}: capability "
                            f"{strategy.capability!r} is {descriptor.method}, not element"
                        )
                        continue
                    resolved.append(ResolvedStrategy(strategy))
                    continue
                if "element.activate" not in capabilities:
                    unavailable.append(f"{strategy.strategy_id}: element activation unsupported")
                    continue
                selector = binding.selectors[strategy.selector_key or ""]
                match = self._finder.find(observation, selector)
                if match.status is FindStatus.FOUND:
                    resolved.append(ResolvedStrategy(strategy, match.selected))
                elif match.status is FindStatus.AMBIGUOUS:
                    ambiguous.append(f"{strategy.strategy_id}: {match.detail}")
                else:
                    unavailable.append(f"{strategy.strategy_id}: target not found")
                continue
            if strategy.capability not in capabilities:
                unavailable.append(
                    f"{strategy.strategy_id}: capability {strategy.capability!r} unsupported"
                )
                continue
            descriptor = capabilities.descriptor(strategy.capability or "")
            if descriptor.method is not strategy.method:
                unavailable.append(
                    f"{strategy.strategy_id}: capability {strategy.capability!r} is "
                    f"{descriptor.method}, not {strategy.method}"
                )
                continue
            resolved.append(ResolvedStrategy(strategy))
        return Resolution(tuple(resolved), tuple(unavailable), tuple(ambiguous))
