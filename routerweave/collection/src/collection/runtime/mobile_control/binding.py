"""App-specific semantic bindings kept separate from task flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .interruption import InterruptionRule
from .perception import PageDefinition, SemanticSelector
from .status import ActionMethod, Idempotency, Platform


@dataclass(frozen=True, slots=True)
class ActionStrategy:
    strategy_id: str
    method: ActionMethod
    idempotency: Idempotency
    capability: str | None = None
    selector_key: str | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    priority: int = 0

    def validate(self) -> None:
        if not self.strategy_id:
            raise ValueError("strategy_id is required")
        if self.method is ActionMethod.ELEMENT:
            if bool(self.selector_key) == bool(self.capability):
                raise ValueError(
                    "element strategy requires exactly one of selector_key or capability"
                )
        elif not self.capability or self.selector_key:
            raise ValueError(f"{self.method} strategy requires capability only")


@dataclass(frozen=True, slots=True)
class ActionBinding:
    semantic_action: str
    strategies: tuple[ActionStrategy, ...]

    def validate(self) -> None:
        if not self.semantic_action:
            raise ValueError("semantic_action is required")
        if not self.strategies:
            raise ValueError(f"action {self.semantic_action!r} has no strategies")
        ids: set[str] = set()
        for strategy in self.strategies:
            strategy.validate()
            if strategy.strategy_id in ids:
                raise ValueError(f"duplicate strategy id {strategy.strategy_id!r}")
            ids.add(strategy.strategy_id)


@dataclass(frozen=True, slots=True)
class ElementObservationQuery:
    """App-owned read-only native query for one semantic selector."""

    capability: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.capability:
            raise ValueError("element observation query capability is required")


@dataclass(frozen=True, slots=True)
class AppBinding:
    binding_id: str
    platform: Platform
    app_id: str
    selectors: Mapping[str, SemanticSelector] = field(default_factory=dict)
    pages: Mapping[str, PageDefinition] = field(default_factory=dict)
    actions: Mapping[str, ActionBinding] = field(default_factory=dict)
    interruptions: tuple[InterruptionRule, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    element_queries: Mapping[str, ElementObservationQuery] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.binding_id or not self.app_id:
            raise ValueError("binding_id and app_id are required")
        for selector in self.selectors.values():
            selector.validate()
        for page_name, page in self.pages.items():
            page.validate()
            for selector_key in (*page.required, *page.any_of, *page.forbidden):
                if selector_key not in self.selectors:
                    raise ValueError(
                        f"page {page_name!r} references unknown selector {selector_key!r}"
                    )
        for action_name, binding in self.actions.items():
            binding.validate()
            if action_name != binding.semantic_action:
                raise ValueError(f"action map key {action_name!r} disagrees with binding")
            for strategy in binding.strategies:
                if strategy.selector_key and strategy.selector_key not in self.selectors:
                    raise ValueError(
                        f"strategy {strategy.strategy_id!r} references unknown selector "
                        f"{strategy.selector_key!r}"
                    )
        for selector_key, query in self.element_queries.items():
            query.validate()
            if selector_key not in self.selectors:
                raise ValueError(
                    f"element observation query references unknown selector {selector_key!r}"
                )
        interruption_ids: set[str] = set()
        for rule in self.interruptions:
            rule.validate()
            if rule.rule_id in interruption_ids:
                raise ValueError(f"duplicate interruption rule {rule.rule_id!r}")
            interruption_ids.add(rule.rule_id)
            selector_keys = (rule.marker_selector_key, rule.resolution_selector_key)
            for selector_key in selector_keys:
                if selector_key and selector_key not in self.selectors:
                    raise ValueError(
                        f"interruption {rule.rule_id!r} references unknown selector {selector_key!r}"
                    )
