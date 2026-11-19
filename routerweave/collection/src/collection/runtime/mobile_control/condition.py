"""Serializable postconditions and their platform-neutral evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .binding import AppBinding
from .observation import Observation
from .perception import ElementFinder, FindStatus, PageRecognizer
from .status import ConditionStatus


class ConditionKind(StrEnum):
    TRUE = "true"
    APP_FOREGROUND = "app_foreground"
    ELEMENT_PRESENT = "element_present"
    ELEMENT_ABSENT = "element_absent"
    ELEMENT_TEXT_CHANGED = "element_text_changed"
    PAGE_RECOGNIZED = "page_recognized"
    STATE_EQUALS = "state_equals"
    STATE_CONTAINS = "state_contains"
    STATE_CHANGED = "state_changed"
    ALL = "all"
    ANY = "any"
    NOT = "not"


@dataclass(frozen=True, slots=True)
class Condition:
    kind: ConditionKind
    target: str | None = None
    expected: Any = None
    children: tuple["Condition", ...] = ()

    @classmethod
    def true(cls) -> "Condition":
        return cls(ConditionKind.TRUE)


@dataclass(frozen=True, slots=True)
class ConditionResult:
    status: ConditionStatus
    detail: str
    actual: Any = None


class ConditionEvaluator:
    def __init__(
        self,
        finder: ElementFinder | None = None,
        page_recognizer: PageRecognizer | None = None,
    ) -> None:
        self._finder = finder or ElementFinder()
        self._pages = page_recognizer or PageRecognizer(self._finder)

    def evaluate(
        self,
        condition: Condition,
        observation: Observation,
        binding: AppBinding,
        baseline: Observation | None = None,
    ) -> ConditionResult:
        kind = condition.kind
        if kind is ConditionKind.TRUE:
            return ConditionResult(ConditionStatus.MATCHED, "unconditional success")
        if kind is ConditionKind.APP_FOREGROUND:
            expected = condition.expected or binding.app_id
            if observation.app_id is None:
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "foreground app observation is unavailable",
                )
            matched = observation.app_id == expected
            return self._bool(matched, "foreground app", observation.app_id)
        if kind in (ConditionKind.ELEMENT_PRESENT, ConditionKind.ELEMENT_ABSENT):
            if not condition.target or condition.target not in binding.selectors:
                return ConditionResult(ConditionStatus.UNKNOWN, "unknown selector")
            if self._ui_unavailable(observation):
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "structured UI observation is unavailable",
                    observation.errors,
                )
            found = self._finder.find(observation, binding.selectors[condition.target])
            if found.status is FindStatus.AMBIGUOUS:
                return ConditionResult(ConditionStatus.UNKNOWN, found.detail)
            present = found.status is FindStatus.FOUND
            wanted = present if kind is ConditionKind.ELEMENT_PRESENT else not present
            return self._bool(wanted, f"selector {condition.target}", found.status)
        if kind is ConditionKind.ELEMENT_TEXT_CHANGED:
            if not condition.target or condition.target not in binding.selectors or baseline is None:
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "selector and baseline are required for element text change",
                )
            if self._ui_unavailable(observation) or self._ui_unavailable(baseline):
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "structured UI observation is unavailable",
                )
            before = self._finder.find(baseline, binding.selectors[condition.target])
            after = self._finder.find(observation, binding.selectors[condition.target])
            if before.status is FindStatus.NOT_FOUND:
                return ConditionResult(ConditionStatus.UNKNOWN, "baseline element is unavailable")
            if after.status is FindStatus.NOT_FOUND:
                return ConditionResult(ConditionStatus.NOT_MATCHED, "current element is unavailable")
            before_texts = self._candidate_texts(before)
            after_texts = self._candidate_texts(after)
            if not before_texts or not after_texts:
                return ConditionResult(ConditionStatus.UNKNOWN, "element text is unavailable")
            return self._bool(
                before_texts != after_texts,
                f"selector {condition.target} text set changed",
                (before_texts, after_texts),
            )
        if kind is ConditionKind.PAGE_RECOGNIZED:
            if not condition.target or condition.target not in binding.pages:
                return ConditionResult(ConditionStatus.UNKNOWN, "unknown page")
            if self._ui_unavailable(observation):
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "structured UI observation is unavailable",
                    observation.errors,
                )
            result = self._pages.recognize(
                observation, binding.pages[condition.target], binding.selectors
            )
            return self._bool(result.matched, f"page {condition.target}", result.evidence)
        if kind is ConditionKind.STATE_EQUALS:
            if not condition.target:
                return ConditionResult(ConditionStatus.UNKNOWN, "state path is required")
            found, actual = observation.lookup_state(condition.target)
            if not found:
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    f"state {condition.target} is unavailable",
                )
            return self._bool(actual == condition.expected, f"state {condition.target}", actual)
        if kind is ConditionKind.STATE_CONTAINS:
            if not condition.target or not isinstance(condition.expected, str):
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "state path and string expectation are required",
                )
            found, actual = observation.lookup_state(condition.target)
            if not found or not isinstance(actual, str):
                return ConditionResult(
                    ConditionStatus.UNKNOWN,
                    f"string state {condition.target} is unavailable",
                )
            return self._bool(
                condition.expected.casefold() in actual.casefold(),
                f"state {condition.target} contains {condition.expected!r}",
                actual,
            )
        if kind is ConditionKind.STATE_CHANGED:
            if not condition.target or baseline is None:
                return ConditionResult(ConditionStatus.UNKNOWN, "baseline and state path are required")
            before_found, before = baseline.lookup_state(condition.target)
            after_found, after = observation.lookup_state(condition.target)
            if not before_found or not after_found:
                return ConditionResult(ConditionStatus.UNKNOWN, "state value unavailable")
            return self._bool(before != after, f"state {condition.target} changed", (before, after))
        if kind in (ConditionKind.ALL, ConditionKind.ANY):
            if not condition.children:
                return ConditionResult(ConditionStatus.UNKNOWN, "composite condition has no children")
            results = [self.evaluate(child, observation, binding, baseline) for child in condition.children]
            if kind is ConditionKind.ALL:
                if any(item.status is ConditionStatus.NOT_MATCHED for item in results):
                    return ConditionResult(ConditionStatus.NOT_MATCHED, "an ALL child did not match", results)
                if all(item.status is ConditionStatus.MATCHED for item in results):
                    return ConditionResult(ConditionStatus.MATCHED, "all children matched", results)
            else:
                if any(item.status is ConditionStatus.MATCHED for item in results):
                    return ConditionResult(ConditionStatus.MATCHED, "an ANY child matched", results)
                if all(item.status is ConditionStatus.NOT_MATCHED for item in results):
                    return ConditionResult(ConditionStatus.NOT_MATCHED, "no ANY child matched", results)
            return ConditionResult(ConditionStatus.UNKNOWN, "composite result is uncertain", results)
        if kind is ConditionKind.NOT:
            if len(condition.children) != 1:
                return ConditionResult(ConditionStatus.UNKNOWN, "NOT requires one child")
            result = self.evaluate(condition.children[0], observation, binding, baseline)
            if result.status is ConditionStatus.UNKNOWN:
                return result
            inverted = result.status is ConditionStatus.NOT_MATCHED
            return self._bool(inverted, "negated condition", result)
        return ConditionResult(ConditionStatus.UNKNOWN, f"unsupported condition {kind}")

    @staticmethod
    def _bool(matched: bool, detail: str, actual: Any) -> ConditionResult:
        return ConditionResult(
            ConditionStatus.MATCHED if matched else ConditionStatus.NOT_MATCHED,
            detail,
            actual,
        )

    @staticmethod
    def _candidate_texts(result: Any) -> tuple[str, ...]:
        nodes = (
            tuple(candidate.element for candidate in result.candidates)
            if result.status is FindStatus.AMBIGUOUS
            else ((result.selected,) if result.selected is not None else ())
        )
        return tuple(
            sorted(
                {
                    " ".join(node.semantic_text.casefold().split())
                    for node in nodes
                    if node.semantic_text.strip()
                }
            )
        )

    @staticmethod
    def _ui_unavailable(observation: Observation) -> bool:
        return any(
            error.startswith("structured:")
            or "structured UI hierarchy was empty" in error
            or "structured XCUI hierarchy was empty" in error
            for error in observation.errors
        )


def required_observation_signals(condition: Condition) -> frozenset[str]:
    """Return the cheapest raw signals needed to evaluate a condition."""

    if condition.kind is ConditionKind.APP_FOREGROUND:
        return frozenset(("foreground",))
    if condition.kind in (
        ConditionKind.ELEMENT_PRESENT,
        ConditionKind.ELEMENT_ABSENT,
        ConditionKind.ELEMENT_TEXT_CHANGED,
        ConditionKind.PAGE_RECOGNIZED,
    ):
        return frozenset(("ui",))
    if condition.kind in (
        ConditionKind.STATE_EQUALS,
        ConditionKind.STATE_CONTAINS,
        ConditionKind.STATE_CHANGED,
    ):
        target = condition.target or ""
        if target.startswith("media."):
            return frozenset(("media",))
        if target.startswith("audio."):
            return frozenset(("audio",))
        if target.startswith("motion."):
            return frozenset(("motion",))
        if target.startswith("visual."):
            return frozenset(("frame",))
        if target.startswith("network."):
            return frozenset(("network",))
        if target.startswith("device.orientation") or target.startswith("device.viewport"):
            return frozenset(("viewport",))
        if target.startswith("device.foreground"):
            return frozenset(("foreground",))
        return frozenset(("ui",))
    if condition.kind in (ConditionKind.ALL, ConditionKind.ANY, ConditionKind.NOT):
        return frozenset().union(
            *(required_observation_signals(child) for child in condition.children)
        )
    return frozenset()


def requires_baseline_observation(condition: Condition) -> bool:
    """Whether evaluating the condition needs a before-action snapshot."""

    if condition.kind in (ConditionKind.ELEMENT_TEXT_CHANGED, ConditionKind.STATE_CHANGED):
        return True
    return any(requires_baseline_observation(child) for child in condition.children)


def validate_condition(condition: Condition, binding: AppBinding) -> None:
    kind = condition.kind
    if kind in (
        ConditionKind.ELEMENT_PRESENT,
        ConditionKind.ELEMENT_ABSENT,
        ConditionKind.ELEMENT_TEXT_CHANGED,
    ):
        if not condition.target or condition.target not in binding.selectors:
            raise ValueError(f"condition references unknown selector {condition.target!r}")
    elif kind is ConditionKind.PAGE_RECOGNIZED:
        if not condition.target or condition.target not in binding.pages:
            raise ValueError(f"condition references unknown page {condition.target!r}")
    elif kind in (
        ConditionKind.STATE_EQUALS,
        ConditionKind.STATE_CONTAINS,
        ConditionKind.STATE_CHANGED,
    ):
        if not condition.target:
            raise ValueError(f"{kind} condition requires a state path")
        if kind is ConditionKind.STATE_CONTAINS and not isinstance(condition.expected, str):
            raise ValueError("state_contains condition requires a string expectation")
    elif kind in (ConditionKind.ALL, ConditionKind.ANY):
        if not condition.children:
            raise ValueError(f"{kind} condition requires children")
    elif kind is ConditionKind.NOT:
        if len(condition.children) != 1:
            raise ValueError("NOT condition requires exactly one child")
    elif condition.children:
        raise ValueError(f"{kind} condition cannot contain children")
    for child in condition.children:
        validate_condition(child, binding)
