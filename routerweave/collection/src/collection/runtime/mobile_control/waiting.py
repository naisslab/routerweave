"""Condition-driven waiting and observation caching."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

from .binding import AppBinding
from .condition import (
    Condition,
    ConditionEvaluator,
    ConditionKind,
    ConditionResult,
    required_observation_signals,
)
from .observation import Observation
from .interruption import InterruptionResult, InterruptionSweep
from .platform import MobilePlatformAdapter
from .playbook import WaitPolicy
from .status import ConditionStatus, ObservationLevel


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class ObservationBroker:
    """Shares cheap observations while making freshness explicit."""

    def __init__(
        self,
        adapter: MobilePlatformAdapter,
        clock: Clock,
        binding: AppBinding,
        cache_seconds: float = 0.2,
    ) -> None:
        self._adapter = adapter
        self._clock = clock
        self._binding = binding
        self._cache_seconds = cache_seconds
        self._cached: dict[tuple[ObservationLevel, frozenset[str]], tuple[float, Observation]] = {}

    @property
    def adapter(self) -> MobilePlatformAdapter:
        return self._adapter

    def observe(
        self,
        level: ObservationLevel,
        reason: str,
        *,
        fresh: bool = False,
        signals: frozenset[str] = frozenset(),
    ) -> Observation:
        now = self._clock.monotonic()
        key = (level, signals)
        cached = self._cached.get(key)
        if not fresh and cached and now - cached[0] <= self._cache_seconds:
            return cached[1]
        observation = self._adapter.observe(level, reason, signals)
        self._cached[key] = (now, observation)
        return observation

    def invalidate(self) -> None:
        self._cached.clear()

    def can_native_observe(self, condition: Condition) -> bool:
        keys = self._element_query_keys(condition)
        return bool(keys) and all(key in self._binding.element_queries for key in keys)

    def observe_for_condition(
        self,
        level: ObservationLevel,
        reason: str,
        condition: Condition,
        *,
        fresh: bool = False,
        additional_signals: frozenset[str] = frozenset(),
    ) -> Observation:
        keys = self._element_query_keys(condition)
        native_keys = tuple(
            sorted(key for key in (keys or ()) if key in self._binding.element_queries)
        )
        exclusively_native = (
            bool(keys)
            and len(native_keys) == len(keys)
            and "ui" not in additional_signals
        )
        if not exclusively_native:
            base = self.observe_full_condition(
                level,
                reason,
                condition,
                fresh=fresh,
                additional_signals=additional_signals,
            )
            if not native_keys:
                return base
            observation_path = "hybrid_element_query"
        else:
            base_signals = (
                required_observation_signals(condition) - frozenset(("ui",))
            ) | additional_signals
            base = (
                self.observe(
                    level,
                    reason,
                    fresh=fresh,
                    signals=base_signals,
                )
                if base_signals
                else Observation(self._adapter.platform, time.time())
            )
            observation_path = "native_element_query"
        elements = list(base.elements)
        generations = [base.generation]
        query_match_counts: dict[str, int] = {}
        for key in native_keys:
            query = self._binding.element_queries[key]
            try:
                observed = self._adapter.query_elements(
                    query.capability,
                    query.parameters,
                    f"{reason}:selector:{key}",
                )
            except Exception:
                if observation_path == "hybrid_element_query":
                    return base
                return self.observe_full_condition(
                    level, reason, condition, fresh=True,
                    additional_signals=additional_signals,
                )
            match_count = observed.state_value("mobile_control.match_count")
            if observed.errors:
                if observation_path == "hybrid_element_query":
                    return base
                return self.observe_full_condition(
                    level, reason, condition, fresh=True,
                    additional_signals=additional_signals,
                )
            if isinstance(match_count, int):
                query_match_counts[key] = match_count
            resource_id = str(query.parameters.get("resource_id") or "")
            if (
                observation_path == "hybrid_element_query"
                and query.capability == "observation.element.query"
                and resource_id.startswith(self._binding.app_id + ":id/")
            ):
                # This selector explicitly uses the fresh native resource query.
                # Do not count its earlier hierarchy copy as a second control.
                # Retain every native match: genuine ambiguity still fails.
                elements = [node for node in elements if node.resource_id != resource_id]
            elements.extend(observed.elements)
            generations.append(observed.generation)
        state = dict(base.state)
        state["mobile_control"] = {
            "observation_path": observation_path,
            "query_keys": native_keys,
            "query_match_counts": query_match_counts,
            "ambiguous_query_keys": tuple(
                key for key, count in query_match_counts.items() if count > 1
            ),
        }
        unique_elements = tuple({element.handle: element for element in elements}.values())
        return Observation(
            self._adapter.platform,
            time.time(),
            base.app_id,
            unique_elements,
            state,
            base.errors,
            max(generations),
        )

    def observe_full_condition(
        self,
        level: ObservationLevel,
        reason: str,
        condition: Condition,
        *,
        fresh: bool = False,
        additional_signals: frozenset[str] = frozenset(),
    ) -> Observation:
        return self.observe(
            level,
            reason,
            fresh=fresh,
            signals=required_observation_signals(condition) | additional_signals,
        )

    @classmethod
    def _element_query_keys(cls, condition: Condition) -> frozenset[str] | None:
        if condition.kind in (
            ConditionKind.ELEMENT_PRESENT,
            ConditionKind.ELEMENT_ABSENT,
            ConditionKind.ELEMENT_TEXT_CHANGED,
        ):
            return frozenset((condition.target,)) if condition.target else None
        if condition.kind in (ConditionKind.ALL, ConditionKind.ANY, ConditionKind.NOT):
            child_keys = [cls._element_query_keys(child) for child in condition.children]
            if any(keys is None for keys in child_keys):
                return None
            return frozenset().union(*(keys or frozenset() for keys in child_keys))
        if condition.kind in (ConditionKind.TRUE, ConditionKind.APP_FOREGROUND):
            return frozenset()
        if condition.kind in (
            ConditionKind.STATE_EQUALS,
            ConditionKind.STATE_CONTAINS,
            ConditionKind.STATE_CHANGED,
        ):
            return (
                None
                if "ui" in required_observation_signals(condition)
                else frozenset()
            )
        return None


@dataclass(frozen=True, slots=True)
class WaitResult:
    condition: ConditionResult
    observation: Observation | None
    polls: int
    started_at: float
    finished_at: float
    errors: tuple[str, ...] = ()
    interruptions: tuple[InterruptionResult, ...] = ()
    interruption_blocked: bool = False


class ConditionWaiter:
    def __init__(
        self,
        broker: ObservationBroker,
        binding: AppBinding,
        clock: Clock,
        evaluator: ConditionEvaluator | None = None,
    ) -> None:
        self._broker = broker
        self._binding = binding
        self._clock = clock
        self._evaluator = evaluator or ConditionEvaluator()

    def evaluate_now(
        self,
        condition: Condition,
        observation: Observation,
        baseline: Observation | None = None,
    ) -> ConditionResult:
        return self._evaluator.evaluate(condition, observation, self._binding, baseline)

    def wait(
        self,
        condition: Condition,
        baseline: Observation | None,
        policy: WaitPolicy,
        reason: str,
        additional_signals: frozenset[str] = frozenset(),
        interruption_handler: Callable[[Observation, str], InterruptionSweep] | None = None,
    ) -> WaitResult:
        policy.validate()
        started = self._clock.monotonic()
        deadline = started + policy.timeout_seconds
        errors: list[str] = []
        polls = 0
        consecutive = 0
        last_result = ConditionResult(ConditionStatus.UNKNOWN, "condition was not observed")
        last_observation: Observation | None = None
        interruptions: list[InterruptionResult] = []
        if policy.initial_grace_seconds:
            self._clock.sleep(min(policy.initial_grace_seconds, policy.timeout_seconds))

        while True:
            try:
                last_observation = self._broker.observe_for_condition(
                    policy.observation_level,
                    reason,
                    condition,
                    fresh=True,
                    additional_signals=additional_signals,
                )
                polls += 1
                if interruption_handler is not None:
                    sweep = interruption_handler(last_observation, reason)
                    interruptions.extend(sweep.results)
                    last_observation = sweep.observation
                    if sweep.blocked:
                        last_result = ConditionResult(
                            ConditionStatus.UNKNOWN,
                            sweep.results[-1].detail,
                        )
                        return WaitResult(
                            last_result,
                            last_observation,
                            polls,
                            started,
                            self._clock.monotonic(),
                            tuple(errors),
                            tuple(interruptions),
                            True,
                        )
                last_result = self.evaluate_now(condition, last_observation, baseline)
                if last_result.status is ConditionStatus.MATCHED:
                    consecutive += 1
                    if consecutive >= policy.consecutive_matches:
                        return WaitResult(
                            last_result,
                            last_observation,
                            polls,
                            started,
                            self._clock.monotonic(),
                            tuple(errors),
                            tuple(interruptions),
                        )
                else:
                    consecutive = 0
            except Exception as exc:  # adapter failures become evidence, not crashes
                errors.append(f"{type(exc).__name__}: {exc}")
                last_result = ConditionResult(ConditionStatus.UNKNOWN, "observation failed")

            now = self._clock.monotonic()
            if now >= deadline:
                if (
                    last_observation is not None
                    and last_observation.state_value("mobile_control.observation_path")
                    == "native_element_query"
                    and last_result.status is not ConditionStatus.MATCHED
                ):
                    try:
                        last_observation = self._broker.observe_full_condition(
                            policy.observation_level,
                            f"{reason}:full-fallback",
                            condition,
                            fresh=True,
                            additional_signals=additional_signals,
                        )
                        polls += 1
                        last_result = self.evaluate_now(condition, last_observation, baseline)
                        if last_result.status is ConditionStatus.MATCHED:
                            return WaitResult(
                                last_result,
                                last_observation,
                                polls,
                                started,
                                self._clock.monotonic(),
                                tuple(errors),
                                tuple(interruptions),
                            )
                    except Exception as exc:
                        errors.append(f"full fallback: {type(exc).__name__}: {exc}")
                return WaitResult(
                    last_result,
                    last_observation,
                    polls,
                    started,
                    now,
                    tuple(errors),
                    tuple(interruptions),
                )
            self._clock.sleep(min(policy.poll_interval_seconds, deadline - now))
