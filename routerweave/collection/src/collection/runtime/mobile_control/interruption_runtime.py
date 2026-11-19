"""Popup-first resolution before ordinary semantic action lookup."""

from __future__ import annotations

from collections import Counter
import re

from .binding import AppBinding
from .condition import Condition, ConditionKind
from .interruption import (
    InterruptionKind,
    InterruptionResult,
    InterruptionStatus,
    InterruptionSweep,
)
from .interruption_policy import (
    ConservativeGatekeeperPolicy,
    GatekeeperAction,
)
from .observation import ElementNode, Observation
from .perception import ElementFinder, FindStatus
from .playbook import WaitPolicy
from .status import CommandStatus, ConditionStatus, ObservationLevel
from .waiting import Clock, ObservationBroker, ConditionWaiter


class InterruptionManager:
    def __init__(
        self,
        binding: AppBinding,
        broker: ObservationBroker,
        waiter: ConditionWaiter,
        clock: Clock,
        finder: ElementFinder | None = None,
        policy: ConservativeGatekeeperPolicy | None = None,
        max_rounds: int = 4,
        unknown_settle_seconds: float = 3.0,
        policy_observation_attempts: int = 3,
        policy_observation_retry_seconds: float = 0.5,
    ) -> None:
        self._binding = binding
        self._broker = broker
        self._waiter = waiter
        self._clock = clock
        self._finder = finder or ElementFinder()
        self._policy = policy or ConservativeGatekeeperPolicy(
            nonblocking_login_banner=binding.metadata.get("nonblocking_login_banner"),
            inline_containers=binding.metadata.get("inline_containers"),
        )
        self._max_rounds = max_rounds
        self._unknown_settle_seconds = max(0.0, unknown_settle_seconds)
        self._policy_observation_attempts = max(1, policy_observation_attempts)
        self._policy_observation_retry_seconds = max(
            0.0, policy_observation_retry_seconds
        )
        self._occurrences: Counter[tuple[str, str]] = Counter()

    def reset(self) -> None:
        self._occurrences.clear()

    def sweep(self, observation: Observation, reason: str) -> InterruptionSweep:
        current = observation
        results: list[InterruptionResult] = []
        blocker_errors = self._blocker_errors(observation, reason)
        startup_wait = float(self._binding.metadata.get("startup_observation_wait_seconds") or 0)
        startup = reason.split(":", 1)[0] == "launch-app"
        settle_wait = startup_wait if startup else float(
            self._binding.metadata.get("observation_wait_seconds") or 0)

        def transient_read(error: str) -> bool:
            if error.startswith("structured: ValueError: stable UI hierarchy unavailable after "):
                attempts = error.partition("attempt(s): ")[2].split("; ")
                transient_uiautomator = (
                    "ValueError: uiautomator returned no hierarchy: "
                    "ERROR: null root node returned by UiTestAutomationBridge.",
                    "ValueError: uiautomator returned no hierarchy: "
                    "ERROR: could not get idle state.",
                )
                return bool(attempts) and all(
                    any(re.fullmatch(r"attempt [12]: " + re.escape(error), item)
                        for error in transient_uiautomator)
                    for item in attempts)
            return ("current root unavailable" in error
                    or "ConcurrentModificationException: incomplete current hierarchy" in error
                    or ("Android native operation exceeded" in error
                        and ("phase=root" in error or "phase=traverse" in error)))

        if (blocker_errors and 0 < settle_wait <= 90
                and current.state.get("device", {}).get("foreground_app") == self._binding.app_id
                and all(transient_read(error) for error in blocker_errors)):
            deadline = self._clock.monotonic() + settle_wait
            reads = 0
            while blocker_errors and self._clock.monotonic() < deadline:
                self._clock.sleep(min(1.0, deadline - self._clock.monotonic()))
                current = self._broker.observe(
                    ObservationLevel.STRUCTURED, f"{reason}:ui-settle-{reads + 1}",
                    fresh=True, signals=frozenset(("blocker", "ui")),
                )
                reads += 1
                blocker_errors = self._policy_observation_errors(current)
                if current.state.get("device", {}).get("foreground_app") != self._binding.app_id:
                    blocker_errors = (*blocker_errors, "blocker: settling foreground changed")
                    break
                if any(not transient_read(e) for e in blocker_errors):
                    break
            if not blocker_errors:
                results.append(InterruptionResult(
                    "startup-observation-recovered" if startup else "ui-observation-recovered", InterruptionKind.BENIGN,
                    InterruptionStatus.RESOLVED,
                    "fresh complete UI became available after bounded read-only waiting",
                    evidence={"reads": reads, "initial_errors": observation.errors},
                ))
        if blocker_errors:
            results.append(
                InterruptionResult(
                    "blocker-observation-unavailable",
                    InterruptionKind.UNKNOWN,
                    InterruptionStatus.BLOCKED,
                    "blocking UI could not be observed safely",
                    evidence={"errors": blocker_errors},
                )
            )
            return InterruptionSweep(current, tuple(results), True)
        for _ in range(self._max_rounds):
            handled = False
            for rule in (
                rule for rule in self._binding.interruptions if rule.applies_to(reason)
            ):
                marker = self._finder.find(
                    current,
                    self._binding.selectors[rule.marker_selector_key],
                )
                if marker.status is FindStatus.NOT_FOUND:
                    continue
                if marker.status is FindStatus.AMBIGUOUS:
                    results.append(
                        InterruptionResult(
                            rule.rule_id,
                            rule.kind,
                            InterruptionStatus.BLOCKED,
                            "interruption marker is ambiguous",
                            evidence={"candidates": len(marker.candidates)},
                        )
                    )
                    return InterruptionSweep(current, tuple(results), True)
                if (rule.required_foreground_app_id and current.state.get("device", {}).get(
                        "foreground_app") != rule.required_foreground_app_id):
                    results.append(InterruptionResult(
                        rule.rule_id, rule.kind, InterruptionStatus.BLOCKED,
                        "registered interruption foreground identity did not match",
                    ))
                    return InterruptionSweep(current, tuple(results), True)
                occurrence_key = (rule.rule_id, "" if rule.occurrence_scope == "session"
                                  else reason.split(":", 1)[0])
                self._occurrences[occurrence_key] += 1
                if self._occurrences[occurrence_key] > rule.max_occurrences:
                    results.append(
                        InterruptionResult(
                            rule.rule_id,
                            rule.kind,
                            InterruptionStatus.BLOCKED,
                            "interruption repeated beyond its bounded policy",
                        )
                    )
                    return InterruptionSweep(current, tuple(results), True)
                if not rule.auto_resolve and not rule.wait_for_dismissal:
                    results.append(
                        InterruptionResult(
                            rule.rule_id,
                            rule.kind,
                            InterruptionStatus.BLOCKED,
                            "interruption requires explicit task policy or operator input",
                            evidence=self._element_evidence(marker.selected),
                        )
                    )
                    return InterruptionSweep(current, tuple(results), True)

                resolution = None
                command = None
                if not rule.wait_for_dismissal:
                    resolution = self._finder.find(
                        current,
                        self._binding.selectors[rule.resolution_selector_key or ""],
                    )
                    if resolution.status is not FindStatus.FOUND or resolution.selected is None:
                        results.append(
                            InterruptionResult(
                                rule.rule_id,
                                rule.kind,
                                InterruptionStatus.FAILED,
                                f"resolution target was {resolution.status}",
                            )
                        )
                        return InterruptionSweep(current, tuple(results), True)
                    command = self._broker.adapter.activate_element(
                        resolution.selected,
                        {"interruption_rule": rule.rule_id},
                    )
                self._broker.invalidate()
                waited = self._waiter.wait(
                    Condition(ConditionKind.ELEMENT_ABSENT, rule.marker_selector_key),
                    current,
                    WaitPolicy(
                        timeout_seconds=rule.timeout_seconds,
                        poll_interval_seconds=0.25,
                        observation_level=ObservationLevel.STRUCTURED,
                    ),
                    f"{reason}:interruption:{rule.rule_id}",
                    additional_signals=frozenset(("blocker",)),
                )
                verification_errors = (
                    self._blocker_errors(waited.observation, reason)
                    if waited.observation is not None
                    else ("blocking UI observation returned no snapshot",)
                )
                if (rule.required_foreground_app_id and (waited.observation is None
                        or waited.observation.state.get("device", {}).get("foreground_app")
                        != rule.required_foreground_app_id)):
                    verification_errors = (*verification_errors, "registered interruption foreground changed")
                blocker_still_present = (
                    waited.observation is not None
                    and (
                        self._generic_blocker(waited.observation) is not None
                        or (
                            rule.wait_for_dismissal
                            and self._policy.decide(waited.observation).action
                            is not GatekeeperAction.NONE
                        )
                    )
                )
                resolved = (
                    waited.condition.status is ConditionStatus.MATCHED
                    and not verification_errors
                    and not blocker_still_present
                )
                if verification_errors:
                    result_detail = "blocking UI could not be re-observed safely"
                elif blocker_still_present:
                    result_detail = "blocking UI is still present"
                else:
                    result_detail = "blocking UI cleared" if resolved else "blocking UI did not clear"
                results.append(
                    InterruptionResult(
                        rule.rule_id,
                        rule.kind,
                        InterruptionStatus.RESOLVED if resolved else InterruptionStatus.FAILED,
                        result_detail,
                        command,
                        {
                            "marker": self._element_evidence(marker.selected),
                            "resolution": (
                                self._element_evidence(resolution.selected)
                                if resolution is not None else None
                            ),
                            "passive_wait": rule.wait_for_dismissal,
                            "polls": waited.polls,
                            "errors": verification_errors,
                        },
                    )
                )
                if not resolved or waited.observation is None:
                    return InterruptionSweep(current, tuple(results), True)
                current = waited.observation
                handled = True
                break
            if handled:
                continue

            if self._needs_blocker_detail(current):
                current, detail_errors, detail_attempts, recovered_errors = (
                    self._observe_policy_detail(f"{reason}:gatekeeper-detail")
                )
                if detail_errors:
                    results.append(
                        InterruptionResult(
                            "gatekeeper-observation-unavailable",
                            InterruptionKind.UNKNOWN,
                            InterruptionStatus.BLOCKED,
                            "blocking UI detail could not be observed safely",
                            evidence={"errors": detail_errors},
                        )
                    )
                    return InterruptionSweep(current, tuple(results), True)
                if recovered_errors:
                    results.append(
                        InterruptionResult(
                            "gatekeeper-observation-recovered",
                            InterruptionKind.BENIGN,
                            InterruptionStatus.RESOLVED,
                            "blocking UI detail observation recovered after a transient failure",
                            evidence={
                                "attempts": detail_attempts,
                                "errors": recovered_errors,
                            },
                        )
                    )

            decision = self._policy.decide(current)
            if (
                decision.action is GatekeeperAction.BLOCK
                and decision.rule_id == "unclassified-blocking-ui"
                and self._unknown_settle_seconds > 0
            ):
                settle_deadline = self._clock.monotonic() + self._unknown_settle_seconds
                settle_index = 0
                while self._clock.monotonic() < settle_deadline:
                    self._clock.sleep(
                        min(0.75, settle_deadline - self._clock.monotonic())
                    )
                    settle_index += 1
                    current, settle_errors, settle_attempts, recovered_errors = (
                        self._observe_policy_detail(
                            f"{reason}:gatekeeper-settle-{settle_index}"
                        )
                    )
                    if settle_errors:
                        results.append(
                            InterruptionResult(
                                "gatekeeper-observation-unavailable",
                                InterruptionKind.UNKNOWN,
                                InterruptionStatus.BLOCKED,
                                "blocking UI detail could not be observed safely",
                                evidence={"errors": settle_errors},
                            )
                        )
                        return InterruptionSweep(current, tuple(results), True)
                    if recovered_errors:
                        results.append(
                            InterruptionResult(
                                "gatekeeper-observation-recovered",
                                InterruptionKind.BENIGN,
                                InterruptionStatus.RESOLVED,
                                "blocking UI detail observation recovered after a transient failure",
                                evidence={
                                    "attempts": settle_attempts,
                                    "errors": recovered_errors,
                                },
                            )
                        )
                    decision = self._policy.decide(current)
                    if not (
                        decision.action is GatekeeperAction.BLOCK
                        and decision.rule_id == "unclassified-blocking-ui"
                    ):
                        break
            if decision.action is GatekeeperAction.BLOCK:
                blocker = self._generic_blocker(current)
                results.append(
                    InterruptionResult(
                        decision.rule_id,
                        decision.kind,
                        InterruptionStatus.BLOCKED,
                        decision.detail,
                        evidence={**self._element_evidence(blocker),
                                  "device": current.state.get("device", {}),
                                  "ui": current.state.get("ui", {})},
                    )
                )
                return InterruptionSweep(current, tuple(results), True)
            if decision.action is GatekeeperAction.RESOLVE:
                occurrence_key = (decision.rule_id, reason.split(":", 1)[0])
                self._occurrences[occurrence_key] += 1
                if self._occurrences[occurrence_key] > 2:
                    results.append(
                        InterruptionResult(
                            decision.rule_id,
                            decision.kind,
                            InterruptionStatus.BLOCKED,
                            "generic interruption repeated beyond its bounded policy",
                        )
                    )
                    return InterruptionSweep(current, tuple(results), True)
                assert decision.target is not None
                command = self._broker.adapter.activate_element(
                    decision.target,
                    {"interruption_rule": decision.rule_id},
                )
                self._broker.invalidate()
                refreshed, verification_errors, verification_attempts, recovered_errors = (
                    self._observe_policy_detail(
                        f"{reason}:gatekeeper:{decision.rule_id}:verify"
                    )
                )
                if recovered_errors:
                    results.append(
                        InterruptionResult(
                            "gatekeeper-observation-recovered",
                            InterruptionKind.BENIGN,
                            InterruptionStatus.RESOLVED,
                            "blocking UI detail observation recovered after a transient failure",
                            evidence={
                                "attempts": verification_attempts,
                                "errors": recovered_errors,
                            },
                        )
                    )
                next_decision = self._policy.decide(refreshed)
                before_surfaces = self._surface_signature(current)
                after_surfaces = self._surface_signature(refreshed)
                target_still_present = any(
                    node.visible and node.enabled
                    and self._semantic_identity(node) == self._semantic_identity(decision.target)
                    for node in refreshed.elements
                )
                resolved = (
                    not verification_errors
                    and (
                        next_decision.action is GatekeeperAction.NONE
                        or not target_still_present
                        or (bool(before_surfaces) and before_surfaces != after_surfaces)
                    )
                )
                results.append(
                    InterruptionResult(
                        decision.rule_id,
                        decision.kind,
                        (
                            InterruptionStatus.RESOLVED
                            if resolved
                            else InterruptionStatus.FAILED
                        ),
                        (
                            f"{decision.detail}; continuing bounded blocker sweep"
                            if resolved
                            else "generic interruption did not clear after resolution"
                        ),
                        command,
                        {
                            "resolution": self._element_evidence(decision.target),
                            "errors": verification_errors,
                            "surface_changed": before_surfaces != after_surfaces,
                            "target_still_present": target_still_present,
                        },
                    )
                )
                if not resolved:
                    return InterruptionSweep(refreshed, tuple(results), True)
                current = refreshed
                continue

            generic = self._generic_blocker(current)
            if generic is not None:
                results.append(
                    InterruptionResult(
                        "unclassified-blocking-ui",
                        InterruptionKind.UNKNOWN,
                        InterruptionStatus.BLOCKED,
                        "unclassified alert or system dialog blocks the task",
                        evidence=self._element_evidence(generic),
                    )
                )
                return InterruptionSweep(current, tuple(results), True)
            return InterruptionSweep(current, tuple(results), False)

        results.append(
            InterruptionResult(
                "interruption-round-limit",
                InterruptionKind.UNKNOWN,
                InterruptionStatus.BLOCKED,
                "too many sequential blocking surfaces",
            )
        )
        return InterruptionSweep(current, tuple(results), True)

    def _observe_policy_detail(
        self,
        reason: str,
    ) -> tuple[Observation, tuple[str, ...], int, tuple[str, ...]]:
        """Retry read-only blocker detail without weakening the final gate."""

        recovered_errors: list[str] = []
        current: Observation | None = None
        detail_errors: tuple[str, ...] = ()
        for attempt in range(1, self._policy_observation_attempts + 1):
            current = self._broker.observe(
                ObservationLevel.STRUCTURED,
                f"{reason}:attempt-{attempt}",
                fresh=True,
                signals=frozenset(("blocker", "ui")),
            )
            detail_errors = self._policy_observation_errors(current)
            if not detail_errors:
                return current, (), attempt, tuple(recovered_errors)
            recovered_errors.extend(detail_errors)
            if attempt < self._policy_observation_attempts:
                self._clock.sleep(self._policy_observation_retry_seconds)
        assert current is not None
        return current, detail_errors, self._policy_observation_attempts, tuple(recovered_errors)

    def _generic_blocker(self, observation: Observation) -> ElementNode | None:
        return next(iter(self._policy.blocking_surfaces(observation)), None)

    @staticmethod
    def _semantic_identity(node: ElementNode) -> tuple[str, str, str, str]:
        return (node.role, node.resource_id, node.accessibility_id, node.semantic_text)

    def _surface_signature(self, observation: Observation) -> tuple[tuple[str, str, str, str], ...]:
        # Ignore handles and descendant content: chat updates do not prove that
        # a blocking container disappeared or was replaced by a different one.
        return tuple(sorted(self._semantic_identity(node)
                            for node in self._policy.blocking_surfaces(observation)))

    def _blocker_errors(
        self,
        observation: Observation,
        reason: str,
    ) -> tuple[str, ...]:
        scoped_rules_apply = any(
            rule.applies_to(reason) for rule in self._binding.interruptions
        )
        return tuple(
            error
            for error in observation.errors
            if error.startswith("blocker:")
            or (
                scoped_rules_apply
                and (
                    error.startswith("structured:")
                    or "structured UI hierarchy was empty" in error
                    or "structured XCUI hierarchy was empty" in error
                )
            )
        )

    def _needs_blocker_detail(self, observation: Observation) -> bool:
        return self._generic_blocker(observation) is not None and not any(
            node.visible and node.enabled and node.clickable
            for node in observation.elements
        )

    @staticmethod
    def _policy_observation_errors(observation: Observation) -> tuple[str, ...]:
        return tuple(
            error
            for error in observation.errors
            if error.startswith(("blocker:", "structured:"))
            or "structured UI hierarchy was empty" in error
            or "structured XCUI hierarchy was empty" in error
        )

    @staticmethod
    def _element_evidence(element: ElementNode | None) -> dict[str, object]:
        if element is None:
            return {}
        return {
            "handle": element.handle,
            "role": element.role,
            "resource_id": element.resource_id,
            "accessibility_id": element.accessibility_id,
            "text": element.semantic_text,
            "package": element.attributes.get("package"),
            "bundle_id": element.attributes.get("bundle_id"),
            "probe": element.attributes.get("probe"),
        }
