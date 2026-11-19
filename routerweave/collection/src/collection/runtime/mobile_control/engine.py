"""Deterministic semantic playbook execution engine."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from .binding import AppBinding
from .condition import (
    ConditionKind,
    ConditionResult,
    requires_baseline_observation,
    required_observation_signals,
    validate_condition,
)
from .events import EventSink, NullEventSink
from .interruption import InterruptionResult
from .interruption_runtime import InterruptionManager
from .observation import Observation
from .platform import CommandResult, MobilePlatformAdapter
from .playbook import Playbook, Step, WaitPolicy
from .resolver import ActionResolver, ResolvedStrategy
from .result import ActivityResult, AttemptResult, RunResult, StepResult, SustainResult
from .status import (
    ActionMethod,
    CommandStatus,
    ConditionStatus,
    FailureKind,
    Idempotency,
    ObservationLevel,
    OutcomeStatus,
)
from .waiting import Clock, ConditionWaiter, ObservationBroker, SystemClock


class PlaybookRunner:
    """Runs deterministic tasks and verifies effects independently of commands."""

    def __init__(
        self,
        adapter: MobilePlatformAdapter,
        binding: AppBinding,
        *,
        clock: Clock | None = None,
        event_sink: EventSink | None = None,
        resolver: ActionResolver | None = None,
        uncertain_reconcile_seconds: float = 1.5,
    ) -> None:
        self._adapter = adapter
        self._binding = binding
        self._clock = clock or SystemClock()
        self._events = event_sink or NullEventSink()
        self._resolver = resolver or ActionResolver()
        self._broker = ObservationBroker(adapter, self._clock, binding)
        self._waiter = ConditionWaiter(self._broker, binding, self._clock)
        self._interruptions = InterruptionManager(
            binding,
            self._broker,
            self._waiter,
            self._clock,
        )
        self._uncertain_reconcile_seconds = uncertain_reconcile_seconds
        self._event_errors: list[str] = []
        self._playbook_started: float | None = None

    def run(self, playbook: Playbook) -> RunResult:
        self._validate(playbook)
        self._event_errors.clear()
        self._interruptions.reset()
        started = self._clock.monotonic()
        self._playbook_started = started
        self._emit("playbook_started", {"playbook_id": playbook.playbook_id})
        steps: list[StepResult] = []
        cleanup: list[StepResult] = []
        try:
            for step in playbook.steps:
                result = self._run_step(step)
                steps.append(result)
                if playbook.stop_on_failure and not result.successful:
                    break
        finally:
            for step in playbook.cleanup:
                cleanup.append(self._run_step(step, cleanup=True))

        finished = self._clock.monotonic()
        main_ok = len(steps) == len(playbook.steps) and all(item.successful for item in steps)
        cleanup_ok = all(item.successful for item in cleanup)
        results = (*steps, *cleanup)
        definite_failure = any(
            item.outcome in (OutcomeStatus.FINAL_FAILURE, OutcomeStatus.RETRYABLE_FAILURE)
            for item in results
        )
        if self._event_errors:
            outcome = OutcomeStatus.FINAL_FAILURE
            detail = "control completed but event evidence is incomplete"
        elif definite_failure:
            outcome = OutcomeStatus.FINAL_FAILURE
            detail = "playbook has a definite required-step failure"
        elif main_ok and cleanup_ok:
            outcome = OutcomeStatus.SUCCESS
            detail = "playbook completed"
        elif any(item.outcome is OutcomeStatus.UNKNOWN for item in results):
            outcome = OutcomeStatus.UNKNOWN
            detail = "playbook outcome is uncertain"
        elif any(item.outcome is OutcomeStatus.UNSUPPORTED for item in results):
            outcome = OutcomeStatus.UNSUPPORTED
            detail = "playbook requires an unsupported capability"
        else:
            outcome = OutcomeStatus.FINAL_FAILURE
            detail = "playbook did not complete"
        result = RunResult(
            playbook.playbook_id,
            outcome,
            tuple(steps),
            tuple(cleanup),
            started,
            finished,
            detail,
            tuple(self._event_errors),
        )
        error_count = len(self._event_errors)
        self._emit("playbook_finished", {"result": result})
        if len(self._event_errors) != error_count:
            result = replace(
                result,
                outcome=OutcomeStatus.FINAL_FAILURE,
                detail="control completed but final event evidence could not be written",
                event_errors=tuple(self._event_errors),
            )
        return result

    def _validate(self, playbook: Playbook) -> None:
        playbook.validate()
        self._binding.validate()
        if self._adapter.platform is not self._binding.platform:
            raise ValueError(
                f"adapter platform {self._adapter.platform} does not match "
                f"binding platform {self._binding.platform}"
            )
        for step in self._walk_steps((*playbook.steps, *playbook.cleanup)):
            validate_condition(step.success, self._binding)
            if step.skip_when is not None:
                validate_condition(step.skip_when, self._binding)
                if requires_baseline_observation(step.skip_when):
                    raise ValueError("conditional action omission cannot use a transition condition")
            if step.sustain is not None:
                if step.success.kind is ConditionKind.TRUE:
                    raise ValueError(
                        f"step {step.step_id!r} cannot sustain an unconditional condition"
                    )
                if requires_baseline_observation(step.success):
                    raise ValueError(
                        f"step {step.step_id!r} cannot sustain a transition-only condition"
                    )
                for recovery_step in self._walk_steps(step.recovery):
                    action = self._binding.actions.get(recovery_step.semantic_action or "")
                    if action and any(
                        strategy.idempotency is Idempotency.NON_IDEMPOTENT
                        for strategy in action.strategies
                    ) and recovery_step.retry.max_attempts != 1:
                        raise ValueError(
                            f"sustained step {step.step_id!r} has retrying non-idempotent "
                            f"recovery {recovery_step.step_id!r}; recovery actions must "
                            "have exactly one attempt"
                        )
                for activity in step.sustain.activities:
                    if activity.guard is None:
                        continue
                    validate_condition(activity.guard, self._binding)
                    if requires_baseline_observation(activity.guard):
                        raise ValueError(
                            f"scheduled activity {activity.label!r} cannot use a "
                            "transition-only guard"
                        )
            if step.semantic_action and step.semantic_action not in self._binding.actions:
                raise ValueError(f"step {step.step_id!r} uses unbound action {step.semantic_action!r}")
        for step in self._walk_steps(playbook.cleanup):
            if not step.bypass_interruptions:
                continue
            action = self._binding.actions.get(step.semantic_action or "")
            if action is None or any(
                strategy.method is not ActionMethod.DIRECT
                or strategy.capability != "app.terminate"
                for strategy in action.strategies
            ):
                raise ValueError(
                    f"cleanup step {step.step_id!r} may bypass interruptions only "
                    "through direct app.terminate"
                )

    def _walk_steps(self, steps: tuple[Step, ...]):
        for step in steps:
            yield step
            yield from self._walk_steps(step.recovery)
            if step.sustain is not None:
                for activity in step.sustain.activities:
                    yield from self._walk_steps(activity.steps)

    def _run_step(self, step: Step, *, cleanup: bool = False) -> StepResult:
        started = self._clock.monotonic()
        interruption_results: tuple[InterruptionResult, ...] = ()
        scan_interruptions = not step.bypass_interruptions
        self._emit("step_started", {"step_id": step.step_id, "cleanup": cleanup})
        try:
            baseline = self._observe_step_baseline(
                step,
                f"{step.step_id}:baseline",
                scan_interruptions=scan_interruptions,
            )
        except Exception as exc:
            return self._finish_step(
                step,
                OutcomeStatus.FINAL_FAILURE,
                (),
                started,
                f"baseline observation failed: {type(exc).__name__}: {exc}",
                FailureKind.OBSERVATION_FAILED,
            )

        if scan_interruptions:
            sweep = self._interruptions.sweep(baseline, step.step_id)
            interruption_results += sweep.results
            for interruption in sweep.results:
                self._emit(
                    "interruption_finished",
                    {"step_id": step.step_id, "result": interruption},
                )
            if sweep.blocked:
                return self._finish_step(
                    step,
                    OutcomeStatus.FINAL_FAILURE,
                    (),
                    started,
                    sweep.results[-1].detail,
                    FailureKind.INTERRUPTION_BLOCKED,
                    interruptions=interruption_results,
                )
            baseline = sweep.observation

        if step.skip_when is not None:
            omission = self._waiter.evaluate_now(step.skip_when, baseline, None)
            if omission.status is ConditionStatus.UNKNOWN:
                return self._finish_step(step, OutcomeStatus.FINAL_FAILURE, (), started,
                    "action applicability could not be observed", FailureKind.OBSERVATION_FAILED,
                    interruptions=interruption_results, verification=omission)
            if omission.status is ConditionStatus.MATCHED:
                return self._finish_step(step, OutcomeStatus.SKIPPED, (), started,
                    "action not applicable in observed state",
                    interruptions=interruption_results, verification=omission)

        initial_verification = self._condition_now(step, baseline, baseline)
        if (
            step.skip_if_satisfied
            and step.success.kind is not ConditionKind.TRUE
            and initial_verification.status is ConditionStatus.MATCHED
        ):
            return self._finish_successful_step(
                step,
                OutcomeStatus.SKIPPED,
                (),
                started,
                "postcondition already satisfied",
                interruptions=interruption_results,
                verification=initial_verification,
            )

        if step.semantic_action is None:
            waited = self._waiter.wait(
                step.success,
                baseline,
                step.wait,
                f"{step.step_id}:verify",
                additional_signals=self._step_signals(
                    step,
                    scan_interruptions=scan_interruptions,
                ),
                interruption_handler=(
                    self._interruptions.sweep if scan_interruptions else None
                ),
            )
            interruption_results += waited.interruptions
            for interruption in waited.interruptions:
                self._emit(
                    "interruption_finished",
                    {"step_id": step.step_id, "result": interruption},
                )
            if waited.interruption_blocked:
                return self._finish_step(
                    step,
                    OutcomeStatus.FINAL_FAILURE,
                    (),
                    started,
                    waited.condition.detail,
                    FailureKind.INTERRUPTION_BLOCKED,
                    interruptions=interruption_results,
                )
            outcome = (
                OutcomeStatus.SUCCESS
                if waited.condition.status is ConditionStatus.MATCHED
                else (
                    OutcomeStatus.UNKNOWN
                    if waited.condition.status is ConditionStatus.UNKNOWN
                    else OutcomeStatus.FINAL_FAILURE
                )
            )
            attempt = AttemptResult(
                1,
                None,
                None,
                waited.condition,
                outcome,
                waited.condition.detail,
                waited.started_at,
                waited.finished_at,
                evidence={"polls": waited.polls, "errors": waited.errors},
            )
            if outcome is OutcomeStatus.SUCCESS:
                return self._finish_successful_step(
                    step,
                    outcome,
                    (attempt,),
                    started,
                    waited.condition.detail,
                    interruptions=interruption_results,
                    verification=waited.condition,
                )
            return self._finish_step(
                step,
                outcome,
                (attempt,),
                started,
                waited.condition.detail,
                (
                    FailureKind.VERIFICATION_UNAVAILABLE
                    if outcome is OutcomeStatus.UNKNOWN
                    else FailureKind.TRANSITION_TIMEOUT
                ),
                interruptions=interruption_results,
            )

        attempts: list[AttemptResult] = []
        recovery_results: list[StepResult] = []
        last_resolution_detail = ""
        strategy_cursor = 0
        for attempt_number in range(1, step.retry.max_attempts + 1):
            if attempt_number > 1 and step.recovery:
                recovery_ok = True
                for recovery_step in step.recovery:
                    # A delayed command may already have succeeded. Reconcile
                    # before EACH recovery action, not after mutating the page.
                    current = self._broker.observe_for_condition(
                        step.wait.observation_level,
                        f"{step.step_id}:before-recovery:{recovery_step.step_id}",
                        step.success, fresh=True,
                        additional_signals=self._step_signals(
                            step, scan_interruptions=scan_interruptions,
                            include_action_targets=False,
                        ),
                    )
                    if scan_interruptions:
                        sweep = self._interruptions.sweep(current, f"{step.step_id}:before-recovery")
                        interruption_results += sweep.results
                        for interruption in sweep.results:
                            self._emit("interruption_finished", {"step_id": step.step_id, "result": interruption})
                        if sweep.blocked:
                            return self._finish_step(
                                step, OutcomeStatus.FINAL_FAILURE, tuple(attempts), started,
                                "recovery blocked by interruption", FailureKind.INTERRUPTION_BLOCKED,
                                tuple(recovery_results), interruptions=interruption_results,
                            )
                        current = sweep.observation
                    verified = self._condition_now(step, current, baseline)
                    if step.success.kind is not ConditionKind.TRUE and verified.status is ConditionStatus.MATCHED:
                        return self._finish_successful_step(
                            step, OutcomeStatus.SUCCESS, tuple(attempts), started,
                            "postcondition satisfied before recovery action",
                            recovery_results=tuple(recovery_results),
                            interruptions=interruption_results, verification=verified,
                        )
                    recovery_action = self._binding.actions.get(recovery_step.semantic_action or "")
                    page_independent_reset = recovery_action is not None and all(
                        strategy.method is ActionMethod.DIRECT
                        and strategy.idempotency is Idempotency.STATE_SETTING
                        for strategy in recovery_action.strategies
                    )
                    if (
                        verified.status is ConditionStatus.UNKNOWN
                        and recovery_step.semantic_action is not None
                        and not page_independent_reset
                    ):
                        return self._finish_step(
                            step, OutcomeStatus.UNKNOWN, tuple(attempts), started,
                            "current state is unknown; page-dependent recovery suppressed",
                            FailureKind.VERIFICATION_UNAVAILABLE, tuple(recovery_results),
                            interruptions=interruption_results, verification=verified,
                        )
                    recovery_result = self._run_step(recovery_step)
                    recovery_results.append(recovery_result)
                    recovery_ok = recovery_ok and recovery_result.successful
                    if not recovery_ok:
                        break
                if not recovery_ok:
                    return self._finish_step(
                        step,
                        OutcomeStatus.FINAL_FAILURE,
                        tuple(attempts),
                        started,
                        "recovery failed",
                        FailureKind.RECOVERY_FAILED,
                        tuple(recovery_results),
                        interruptions=interruption_results,
                    )

            if attempt_number > 1:
                try:
                    baseline = self._observe_step_baseline(
                        step,
                        f"{step.step_id}:attempt-{attempt_number}-baseline",
                        scan_interruptions=scan_interruptions,
                    )
                except Exception as exc:
                    last_resolution_detail = f"observation failed: {type(exc).__name__}: {exc}"
                    continue
                if scan_interruptions:
                    sweep = self._interruptions.sweep(
                        baseline,
                        f"{step.step_id}:attempt-{attempt_number}",
                    )
                    interruption_results += sweep.results
                    for interruption in sweep.results:
                        self._emit(
                            "interruption_finished",
                            {"step_id": step.step_id, "result": interruption},
                        )
                    if sweep.blocked:
                        return self._finish_step(
                            step,
                            OutcomeStatus.FINAL_FAILURE,
                            tuple(attempts),
                            started,
                            sweep.results[-1].detail,
                            FailureKind.INTERRUPTION_BLOCKED,
                            tuple(recovery_results),
                            interruption_results,
                        )
                    baseline = sweep.observation

                recovery_verification = self._condition_now(step, baseline, baseline)
                if (
                    step.success.kind is not ConditionKind.TRUE
                    and recovery_verification.status is ConditionStatus.MATCHED
                ):
                    return self._finish_successful_step(
                        step,
                        OutcomeStatus.SUCCESS,
                        tuple(attempts),
                        started,
                        "postcondition became satisfied during recovery",
                        recovery_results=tuple(recovery_results),
                        interruptions=interruption_results,
                        verification=recovery_verification,
                    )

            resolution = self._resolver.resolve(
                step.semantic_action,
                self._binding,
                self._adapter.capabilities,
                baseline,
            )
            last_resolution_detail = "; ".join((*resolution.unavailable, *resolution.ambiguous))
            if not resolution.resolved:
                break
            resolved = resolution.resolved[strategy_cursor % len(resolution.resolved)]
            strategy_cursor += 1
            attempt, wait_interruptions, interruption_blocked = self._execute_attempt(
                step,
                resolved,
                baseline,
                attempt_number,
                scan_interruptions=scan_interruptions,
            )
            attempts.append(attempt)
            interruption_results += wait_interruptions
            for interruption in wait_interruptions:
                self._emit(
                    "interruption_finished",
                    {"step_id": step.step_id, "result": interruption},
                )
            if interruption_blocked:
                return self._finish_step(
                    step,
                    OutcomeStatus.FINAL_FAILURE,
                    tuple(attempts),
                    started,
                    attempt.detail,
                    FailureKind.INTERRUPTION_BLOCKED,
                    tuple(recovery_results),
                    interruption_results,
                )
            if attempt.outcome is OutcomeStatus.SUCCESS:
                return self._finish_successful_step(
                    step,
                    OutcomeStatus.SUCCESS,
                    tuple(attempts),
                    started,
                    "postcondition satisfied",
                    recovery_results=tuple(recovery_results),
                    interruptions=interruption_results,
                )
            if (
                resolved.strategy.idempotency is Idempotency.NON_IDEMPOTENT
                and attempt.command is not None
                and attempt.command.status
                in (CommandStatus.ACCEPTED, CommandStatus.TIMEOUT, CommandStatus.UNKNOWN)
                and attempt.command.evidence.get("effect_started") is not False
            ):
                if (
                    step.safe_retry_after_recovery
                    and attempt_number < step.retry.max_attempts
                ):
                    continue
                return self._finish_step(
                    step,
                    OutcomeStatus.UNKNOWN,
                    tuple(attempts),
                    started,
                    "non-idempotent action outcome is uncertain; retry suppressed",
                    FailureKind.COMMAND_UNCERTAIN,
                    tuple(recovery_results),
                    interruptions=interruption_results,
                )

        if not attempts:
            failure = FailureKind.AMBIGUOUS_TARGET if "differ by" in last_resolution_detail else FailureKind.NO_STRATEGY
            outcome = OutcomeStatus.UNSUPPORTED if failure is FailureKind.NO_STRATEGY else OutcomeStatus.FINAL_FAILURE
            return self._finish_step(
                step,
                outcome,
                (),
                started,
                last_resolution_detail or "no executable strategy",
                failure,
                tuple(recovery_results),
                interruptions=interruption_results,
            )
        last = attempts[-1]
        if last.outcome is OutcomeStatus.UNKNOWN:
            return self._finish_step(
                step,
                OutcomeStatus.UNKNOWN,
                tuple(attempts),
                started,
                last.detail,
                FailureKind.VERIFICATION_UNAVAILABLE,
                tuple(recovery_results),
                interruptions=interruption_results,
            )
        failure = (
            FailureKind.COMMAND_REJECTED
            if last.command and last.command.status is CommandStatus.REJECTED
            else FailureKind.TRANSITION_TIMEOUT
        )
        return self._finish_step(
            step,
            OutcomeStatus.FINAL_FAILURE,
            tuple(attempts),
            started,
            last.detail,
            failure,
            tuple(recovery_results),
            interruptions=interruption_results,
        )

    def _execute_attempt(
        self,
        step: Step,
        resolved: ResolvedStrategy,
        baseline: Observation,
        attempt_number: int,
        *,
        scan_interruptions: bool,
    ) -> tuple[AttemptResult, tuple[InterruptionResult, ...], bool]:
        started = self._clock.monotonic()
        strategy = resolved.strategy
        parameters = {**strategy.parameters, **step.parameters}
        try:
            command = self._dispatch(resolved, parameters)
        except Exception as exc:
            command = CommandResult(
                CommandStatus.UNKNOWN,
                strategy.method,
                strategy.strategy_id,
                f"adapter raised {type(exc).__name__}: {exc}",
            )
        self._broker.invalidate()
        self._emit(
            "command_finished",
            {"step_id": step.step_id, "attempt": attempt_number, "command": command},
        )

        effect_definitely_not_started = command.evidence.get("effect_started") is False
        if command.status in (CommandStatus.REJECTED, CommandStatus.UNSUPPORTED) or (
            command.status in (CommandStatus.TIMEOUT, CommandStatus.UNKNOWN)
            and effect_definitely_not_started
        ):
            current = self._safe_observe(step, f"{step.step_id}:rejected-check")
            condition = self._condition_now(step, current, baseline) if current else None
            if condition and condition.status is ConditionStatus.MATCHED:
                outcome = OutcomeStatus.SUCCESS
                detail = "postcondition satisfied despite rejected command report"
            elif condition is None or condition.status is ConditionStatus.UNKNOWN:
                outcome = OutcomeStatus.UNKNOWN
                detail = "command effect did not start and postcondition could not be verified"
            else:
                outcome = OutcomeStatus.RETRYABLE_FAILURE
                detail = command.detail or command.status.value
            return (
                AttemptResult(
                    attempt_number,
                    strategy.strategy_id,
                    command,
                    condition,
                    outcome,
                    detail,
                    started,
                    self._clock.monotonic(),
                ),
                (),
                False,
            )

        waited = self._waiter.wait(
            step.success,
            baseline,
            step.wait,
            f"{step.step_id}:postcondition",
            additional_signals=self._step_signals(
                step,
                scan_interruptions=scan_interruptions,
                include_action_targets=False,
            ),
            interruption_handler=(
                self._interruptions.sweep if scan_interruptions else None
            ),
        )
        wait_interruptions = waited.interruptions
        reconciled = False
        if (
            not waited.interruption_blocked
            and
            waited.condition.status is not ConditionStatus.MATCHED
            and (
                command.status in (CommandStatus.TIMEOUT, CommandStatus.UNKNOWN)
                or strategy.idempotency is Idempotency.NON_IDEMPOTENT
            )
            and self._uncertain_reconcile_seconds > 0
        ):
            reconcile_policy = replace(
                step.wait,
                timeout_seconds=self._uncertain_reconcile_seconds,
                initial_grace_seconds=0,
            )
            waited = self._waiter.wait(
                step.success,
                baseline,
                reconcile_policy,
                f"{step.step_id}:reconcile",
                additional_signals=self._step_signals(
                    step,
                    scan_interruptions=scan_interruptions,
                    include_action_targets=False,
                ),
                interruption_handler=(
                    self._interruptions.sweep if scan_interruptions else None
                ),
            )
            wait_interruptions += waited.interruptions
            reconciled = True

        matched = waited.condition.status is ConditionStatus.MATCHED
        outcome = (
            OutcomeStatus.FINAL_FAILURE
            if waited.interruption_blocked
            else (
                OutcomeStatus.SUCCESS
                if matched
                else (
                    OutcomeStatus.UNKNOWN
                    if waited.condition.status is ConditionStatus.UNKNOWN
                    else OutcomeStatus.RETRYABLE_FAILURE
                )
            )
        )
        detail = (
            waited.condition.detail
            if waited.interruption_blocked
            else (
                "postcondition satisfied"
                if matched
                else f"postcondition not satisfied after {waited.polls} polls"
            )
        )
        return (
            AttemptResult(
                attempt_number,
                strategy.strategy_id,
                command,
                waited.condition,
                outcome,
                detail,
                started,
                self._clock.monotonic(),
                reconciled,
                {"polls": waited.polls, "observation_errors": waited.errors},
            ),
            wait_interruptions,
            waited.interruption_blocked,
        )

    def _dispatch(
        self,
        resolved: ResolvedStrategy,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        strategy = resolved.strategy
        if strategy.method is ActionMethod.DIRECT:
            return self._adapter.execute_direct(strategy.capability or "", parameters)
        if strategy.method is ActionMethod.ELEMENT:
            if resolved.element is not None:
                return self._adapter.activate_element(resolved.element, parameters)
            if strategy.capability:
                return self._adapter.execute_element(strategy.capability, parameters)
            raise ValueError("resolved element strategy has neither element nor capability")
        if strategy.method is ActionMethod.GESTURE:
            return self._adapter.execute_gesture(strategy.capability or "", parameters)
        return self._adapter.execute_visual(strategy.capability or "", parameters)

    def _safe_observe(self, step: Step, reason: str) -> Observation | None:
        try:
            return self._observe_step_baseline(
                step,
                reason,
                scan_interruptions=False,
            )
        except Exception:
            return None

    def _observe_step_baseline(
        self,
        step: Step,
        reason: str,
        *,
        scan_interruptions: bool,
    ) -> Observation:
        needs_success = step.skip_if_satisfied or requires_baseline_observation(step.success)
        signals = self._step_signals(step, scan_interruptions=scan_interruptions)
        if step.skip_when is None and needs_success and self._broker.can_native_observe(step.success):
            return self._broker.observe_for_condition(
                step.wait.observation_level,
                reason,
                step.success,
                fresh=True,
                additional_signals=signals,
            )
        return self._broker.observe(
            step.wait.observation_level,
            reason,
            fresh=True,
            signals=signals,
        )

    def _step_signals(
        self,
        step: Step,
        *,
        scan_interruptions: bool = True,
        include_action_targets: bool = True,
    ) -> frozenset[str]:
        signals = set(step.observation_signals)
        if step.skip_when is not None:
            signals.update(required_observation_signals(step.skip_when))
        if (
            step.skip_if_satisfied or requires_baseline_observation(step.success)
        ) and not self._broker.can_native_observe(step.success):
            signals.update(required_observation_signals(step.success))
        if scan_interruptions:
            signals.add("blocker")
            if any(rule.applies_to(step.step_id) for rule in self._binding.interruptions):
                signals.add("ui")
        if include_action_targets and step.semantic_action:
            action = self._binding.actions.get(step.semantic_action)
            if action and any(
                strategy.method is ActionMethod.ELEMENT and not strategy.capability
                for strategy in action.strategies
            ):
                signals.add("ui")
        return frozenset(signals)

    def _condition_now(
        self,
        step: Step,
        current: Observation,
        baseline: Observation | None,
    ) -> ConditionResult:
        return self._waiter.evaluate_now(step.success, current, baseline)

    def _finish_successful_step(
        self,
        step: Step,
        outcome: OutcomeStatus,
        attempts: tuple[AttemptResult, ...],
        started: float,
        detail: str,
        recovery_results: tuple[StepResult, ...] = (),
        interruptions: tuple[InterruptionResult, ...] = (),
        verification: ConditionResult | None = None,
    ) -> StepResult:
        if step.sustain is None:
            return self._finish_step(
                step,
                outcome,
                attempts,
                started,
                detail,
                recovery_results=recovery_results,
                interruptions=interruptions,
                verification=verification,
            )
        sustained, sustained_recovery, sustained_interruptions, failure_kind = (
            self._sustain_step(step)
        )
        final_outcome = (
            OutcomeStatus.SUCCESS
            if sustained.outcome is OutcomeStatus.SUCCESS
            else sustained.outcome
        )
        return self._finish_step(
            step,
            final_outcome,
            attempts,
            started,
            sustained.detail,
            failure_kind,
            (*recovery_results, *sustained_recovery),
            (*interruptions, *sustained_interruptions),
            verification,
            sustained,
        )

    def _sustain_step(
        self,
        step: Step,
    ) -> tuple[
        SustainResult,
        tuple[StepResult, ...],
        tuple[InterruptionResult, ...],
        FailureKind | None,
    ]:
        policy = step.sustain
        if policy is None:
            raise ValueError("sustain policy is required")
        started = self._clock.monotonic()
        budget_started = (
            self._playbook_started
            if policy.count_from_playbook_start and self._playbook_started is not None
            else started
        )
        deadline = budget_started + policy.duration_seconds
        checks = 0
        recoveries = 0
        consecutive_misses = 0
        consecutive_activity_failures = 0
        errors: list[str] = []
        recovery_results: list[StepResult] = []
        interruption_results: list[InterruptionResult] = []
        activity_results: list[ActivityResult] = []
        activity_index = 0
        deferred_activity_index: int | None = None
        next_activity_at = (
            started
            + (
                policy.activities[0].delay_after_previous_seconds
                if policy.activities[0].delay_after_previous_seconds is not None
                else policy.activities[0].at_seconds
            )
            if policy.activities
            else None
        )
        last_condition: ConditionResult | None = None
        self._emit(
            "sustain_started",
            {
                "step_id": step.step_id,
                "duration_seconds": policy.duration_seconds,
                "budget_origin": (
                    "playbook_start"
                    if policy.count_from_playbook_start
                    else "sustain_start"
                ),
                "budget_elapsed_before_sustain_seconds": round(
                    max(0.0, started - budget_started),
                    6,
                ),
            },
        )

        while True:
            try:
                observation = self._broker.observe_for_condition(
                    step.wait.observation_level,
                    f"{step.step_id}:sustain",
                    step.success,
                    fresh=True,
                    additional_signals=self._step_signals(step),
                )
                checks += 1
                sweep = self._interruptions.sweep(observation, f"{step.step_id}:sustain")
                interruption_results.extend(sweep.results)
                for interruption in sweep.results:
                    self._emit(
                        "interruption_finished",
                        {"step_id": step.step_id, "result": interruption},
                    )
                if sweep.blocked:
                    last_condition = ConditionResult(
                        ConditionStatus.UNKNOWN,
                        sweep.results[-1].detail,
                    )
                    return self._finish_sustain(
                        step,
                        OutcomeStatus.FINAL_FAILURE,
                        started,
                        checks,
                        recoveries,
                        "sustained verification was blocked by an interruption",
                        last_condition,
                        errors,
                        recovery_results,
                        interruption_results,
                        activity_results,
                        FailureKind.INTERRUPTION_BLOCKED,
                    )
                last_condition = self._waiter.evaluate_now(
                    step.success,
                    sweep.observation,
                    None,
                )
                self._emit("sustain_check", {
                    "step_id": step.step_id,
                    "check_index": checks,
                    "observed_at": sweep.observation.observed_at,
                    "condition": last_condition,
                })
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                last_condition = ConditionResult(
                    ConditionStatus.UNKNOWN,
                    "sustained observation failed",
                )

            if last_condition.status is ConditionStatus.MATCHED:
                consecutive_misses = 0
            else:
                consecutive_misses += 1

            if consecutive_misses >= policy.max_consecutive_misses:
                if step.recovery and recoveries < policy.max_recoveries:
                    recoveries += 1
                    recovery_ok = True
                    for recovery_step in step.recovery:
                        recovery_result = self._run_step(recovery_step)
                        recovery_results.append(recovery_result)
                        recovery_ok = recovery_ok and recovery_result.successful
                    if not recovery_ok:
                        return self._finish_sustain(
                            step,
                            OutcomeStatus.FINAL_FAILURE,
                            started,
                            checks,
                            recoveries,
                            "sustained-state recovery failed",
                            last_condition,
                            errors,
                            recovery_results,
                            interruption_results,
                            activity_results,
                            FailureKind.RECOVERY_FAILED,
                        )
                    consecutive_misses = 0
                else:
                    uncertain = last_condition.status is ConditionStatus.UNKNOWN
                    return self._finish_sustain(
                        step,
                        OutcomeStatus.UNKNOWN if uncertain else OutcomeStatus.FINAL_FAILURE,
                        started,
                        checks,
                        recoveries,
                        "sustained state could not be verified"
                        if uncertain
                        else "sustained state was lost",
                        last_condition,
                        errors,
                        recovery_results,
                        interruption_results,
                        activity_results,
                        (
                            FailureKind.VERIFICATION_UNAVAILABLE
                            if uncertain
                            else FailureKind.SUSTAINMENT_FAILED
                        ),
                    )

            now = self._clock.monotonic()
            if (
                last_condition.status is ConditionStatus.MATCHED
                and
                activity_index < len(policy.activities)
                and next_activity_at is not None
                # A fresh observation may finish just beyond the deadline.
                # Complete work already due within the budget before reporting
                # success; relative activities newly due after it remain omitted.
                and next_activity_at < deadline
                and now >= next_activity_at
            ):
                activity = policy.activities[activity_index]
                if activity.guard is not None:
                    try:
                        guard_observation = self._broker.observe_for_condition(
                            step.wait.observation_level,
                            f"{step.step_id}:activity-guard:{activity.label}",
                            activity.guard,
                            fresh=True,
                        )
                        guard_result = self._waiter.evaluate_now(
                            activity.guard,
                            guard_observation,
                            None,
                        )
                    except Exception as exc:
                        errors.append(f"activity guard {activity.label}: {type(exc).__name__}: {exc}")
                        guard_result = ConditionResult(
                            ConditionStatus.UNKNOWN,
                            "scheduled activity guard observation failed",
                        )
                    if guard_result.status is not ConditionStatus.MATCHED:
                        if deferred_activity_index != activity_index:
                            self._emit(
                                "activity_deferred",
                                {
                                    "step_id": step.step_id,
                                    "label": activity.label,
                                    "planned_at_seconds": activity.at_seconds,
                                    "guard": guard_result,
                                },
                            )
                            deferred_activity_index = activity_index
                        next_activity_at = min(
                            deadline,
                            now + policy.poll_interval_seconds,
                        )
                        self._clock.sleep(
                            min(
                                policy.poll_interval_seconds,
                                max(0.0, next_activity_at - now),
                            )
                        )
                        continue
                deferred_activity_index = None
                activity_index += 1
                activity_started = self._clock.monotonic()
                self._emit(
                    "activity_started",
                    {
                        "step_id": step.step_id,
                        "label": activity.label,
                        "planned_at_seconds": activity.at_seconds,
                    },
                )
                executed: list[StepResult] = []
                for activity_step in activity.steps:
                    activity_step_result = self._run_step(activity_step)
                    executed.append(activity_step_result)
                    if not activity_step_result.successful:
                        break
                activity_outcome = (
                    OutcomeStatus.SUCCESS
                    if len(executed) == len(activity.steps)
                    and all(item.successful for item in executed)
                    else OutcomeStatus.FINAL_FAILURE
                )
                activity_result = ActivityResult(
                    activity.label,
                    activity.at_seconds,
                    activity_started,
                    self._clock.monotonic(),
                    activity_outcome,
                    tuple(executed),
                )
                activity_results.append(activity_result)
                if activity_index < len(policy.activities):
                    next_activity = policy.activities[activity_index]
                    next_activity_at = (
                        activity_result.finished_at
                        + next_activity.delay_after_previous_seconds
                        if next_activity.delay_after_previous_seconds is not None
                        else started + next_activity.at_seconds
                    )
                else:
                    next_activity_at = None
                self._emit(
                    "activity_finished",
                    {
                        "step_id": step.step_id,
                        "result": activity_result,
                    },
                )
                if not activity_result.successful:
                    consecutive_activity_failures += 1
                    if (
                        consecutive_activity_failures
                        > policy.max_consecutive_activity_failures
                    ):
                        return self._finish_sustain(
                            step,
                            OutcomeStatus.FINAL_FAILURE,
                            started,
                            checks,
                            recoveries,
                            f"scheduled activity {activity.label!r} failed",
                            last_condition,
                            errors,
                            recovery_results,
                            interruption_results,
                            activity_results,
                            FailureKind.ACTIVITY_FAILED,
                        )
                    self._emit(
                        "activity_failure_tolerated",
                        {
                            "step_id": step.step_id,
                            "label": activity.label,
                            "consecutive_failures": consecutive_activity_failures,
                            "limit": policy.max_consecutive_activity_failures,
                        },
                    )
                    continue
                consecutive_activity_failures = 0
                consecutive_misses = 0
                continue
            if now >= deadline and last_condition.status is ConditionStatus.MATCHED:
                return self._finish_sustain(
                    step,
                    OutcomeStatus.SUCCESS,
                    started,
                    checks,
                    recoveries,
                    "sustained state verified for the requested interval",
                    last_condition,
                    errors,
                    recovery_results,
                    interruption_results,
                    activity_results,
                    None,
                )
            next_deadline = deadline
            if next_activity_at is not None:
                next_deadline = min(next_deadline, next_activity_at)
            self._clock.sleep(
                min(policy.poll_interval_seconds, max(0.0, next_deadline - now))
            )

    def _finish_sustain(
        self,
        step: Step,
        outcome: OutcomeStatus,
        started: float,
        checks: int,
        recoveries: int,
        detail: str,
        last_condition: ConditionResult | None,
        errors: list[str],
        recovery_results: list[StepResult],
        interruptions: list[InterruptionResult],
        activities: list[ActivityResult],
        failure_kind: FailureKind | None,
    ) -> tuple[
        SustainResult,
        tuple[StepResult, ...],
        tuple[InterruptionResult, ...],
        FailureKind | None,
    ]:
        result = SustainResult(
            outcome,
            started,
            self._clock.monotonic(),
            checks,
            recoveries,
            detail,
            last_condition,
            tuple(errors),
            tuple(activities),
        )
        self._emit("sustain_finished", {"step_id": step.step_id, "result": result})
        return result, tuple(recovery_results), tuple(interruptions), failure_kind

    def _finish_step(
        self,
        step: Step,
        outcome: OutcomeStatus,
        attempts: tuple[AttemptResult, ...],
        started: float,
        detail: str,
        failure_kind: FailureKind | None = None,
        recovery_results: tuple[StepResult, ...] = (),
        interruptions: tuple[InterruptionResult, ...] = (),
        verification: ConditionResult | None = None,
        sustain: SustainResult | None = None,
    ) -> StepResult:
        result = StepResult(
            step.step_id,
            outcome,
            attempts,
            started,
            self._clock.monotonic(),
            detail,
            failure_kind,
            recovery_results,
            interruptions,
            verification,
            sustain,
        )
        self._emit("step_finished", {"result": result})
        return result

    def _emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        try:
            self._events.emit(event_type, payload)
        except Exception as exc:
            self._event_errors.append(f"{event_type}: {type(exc).__name__}: {exc}")
