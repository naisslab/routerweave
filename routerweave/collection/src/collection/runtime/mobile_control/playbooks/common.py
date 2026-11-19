"""Shared lifecycle composition for task-family playbooks."""

from __future__ import annotations

from ..condition import Condition, ConditionKind
from ..playbook import RetryPolicy, ScheduledActivity, Step, SustainPolicy, WaitPolicy


def session_start(wait: WaitPolicy, restart_app: bool) -> tuple[Step, ...]:
    steps: list[Step] = []
    if restart_app:
        steps.append(
            Step(
                "reset-app",
                "reset_app",
                Condition(
                    ConditionKind.NOT,
                    children=(Condition(ConditionKind.APP_FOREGROUND),),
                ),
                wait=wait,
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
            )
        )
    steps.append(
        Step(
            "launch-app",
            "launch_app",
            Condition(ConditionKind.APP_FOREGROUND),
            wait=wait,
        )
    )
    return tuple(steps)


def session_cleanup(wait: WaitPolicy, leave_app_open: bool) -> tuple[Step, ...]:
    if leave_app_open:
        return ()
    return (
        Step(
            "terminate-app",
            "terminate_app",
            Condition(
                ConditionKind.NOT,
                children=(Condition(ConditionKind.APP_FOREGROUND),),
            ),
            wait=wait,
            retry=RetryPolicy(1),
            bypass_interruptions=True,
            skip_if_satisfied=False,
        ),
    )


def monitored_state(
    condition: Condition,
    wait: WaitPolicy,
    duration_seconds: float,
    recovery_action: str | None,
    *,
    step_id: str = "monitor-active-state",
    activities: tuple[ScheduledActivity, ...] = (),
    max_consecutive_misses: int = 2,
    max_recoveries: int = 2,
    max_consecutive_activity_failures: int = 0,
    recovery_steps: tuple[Step, ...] | None = None,
    count_from_playbook_start: bool = False,
) -> tuple[Step, ...]:
    """Compose a verified long-running state without using an opaque sleep."""

    if duration_seconds <= 0:
        return ()
    recovery = recovery_steps if recovery_steps is not None else (
        (
            Step(
                f"{step_id}-recover",
                recovery_action,
                condition,
                wait=wait,
                skip_if_satisfied=False,
            ),
        )
        if recovery_action
        else ()
    )
    return (
        Step(
            step_id,
            recovery_action,
            condition,
            wait=wait,
            recovery=recovery,
            sustain=SustainPolicy(
                duration_seconds,
                poll_interval_seconds=min(2.0, max(0.25, duration_seconds / 10.0)),
                max_consecutive_misses=max_consecutive_misses,
                max_recoveries=max_recoveries,
                max_consecutive_activity_failures=max_consecutive_activity_failures,
                activities=activities,
                count_from_playbook_start=count_from_playbook_start,
            ),
        ),
    )


def verified_hold(
    step_id: str,
    condition: Condition,
    wait: WaitPolicy,
    duration_seconds: float,
    recovery_action: str | None,
) -> Step:
    """Hold a human pause/read state while continuing normal verification."""

    steps = monitored_state(
        condition,
        wait,
        duration_seconds,
        recovery_action,
        step_id=step_id,
    )
    if len(steps) != 1:
        raise ValueError("verified hold duration must be positive")
    return steps[0]


def interruption_scan_step(step_id: str, wait: WaitPolicy) -> Step:
    """Request one explicit full UI scan so the gatekeeper can clear blockers.

    Normal actions keep using their cheapest observations. Recovery paths opt
    into the heavier hierarchy only after evidence says the normal path failed.
    """

    return Step(
        step_id,
        None,
        Condition.true(),
        wait=WaitPolicy(
            timeout_seconds=min(wait.timeout_seconds, 4.0),
            poll_interval_seconds=wait.poll_interval_seconds,
            observation_level=wait.observation_level,
        ),
        retry=RetryPolicy(1),
        skip_if_satisfied=False,
        observation_signals=("blocker", "ui"),
    )
