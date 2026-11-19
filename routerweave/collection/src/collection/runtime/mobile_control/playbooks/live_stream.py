"""Platform-neutral live-stream task composition."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, ScheduledActivity, Step, WaitPolicy
from .common import monitored_state, verified_hold
from .human_activity import HumanActivityDecision


@dataclass(frozen=True, slots=True)
class LiveStreamTask:
    """Parameters supplied by an authoring agent, not runtime UI logic."""

    room_query: str | None = None
    run_pause_resume: bool = True
    switch_room: bool = True
    leave_app_open: bool = False
    restart_app: bool = False
    transition_timeout_seconds: float = 8.0
    monitor_seconds: float = 0.0
    human_activity: tuple[HumanActivityDecision, ...] = ()

    def validate(self) -> None:
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class LiveStreamVerification:
    """App/platform evidence contract supplied with the reusable task flow."""

    room_entered: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "live_room")
    )
    active: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "live_active")
    )
    paused: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "stream_paused")
    )
    playing: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "stream_playing")
    )
    room_switched: Condition = field(
        default_factory=lambda: Condition(
            ConditionKind.ELEMENT_TEXT_CHANGED,
            "room_identity",
        )
    )
    monitored_active: Condition | None = None
    pause_hold: Condition | None = None


@dataclass(frozen=True, slots=True)
class LiveStreamPreparation:
    """Small app/platform setup steps inserted around shared task semantics."""

    before_enter: tuple[Step, ...] = ()
    enter_recovery: tuple[Step, ...] = ()
    enter_retry_safe: bool = False
    before_active: tuple[Step, ...] = ()
    active_recovery: tuple[Step, ...] = ()
    before_pause: tuple[Step, ...] = ()
    pause_recovery: tuple[Step, ...] = ()
    before_resume: tuple[Step, ...] = ()
    resume_recovery: tuple[Step, ...] = ()
    before_switch: tuple[Step, ...] = ()
    switch_recovery: tuple[Step, ...] = ()
    before_switched_active: tuple[Step, ...] = ()
    switched_active_recovery: tuple[Step, ...] = ()
    switch_active_retry_alternate_slot: bool = False
    monitor_recovery: tuple[Step, ...] = ()
    monitor_max_consecutive_misses: int = 2
    monitor_max_recoveries: int = 2


def build_live_stream_playbook(
    task: LiveStreamTask,
    verification: LiveStreamVerification | None = None,
    preparation: LiveStreamPreparation | None = None,
) -> Playbook:
    task.validate()
    verification = verification or LiveStreamVerification()
    preparation = preparation or LiveStreamPreparation()
    wait = WaitPolicy(timeout_seconds=task.transition_timeout_seconds)
    steps: list[Step] = []
    if task.restart_app:
        steps.append(
            Step(
                "reset-app",
                "reset_app",
                Condition(
                    ConditionKind.NOT,
                    children=(Condition(ConditionKind.APP_FOREGROUND),),
                ),
                wait=WaitPolicy(timeout_seconds=min(4.0, task.transition_timeout_seconds)),
                retry=RetryPolicy(max_attempts=1),
            )
        )
    steps.extend(
        (
            Step(
                "launch-app",
                "launch_app",
                Condition(ConditionKind.APP_FOREGROUND),
                wait=wait,
            ),
            *preparation.before_enter,
            Step(
                "enter-live-room",
                "enter_live_room",
                verification.room_entered,
                parameters={"room_query": task.room_query} if task.room_query else {},
                wait=wait,
                retry=RetryPolicy(max_attempts=3 if preparation.enter_retry_safe else 2),
                recovery=preparation.enter_recovery,
                safe_retry_after_recovery=preparation.enter_retry_safe,
            ),
            *preparation.before_active,
            Step(
                "verify-live-active",
                "ensure_live_active",
                verification.active,
                wait=wait,
                recovery=preparation.active_recovery,
            ),
        )
    )
    if task.run_pause_resume:
        steps.extend(
            (
                *preparation.before_pause,
                Step(
                    "pause-stream",
                    "ensure_paused",
                    verification.paused,
                    wait=wait,
                    skip_if_satisfied=False,
                    recovery=preparation.pause_recovery,
                ),
                *preparation.before_resume,
                Step(
                    "resume-stream",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                    recovery=preparation.resume_recovery,
                ),
            )
        )
    if task.switch_room:
        steps.extend(
            (
                *preparation.before_switch,
                Step(
                    "switch-live-room",
                    "switch_live_room",
                    verification.room_switched,
                    wait=wait,
                    retry=RetryPolicy(max_attempts=2),
                    skip_if_satisfied=False,
                    recovery=preparation.switch_recovery,
                ),
                *preparation.before_switched_active,
                Step(
                    "verify-switched-live-active",
                    "ensure_live_active",
                    verification.active,
                    wait=wait,
                    recovery=preparation.switched_active_recovery,
                ),
            )
        )
    activities = _live_stream_activities(
        task.human_activity,
        verification,
        preparation,
        wait,
    )
    steps.extend(
        monitored_state(
            verification.monitored_active or verification.active,
            wait,
            task.monitor_seconds,
            "ensure_live_active",
            activities=activities,
            recovery_steps=preparation.monitor_recovery or None,
            max_consecutive_misses=preparation.monitor_max_consecutive_misses,
            max_recoveries=preparation.monitor_max_recoveries,
        )
    )

    cleanup: tuple[Step, ...] = ()
    if not task.leave_app_open:
        cleanup = (
            Step(
                "terminate-app",
                "terminate_app",
                Condition(
                    ConditionKind.NOT,
                    children=(Condition(ConditionKind.APP_FOREGROUND),),
                ),
                wait=WaitPolicy(timeout_seconds=min(4.0, task.transition_timeout_seconds)),
                retry=RetryPolicy(max_attempts=1),
                skip_if_satisfied=False,
                bypass_interruptions=True,
            ),
        )
    return Playbook(
        "live-stream-session",
        1,
        tuple(steps),
        cleanup,
        metadata={"task_family": "live_stream"},
    )


def _live_stream_activities(
    decisions: tuple[HumanActivityDecision, ...],
    verification: LiveStreamVerification,
    preparation: LiveStreamPreparation,
    wait: WaitPolicy,
) -> tuple[ScheduledActivity, ...]:
    result: list[ScheduledActivity] = []
    for index, decision in enumerate(decisions, start=1):
        prefix = f"activity-live-stream-{index}"
        activity_steps: list[Step] = []
        if decision.label == "pause_resume":
            activity_steps.extend(
                _prefixed_steps(f"{prefix}-before-pause", preparation.before_pause)
            )
            activity_steps.append(
                Step(
                    f"{prefix}-pause",
                    "ensure_paused",
                    verification.paused,
                    wait=wait,
                    skip_if_satisfied=False,
                    recovery=_prefixed_steps(
                        f"{prefix}-pause-recovery",
                        preparation.pause_recovery,
                    ),
                )
            )
            if decision.hold_seconds:
                activity_steps.append(
                    verified_hold(
                        f"{prefix}-human-pause",
                        verification.pause_hold or verification.paused,
                        wait,
                        decision.hold_seconds[0],
                        None,
                    )
                )
            activity_steps.extend(
                _prefixed_steps(f"{prefix}-before-resume", preparation.before_resume)
            )
            activity_steps.append(
                Step(
                    f"{prefix}-resume",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                    recovery=_prefixed_steps(
                        f"{prefix}-resume-recovery",
                        preparation.resume_recovery,
                    ),
                )
            )
        elif decision.label == "switch_room":
            alternate_x = 0.75 if decision.x_ratio < 0.5 else 0.25
            switched_active_recovery = _prefixed_steps(
                f"{prefix}-switched-active-recovery",
                preparation.switched_active_recovery,
            )
            if preparation.switch_active_retry_alternate_slot:
                switched_active_recovery = (
                    *_prefixed_steps(
                        f"{prefix}-alternate-before-switch",
                        preparation.before_switch,
                    ),
                    Step(
                        f"{prefix}-alternate-switch-room",
                        "switch_live_room",
                        verification.room_switched,
                        parameters={
                            "x_ratio": alternate_x,
                            "y_ratio": decision.start_y_ratio,
                        },
                        wait=wait,
                        retry=RetryPolicy(2),
                        skip_if_satisfied=False,
                        recovery=_prefixed_steps(
                            f"{prefix}-alternate-switch-recovery",
                            preparation.switch_recovery,
                        ),
                    ),
                )
            switch_recovery = _prefixed_steps(
                f"{prefix}-switch-recovery",
                preparation.switch_recovery,
            )
            if preparation.switch_active_retry_alternate_slot:
                switch_recovery = (
                    *_prefixed_steps(
                        f"{prefix}-failed-switch-return-home",
                        preparation.before_switch,
                    ),
                    Step(
                        f"{prefix}-failed-switch-alternate-room",
                        "switch_live_room",
                        verification.room_switched,
                        parameters={
                            "x_ratio": alternate_x,
                            "y_ratio": decision.start_y_ratio,
                        },
                        wait=wait,
                        retry=RetryPolicy(1),
                        skip_if_satisfied=False,
                    ),
                    Step(
                        f"{prefix}-failed-switch-reconcile",
                        None,
                        Condition.true(),
                        wait=wait,
                        skip_if_satisfied=False,
                    ),
                )
            activity_steps.extend(
                _prefixed_steps(f"{prefix}-before-switch", preparation.before_switch)
            )
            activity_steps.extend(
                (
                    Step(
                        f"{prefix}-switch-room",
                        "switch_live_room",
                        verification.room_switched,
                        parameters={
                            "x_ratio": decision.x_ratio,
                            "y_ratio": decision.start_y_ratio,
                        },
                        wait=wait,
                        retry=RetryPolicy(2),
                        skip_if_satisfied=False,
                        recovery=switch_recovery,
                        safe_retry_after_recovery=(
                            preparation.switch_active_retry_alternate_slot
                        ),
                    ),
                    *_prefixed_steps(
                        f"{prefix}-before-switched-active",
                        preparation.before_switched_active,
                    ),
                    Step(
                        f"{prefix}-verify-active",
                        "ensure_live_active",
                        verification.active,
                        wait=wait,
                        recovery=switched_active_recovery,
                    ),
                )
            )
        elif decision.label != "stay_current_room":
            raise ValueError(f"unsupported live-stream activity {decision.label!r}")
        result.append(
            ScheduledActivity(
                decision.at_seconds,
                decision.label,
                tuple(activity_steps),
            )
        )
    return tuple(result)


def _prefixed_steps(prefix: str, steps: tuple[Step, ...]) -> tuple[Step, ...]:
    return tuple(
        replace(
            step,
            step_id=f"{prefix}-{step.step_id}",
            recovery=_prefixed_steps(f"{prefix}-recovery", step.recovery),
        )
        for step in steps
    )
