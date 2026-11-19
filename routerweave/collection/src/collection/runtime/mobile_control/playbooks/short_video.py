"""Platform-neutral short-video feed task composition."""

from __future__ import annotations

from dataclasses import replace
from dataclasses import dataclass, field

from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, ScheduledActivity, Step, WaitPolicy
from .common import monitored_state, session_cleanup, session_start
from .human_activity import HumanActivityDecision


@dataclass(frozen=True, slots=True)
class ShortVideoTask:
    advances: int = 2
    leave_app_open: bool = False
    restart_app: bool = False
    transition_timeout_seconds: float = 8.0
    monitor_seconds: float = 0.0
    human_activity: tuple[HumanActivityDecision, ...] = ()

    def validate(self) -> None:
        if self.advances < 0:
            raise ValueError("advances cannot be negative")
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class ShortVideoVerification:
    active: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "short_video_active")
    )
    content_allowed: Condition = field(default_factory=Condition.true)
    content_changed: Condition = field(
        default_factory=lambda: Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "video_identity")
    )
    advance_guard: Condition | None = None


@dataclass(frozen=True, slots=True)
class ShortVideoPreparation:
    """Optional platform/app recovery inserted around feed advances."""

    advance_recovery: tuple[Step, ...] = ()
    playback_preparation: tuple[Step, ...] = ()
    advance_retry_attempts: int = 1
    max_consecutive_activity_failures: int = 2
    content_recovery_action: str | None = None
    playback_retry_attempts: int = 2
    max_playback_recoveries: int = 2


def build_short_video_playbook(
    task: ShortVideoTask,
    verification: ShortVideoVerification | None = None,
    preparation: ShortVideoPreparation | None = None,
) -> Playbook:
    task.validate()
    verification = verification or ShortVideoVerification()
    preparation = preparation or ShortVideoPreparation()
    if preparation.advance_retry_attempts < 1:
        raise ValueError("advance retry attempts must be positive")
    if preparation.playback_retry_attempts < 1:
        raise ValueError("playback retry attempts must be positive")
    if preparation.max_playback_recoveries < 0:
        raise ValueError("playback recovery budget cannot be negative")
    if (
        verification.content_allowed.kind is not ConditionKind.TRUE
        and not preparation.content_recovery_action
    ):
        raise ValueError("content verification requires a bounded recovery action")
    wait = WaitPolicy(timeout_seconds=task.transition_timeout_seconds)
    verified_active = _verified_active(verification)
    steps = list(session_start(wait, task.restart_app))
    steps.extend(_prefixed_recovery("initial", preparation.playback_preparation))
    steps.append(
        Step(
            "verify-short-video-active",
            "ensure_video_active",
            verification.active,
            wait=wait,
            retry=RetryPolicy(preparation.playback_retry_attempts),
        )
    )
    steps.extend(
        _content_gate_steps(
            "exclude-disallowed-short-video",
            preparation.content_recovery_action,
            verified_active,
            wait,
        )
    )
    for index in range(task.advances):
        advance_id = f"advance-short-video-{index + 1}"
        if verification.advance_guard is not None:
            steps.append(
                Step(
                    f"verify-short-video-surface-{index + 1}",
                    None,
                    verification.advance_guard,
                    wait=wait,
                )
            )
        steps.extend(
            (
                Step(
                    advance_id,
                    "advance_short_video",
                    verification.content_changed,
                    wait=wait,
                    retry=RetryPolicy(preparation.advance_retry_attempts),
                    recovery=_prefixed_recovery(
                        advance_id,
                        preparation.advance_recovery,
                    ),
                    safe_retry_after_recovery=bool(preparation.advance_recovery),
                    skip_if_satisfied=False,
                ),
                *_prefixed_recovery(advance_id, preparation.playback_preparation),
                Step(
                    f"verify-short-video-active-{index + 1}",
                    "ensure_video_active",
                    verification.active,
                    wait=wait,
                    retry=RetryPolicy(preparation.playback_retry_attempts),
                ),
                *_content_gate_steps(
                    f"exclude-disallowed-short-video-{index + 1}",
                    preparation.content_recovery_action,
                    verified_active,
                    wait,
                ),
            )
        )
    activities = tuple(
        ScheduledActivity(
            decision.at_seconds,
            decision.label,
            (
                Step(
                    f"activity-short-video-{index}-advance",
                    "advance_short_video",
                    verification.content_changed,
                    parameters={
                        "duration_ms": decision.gesture_duration_ms,
                        "x_ratio": decision.x_ratio,
                        "start_y_ratio": decision.start_y_ratio,
                        "end_y_ratio": decision.end_y_ratio,
                        "end_x_delta_px": decision.end_x_delta_px,
                    },
                    wait=replace(
                        wait,
                        initial_grace_seconds=decision.hold_seconds[0],
                    ),
                    retry=RetryPolicy(preparation.advance_retry_attempts),
                    recovery=_prefixed_recovery(
                        f"activity-short-video-{index}-advance",
                        preparation.advance_recovery,
                    ),
                    safe_retry_after_recovery=bool(preparation.advance_recovery),
                    skip_if_satisfied=False,
                ),
                *_prefixed_recovery(f"activity-short-video-{index}", preparation.playback_preparation),
                Step(
                    f"activity-short-video-{index}-verify-active",
                    "ensure_video_active",
                    verification.active,
                    wait=wait,
                    retry=RetryPolicy(preparation.playback_retry_attempts),
                ),
                *_content_gate_steps(
                    f"activity-short-video-{index}-exclude-disallowed",
                    preparation.content_recovery_action,
                    verified_active,
                    wait,
                ),
            ),
            delay_after_previous_seconds=decision.delay_after_previous_seconds,
            guard=verification.advance_guard,
        )
        for index, decision in enumerate(task.human_activity, start=1)
    )
    steps.extend(
        monitored_state(
            verification.active,
            wait,
            task.monitor_seconds,
            "ensure_video_active",
            activities=activities,
            recovery_steps=(
                *_prefixed_recovery("monitor", preparation.playback_preparation),
                Step(
                    "monitor-active-state-recover", "ensure_video_active",
                    verification.active, wait=wait,
                    retry=RetryPolicy(preparation.playback_retry_attempts),
                    skip_if_satisfied=False,
                ),
            ),
            max_consecutive_activity_failures=(
                preparation.max_consecutive_activity_failures
            ),
            max_recoveries=preparation.max_playback_recoveries,
        )
    )
    return Playbook(
        "short-video-session",
        1,
        tuple(steps),
        session_cleanup(wait, task.leave_app_open),
        metadata={"task_family": "short_video"},
    )


def _prefixed_recovery(prefix: str, recovery: tuple[Step, ...]) -> tuple[Step, ...]:
    return tuple(
        replace(step, step_id=f"{prefix}-{step.step_id}")
        for step in recovery
    )


def _verified_active(verification: ShortVideoVerification) -> Condition:
    if verification.content_allowed.kind is ConditionKind.TRUE:
        return verification.active
    return Condition(
        ConditionKind.ALL,
        children=(verification.active, verification.content_allowed),
    )


def _content_gate_steps(
    step_id: str,
    recovery_action: str | None,
    success: Condition,
    wait: WaitPolicy,
) -> tuple[Step, ...]:
    if not recovery_action:
        return ()
    return (
        Step(
            step_id,
            recovery_action,
            success,
            wait=wait,
            retry=RetryPolicy(1),
        ),
    )
