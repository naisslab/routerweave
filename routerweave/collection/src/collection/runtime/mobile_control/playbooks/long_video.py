"""Platform-neutral long-video playback task composition."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, ScheduledActivity, Step, WaitPolicy
from .common import monitored_state, session_cleanup, session_start, verified_hold
from .human_activity import HumanActivityDecision


@dataclass(frozen=True, slots=True)
class LongVideoTask:
    run_pause_resume: bool = True
    switch_video: bool = True
    leave_app_open: bool = False
    restart_app: bool = False
    transition_timeout_seconds: float = 12.0
    monitor_seconds: float = 0.0
    human_activity: tuple[HumanActivityDecision, ...] = ()

    def validate(self) -> None:
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class LongVideoVerification:
    video_open: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "long_video_player")
    )
    playing: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "long_video_playing")
    )
    paused: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "long_video_paused")
    )
    video_changed: Condition = field(
        default_factory=lambda: Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "video_identity")
    )


@dataclass(frozen=True, slots=True)
class LongVideoPreparation:
    before_enter: tuple[Step, ...] = ()
    before_playing: tuple[Step, ...] = ()
    before_pause: tuple[Step, ...] = ()
    before_resume: tuple[Step, ...] = ()
    before_switch: tuple[Step, ...] = ()
    monitor_recovery: tuple[Step, ...] = ()
    monitor_max_consecutive_misses: int = 10
    monitor_max_recoveries: int = 4
    pause_recovery_action: str | None = None


def build_long_video_playbook(
    task: LongVideoTask,
    verification: LongVideoVerification | None = None,
    preparation: LongVideoPreparation | None = None,
) -> Playbook:
    task.validate()
    verification = verification or LongVideoVerification()
    preparation = preparation or LongVideoPreparation()
    wait = WaitPolicy(timeout_seconds=task.transition_timeout_seconds)
    steps = list(session_start(wait, task.restart_app))
    steps.extend(
        (
            *preparation.before_enter,
            Step("enter-long-video", "enter_long_video", verification.video_open, wait=wait),
            *preparation.before_playing,
            Step("verify-long-video-playing", "ensure_playing", verification.playing, wait=wait),
        )
    )
    if task.run_pause_resume:
        steps.extend(
            (
                *preparation.before_pause,
                Step(
                    "pause-long-video",
                    "ensure_paused",
                    verification.paused,
                    wait=wait,
                    skip_if_satisfied=False,
                ),
                *preparation.before_resume,
                Step(
                    "resume-long-video",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                ),
            )
        )
    if task.switch_video:
        steps.extend(
            (
                *preparation.before_switch,
                Step(
                    "switch-long-video",
                    "switch_long_video",
                    verification.video_changed,
                    wait=wait,
                    retry=RetryPolicy(1),
                    skip_if_satisfied=False,
                ),
                Step("verify-switched-video-playing", "ensure_playing", verification.playing, wait=wait),
            )
        )
    activities = _long_video_activities(
        task.human_activity, verification, wait, preparation.pause_recovery_action,
    )
    steps.extend(
        monitored_state(
            verification.playing,
            wait,
            task.monitor_seconds,
            "ensure_playing",
            activities=activities,
            max_consecutive_misses=preparation.monitor_max_consecutive_misses,
            max_recoveries=preparation.monitor_max_recoveries,
            recovery_steps=preparation.monitor_recovery or None,
        )
    )
    return Playbook(
        "long-video-session",
        1,
        tuple(steps),
        session_cleanup(wait, task.leave_app_open),
        metadata={"task_family": "long_video"},
    )


def _long_video_activities(
    decisions: tuple[HumanActivityDecision, ...],
    verification: LongVideoVerification,
    wait: WaitPolicy,
    pause_recovery_action: str | None = None,
) -> tuple[ScheduledActivity, ...]:
    result: list[ScheduledActivity] = []
    for index, decision in enumerate(decisions, start=1):
        prefix = f"activity-long-video-{index}"
        activity_steps: list[Step] = []
        if decision.label == "pause_resume":
            activity_steps.append(
                Step(
                    f"{prefix}-pause",
                    "ensure_paused",
                    verification.paused,
                    wait=wait,
                    skip_if_satisfied=False,
                )
            )
            if decision.hold_seconds:
                hold = verified_hold(
                    f"{prefix}-human-pause",
                    verification.paused,
                    wait,
                    decision.hold_seconds[0],
                    "ensure_paused",
                )
                if pause_recovery_action:
                    hold = replace(hold, recovery=(Step(
                        f"{prefix}-human-pause-recover", pause_recovery_action,
                        verification.paused, wait=wait, retry=RetryPolicy(1),
                        skip_if_satisfied=False,
                    ),))
                activity_steps.append(hold)
            activity_steps.append(
                Step(
                    f"{prefix}-resume",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                )
            )
        elif decision.label == "switch_video":
            activity_steps.extend(
                (
                    Step(
                        f"{prefix}-switch",
                        "switch_long_video",
                        verification.video_changed,
                        wait=wait,
                        retry=RetryPolicy(1),
                        skip_if_satisfied=False,
                    ),
                    Step(
                        f"{prefix}-verify-playing",
                        "ensure_playing",
                        verification.playing,
                        wait=wait,
                    ),
                )
            )
        elif decision.label != "stay_current_video":
            raise ValueError(f"unsupported long-video activity {decision.label!r}")
        result.append(
            ScheduledActivity(
                decision.at_seconds,
                decision.label,
                tuple(activity_steps),
            )
        )
    return tuple(result)
