"""Platform-neutral music playback task composition."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, ScheduledActivity, Step, WaitPolicy
from .common import monitored_state, session_cleanup, session_start, verified_hold
from .human_activity import HumanActivityDecision


@dataclass(frozen=True, slots=True)
class MusicTask:
    open_player: bool = True
    run_pause_resume: bool = True
    advance_track: bool = True
    leave_app_open: bool = False
    restart_app: bool = False
    transition_timeout_seconds: float = 10.0
    monitor_seconds: float = 0.0
    human_activity: tuple[HumanActivityDecision, ...] = ()

    def validate(self) -> None:
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class MusicVerification:
    player_ready: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "music_player")
    )
    playing: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "music_playing")
    )
    paused: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "music_paused")
    )
    track_changed: Condition = field(
        default_factory=lambda: Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "track_identity")
    )


def build_music_playbook(
    task: MusicTask,
    verification: MusicVerification | None = None,
) -> Playbook:
    task.validate()
    verification = verification or MusicVerification()
    wait = WaitPolicy(
        timeout_seconds=task.transition_timeout_seconds,
        poll_interval_seconds=0.4,
        consecutive_matches=2,
    )
    steps = list(session_start(wait, task.restart_app))
    if task.open_player:
        steps.append(Step("open-player", "open_music_player", verification.player_ready, wait=wait))
    else:
        steps.append(Step("verify-player-ready", None, verification.player_ready, wait=wait))
    steps.append(
        Step(
            "start-music-playback",
            "start_music_playback",
            verification.playing,
            wait=wait,
        )
    )
    if task.run_pause_resume:
        steps.extend(
            (
                Step(
                    "pause-music",
                    "ensure_paused",
                    verification.paused,
                    wait=wait,
                    skip_if_satisfied=False,
                ),
                Step(
                    "resume-music",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                ),
            )
        )
    if task.advance_track:
        steps.append(
            Step(
                "advance-track",
                "advance_track",
                verification.track_changed,
                wait=wait,
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
            )
        )
    activities = _music_activities(task.human_activity, verification, wait)
    steps.extend(
        monitored_state(
            verification.playing,
            wait,
            task.monitor_seconds,
            "ensure_playing",
            activities=activities,
        )
    )
    return Playbook(
        "music-session",
        1,
        tuple(steps),
        session_cleanup(wait, task.leave_app_open),
        metadata={"task_family": "music"},
    )


def _music_activities(
    decisions: tuple[HumanActivityDecision, ...],
    verification: MusicVerification,
    wait: WaitPolicy,
) -> tuple[ScheduledActivity, ...]:
    result: list[ScheduledActivity] = []
    for index, decision in enumerate(decisions, start=1):
        prefix = f"activity-music-{index}"
        activity_steps: list[Step] = []
        if decision.label == "next_track":
            activity_steps.append(
                Step(
                    f"{prefix}-next-track",
                    "advance_track",
                    verification.track_changed,
                    wait=wait,
                    retry=RetryPolicy(1),
                    skip_if_satisfied=False,
                )
            )
        elif decision.label == "pause_resume":
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
                activity_steps.append(
                    verified_hold(
                        f"{prefix}-human-pause",
                        verification.paused,
                        wait,
                        decision.hold_seconds[0],
                        "ensure_paused",
                    )
                )
            activity_steps.append(
                Step(
                    f"{prefix}-resume",
                    "ensure_playing",
                    verification.playing,
                    wait=wait,
                    skip_if_satisfied=False,
                )
            )
        elif decision.label != "continue_playback":
            raise ValueError(f"unsupported music activity {decision.label!r}")
        result.append(
            ScheduledActivity(
                decision.at_seconds,
                decision.label,
                tuple(activity_steps),
            )
        )
    return tuple(result)
