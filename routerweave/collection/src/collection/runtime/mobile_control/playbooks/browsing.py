"""Platform-neutral feed/detail browsing task composition."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, ScheduledActivity, Step, WaitPolicy
from .common import (
    interruption_scan_step,
    monitored_state,
    session_cleanup,
    session_start,
    verified_hold,
)
from .human_activity import HumanActivityDecision


@dataclass(frozen=True, slots=True)
class BrowsingTask:
    detail_visits: int = 1
    feed_scrolls: int = 0
    feed_refreshes: int = 0
    refresh_open_recovery: bool = True
    bidirectional_feed: bool = False
    scroll_detail: bool = True
    leave_app_open: bool = False
    restart_app: bool = False
    transition_timeout_seconds: float = 10.0
    monitor_seconds: float = 0.0
    human_activity: tuple[HumanActivityDecision, ...] = ()
    content_open_attempts: int = 3
    refresh_candidates_on_failure: bool = False

    def validate(self) -> None:
        if type(self.content_open_attempts) is not int or not 1 <= self.content_open_attempts <= 8:
            raise ValueError("content_open_attempts must be 1..8")
        if self.detail_visits < 0:
            raise ValueError("detail_visits cannot be negative")
        if self.feed_scrolls < 0:
            raise ValueError("feed_scrolls cannot be negative")
        if self.feed_refreshes < 0:
            raise ValueError("feed_refreshes cannot be negative")
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class BrowsingVerification:
    feed_ready: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "content_feed")
    )
    feed_progressed: Condition = field(
        default_factory=lambda: Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "feed_identity")
    )
    detail_open: Condition = field(
        default_factory=lambda: Condition(ConditionKind.PAGE_RECOGNIZED, "content_detail")
    )
    detail_progressed: Condition = field(
        default_factory=lambda: Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "detail_identity")
    )
    detail_closed: Condition = field(
        default_factory=lambda: Condition(
            ConditionKind.NOT,
            children=(Condition(ConditionKind.PAGE_RECOGNIZED, "content_detail"),),
        )
    )
    detail_scroll_finished: Condition | None = None


def build_browsing_playbook(
    task: BrowsingTask,
    verification: BrowsingVerification | None = None,
) -> Playbook:
    task.validate()
    verification = verification or BrowsingVerification()
    wait = WaitPolicy(timeout_seconds=task.transition_timeout_seconds)
    steps = list(session_start(wait, task.restart_app))
    steps.append(_ensure_feed_step("verify-content-feed", verification.feed_ready, wait))
    for index in range(task.feed_scrolls):
        suffix = index + 1
        direction = "down" if task.bidirectional_feed and index % 2 else "up"
        steps.append(
            Step(
                f"advance-feed-{suffix}",
                "advance_feed",
                verification.feed_progressed,
                parameters={"direction": direction},
                wait=wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
                recovery=(
                    interruption_scan_step(
                        f"scan-browsing-interruptions-advance-feed-{suffix}",
                        wait,
                    ),
                    Step(
                        f"advance-feed-{suffix}-recover-app",
                        "launch_app",
                        Condition(ConditionKind.APP_FOREGROUND),
                        wait=wait,
                    ),
                ),
            )
        )
    for index in range(task.feed_refreshes):
        suffix = index + 1
        steps.append(
            Step(
                f"refresh-feed-{suffix}",
                "refresh_feed",
                verification.feed_progressed,
                wait=wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
            )
        )
    for index in range(task.detail_visits):
        suffix = index + 1
        steps.append(
            Step(
                f"open-content-{suffix}",
                "open_feed_content",
                verification.detail_open,
                wait=wait,
                retry=RetryPolicy(task.content_open_attempts),
                skip_if_satisfied=False,
                recovery=_open_content_recovery(
                    f"open-content-{suffix}",
                    verification,
                    wait,
                    allow_refresh=(task.refresh_candidates_on_failure or
                                   task.refresh_open_recovery and task.feed_refreshes > 0),
                ),
                safe_retry_after_recovery=True,
            )
        )
        if task.scroll_detail:
            steps.append(
                Step(
                    f"scroll-content-{suffix}",
                    "scroll_content",
                    verification.detail_progressed,
                    wait=wait,
                    retry=RetryPolicy(1),
                    skip_if_satisfied=False,
                    skip_when=verification.detail_scroll_finished,
                )
            )
        steps.append(
            Step(
                f"return-to-feed-{suffix}",
                "return_to_feed",
                verification.detail_closed,
                wait=wait,
                skip_if_satisfied=False,
            )
        )
        steps.append(
            _ensure_feed_step(
                f"restore-content-feed-{suffix}",
                verification.feed_ready,
                wait,
            )
        )
        if index + 1 < task.detail_visits:
            steps.append(
                Step(
                    f"advance-feed-after-detail-{suffix}",
                    "advance_feed",
                    verification.feed_progressed,
                    parameters={"direction": "up"},
                    wait=wait,
                    retry=RetryPolicy(2),
                    skip_if_satisfied=False,
                    recovery=(
                        interruption_scan_step(
                            f"scan-browsing-interruptions-advance-feed-after-detail-{suffix}",
                            wait,
                        ),
                        Step(
                            f"advance-feed-after-detail-{suffix}-recover-app",
                            "launch_app",
                            Condition(ConditionKind.APP_FOREGROUND),
                            wait=wait,
                        ),
                    ),
                )
            )
    activities = _browsing_activities(
        task.human_activity,
        verification,
        wait,
        content_open_attempts=task.content_open_attempts,
        allow_refresh_recovery=(
            task.refresh_candidates_on_failure or
            task.feed_refreshes > 0 and task.refresh_open_recovery
        ),
    )
    steps.extend(
        monitored_state(
            verification.feed_ready,
            wait,
            task.monitor_seconds,
            "launch_app",
            activities=activities,
        )
    )
    return Playbook(
        "browsing-session",
        1,
        tuple(steps),
        session_cleanup(wait, task.leave_app_open),
        metadata={"task_family": "browsing"},
    )


def _browsing_activities(
    decisions: tuple[HumanActivityDecision, ...],
    verification: BrowsingVerification,
    wait: WaitPolicy,
    *,
    allow_refresh_recovery: bool = False,
    content_open_attempts: int = 3,
) -> tuple[ScheduledActivity, ...]:
    result: list[ScheduledActivity] = []
    for index, decision in enumerate(decisions, start=1):
        prefix = f"activity-browsing-{index}"
        activity_steps: list[Step] = []
        if decision.label == "scroll_feed":
            activity_steps.append(
                Step(
                    f"{prefix}-scroll-feed",
                    "advance_feed",
                    verification.feed_progressed,
                    parameters={
                        "duration_ms": decision.gesture_duration_ms,
                        "direction": decision.feed_direction,
                    },
                    wait=wait,
                    retry=RetryPolicy(2),
                    skip_if_satisfied=False,
                )
            )
        elif decision.label.startswith("detail_"):
            activity_steps.extend(
                (
                    Step(
                        f"{prefix}-advance-feed-for-next-content",
                        "advance_feed",
                        verification.feed_progressed,
                        parameters={"direction": decision.feed_direction},
                        wait=wait,
                        retry=RetryPolicy(2),
                        skip_if_satisfied=False,
                    ),
                    Step(
                        f"{prefix}-open-content",
                        "open_feed_content",
                        verification.detail_open,
                        wait=wait,
                        retry=RetryPolicy(content_open_attempts),
                        skip_if_satisfied=False,
                        recovery=_open_content_recovery(
                            f"{prefix}-open-content",
                            verification,
                            wait,
                            allow_refresh=allow_refresh_recovery,
                        ),
                        safe_retry_after_recovery=True,
                    ),
                )
            )
            for hold_index, hold_seconds in enumerate(decision.hold_seconds, start=1):
                activity_steps.append(
                    verified_hold(
                        f"{prefix}-read-{hold_index}",
                        verification.detail_open,
                        wait,
                        hold_seconds,
                        None,
                    )
                )
                if hold_index < len(decision.hold_seconds):
                    activity_steps.append(
                        Step(
                            f"{prefix}-scroll-detail-{hold_index}",
                            "scroll_content",
                            verification.detail_progressed,
                            parameters={"duration_ms": decision.gesture_duration_ms},
                            wait=wait,
                            retry=RetryPolicy(1),
                            skip_if_satisfied=False,
                            skip_when=verification.detail_scroll_finished,
                        )
                    )
            activity_steps.extend(
                (
                    Step(
                        f"{prefix}-return-feed",
                        "return_to_feed",
                        verification.detail_closed,
                        wait=wait,
                        skip_if_satisfied=False,
                    ),
                    _ensure_feed_step(
                        f"{prefix}-verify-feed",
                        verification.feed_ready,
                        wait,
                    ),
                )
            )
        elif decision.label == "refresh_feed":
            activity_steps.append(
                Step(
                    f"{prefix}-refresh-feed",
                    "refresh_feed",
                    verification.feed_progressed,
                    wait=wait,
                    retry=RetryPolicy(2),
                    skip_if_satisfied=False,
                )
            )
        elif decision.label != "read_current_view":
            raise ValueError(f"unsupported browsing activity {decision.label!r}")
        result.append(
            ScheduledActivity(
                decision.at_seconds,
                decision.label,
                tuple(activity_steps),
            )
        )
    return tuple(result)


def _open_content_recovery(
    prefix: str,
    verification: BrowsingVerification,
    wait: WaitPolicy,
    *,
    allow_refresh: bool,
) -> tuple[Step, ...]:
    recovery = [
        interruption_scan_step(
            f"scan-browsing-interruptions-{prefix}",
            wait,
        ),
        Step(
            f"{prefix}-restore-feed",
            "recover_content_feed",
            verification.feed_ready,
            wait=wait,
        ),
        Step(
            f"{prefix}-advance-candidates",
            "advance_feed",
            verification.feed_progressed,
            wait=wait,
            retry=RetryPolicy(2),
            skip_if_satisfied=False,
        ),
    ]
    if allow_refresh:
        recovery.append(
            Step(
                f"{prefix}-refresh-candidates",
                "refresh_feed",
                verification.feed_progressed,
                wait=wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
            )
        )
    return tuple(recovery)


def _ensure_feed_step(step_id: str, condition: Condition, wait: WaitPolicy) -> Step:
    return Step(
        step_id,
        "ensure_content_feed",
        condition,
        wait=wait,
        retry=RetryPolicy(3),
        recovery=(
            interruption_scan_step(
                f"scan-browsing-interruptions-{step_id}",
                wait,
            ),
            Step(
                f"{step_id}-recover-context",
                "recover_content_feed",
                Condition(ConditionKind.APP_FOREGROUND),
                wait=wait,
                skip_if_satisfied=False,
            ),
        ),
    )
