"""Generic app lifecycle smoke used to verify bottom-layer control."""

from __future__ import annotations

from ..binding import ActionBinding, ActionStrategy, AppBinding
from ..condition import Condition, ConditionKind
from ..playbook import Playbook, RetryPolicy, Step, WaitPolicy
from ..status import ActionMethod, Idempotency, ObservationLevel, Platform


def build_lifecycle_binding(platform: Platform, app_id: str) -> AppBinding:
    state_setting = Idempotency.STATE_SETTING
    return AppBinding(
        f"{platform.value}-app-lifecycle",
        platform,
        app_id,
        actions={
            "launch_app": ActionBinding(
                "launch_app",
                (
                    ActionStrategy(
                        "platform-launch",
                        ActionMethod.DIRECT,
                        state_setting,
                        capability="app.launch",
                    ),
                ),
            ),
            "terminate_app": ActionBinding(
                "terminate_app",
                (
                    ActionStrategy(
                        "platform-terminate",
                        ActionMethod.DIRECT,
                        state_setting,
                        capability="app.terminate",
                    ),
                ),
            ),
        },
    )


def build_lifecycle_smoke(timeout_seconds: float = 8.0) -> Playbook:
    wait = WaitPolicy(
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=0.25,
        observation_level=ObservationLevel.FAST,
    )
    return Playbook(
        "app-lifecycle-smoke",
        1,
        (
            Step(
                "launch-app",
                "launch_app",
                Condition(ConditionKind.APP_FOREGROUND),
                wait=wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
            ),
        ),
        (
            Step(
                "terminate-app",
                "terminate_app",
                Condition(
                    ConditionKind.NOT,
                    children=(Condition(ConditionKind.APP_FOREGROUND),),
                ),
                wait=wait,
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
                bypass_interruptions=True,
            ),
        ),
        metadata={"purpose": "mutating capability smoke"},
    )
