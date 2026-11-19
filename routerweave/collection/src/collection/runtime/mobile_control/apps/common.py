"""Small binding helpers shared by every application family."""

from __future__ import annotations

from ..binding import ActionBinding, ActionStrategy
from typing import Any, Mapping

from ..status import ActionMethod, Idempotency
from ..interruption import InterruptionKind, InterruptionRule
from ..perception import SemanticSelector


def register_android_startup_anr_wait(
    profile: Mapping[str, Any], app_id: str,
    selectors: dict[str, SemanticSelector], rules: list[InterruptionRule],
) -> None:
    """One explicit system-ANR Wait, scoped to this target's launch only."""
    _register_android_anr_wait(profile.get("startup_anr_wait_title"), app_id,
                               selectors, rules, startup_only=True)


def register_android_session_anr_wait(
    profile: Mapping[str, Any], app_id: str,
    selectors: dict[str, SemanticSelector], rules: list[InterruptionRule],
) -> None:
    """One verified system-ANR Wait across the entire target session."""
    _register_android_anr_wait(profile.get("session_anr_wait_title"), app_id,
                               selectors, rules, startup_only=False)


def _register_android_anr_wait(
    title: Any, app_id: str, selectors: dict[str, SemanticSelector],
    rules: list[InterruptionRule], *, startup_only: bool,
) -> None:
    if title is None:
        return
    if not isinstance(title, str) or not title.endswith("没有响应"):
        raise ValueError("ANR wait requires the verified exact target title")
    prefix = "startup_anr" if startup_only else "session_anr"
    selectors[prefix + "_title"] = SemanticSelector(
        resource_ids=("miuix.stub:id/alertTitle",), exact_texts=(title,),
        roles=("textview",), attributes={"package": "android"}, minimum_score=200,
    )
    selectors[prefix + "_wait"] = SemanticSelector(
        exact_texts=("等待",), attributes={"package": "android"}, require_clickable=True,
        resource_ids=() if startup_only else ("android:id/aerr_wait",),
        minimum_score=40 if startup_only else 200,
    )
    rules.append(InterruptionRule(
        "android-startup-anr-wait" if startup_only else "android-session-anr-wait",
        InterruptionKind.BENIGN, prefix + "_title", prefix + "_wait", auto_resolve=True,
        timeout_seconds=30, max_occurrences=1,
        step_ids=("launch-app",) if startup_only else (),
        required_foreground_app_id=app_id,
        occurrence_scope="session" if not startup_only else "step",
    ))


def action(name: str, *strategies: ActionStrategy) -> ActionBinding:
    return ActionBinding(name, tuple(strategies))


def direct(
    strategy_id: str,
    capability: str,
    *,
    idempotency: Idempotency = Idempotency.STATE_SETTING,
    parameters: Mapping[str, Any] | None = None,
) -> ActionStrategy:
    return ActionStrategy(
        strategy_id,
        ActionMethod.DIRECT,
        idempotency,
        capability=capability,
        parameters=dict(parameters or {}),
    )


def gesture(
    strategy_id: str,
    capability: str,
    *,
    idempotency: Idempotency,
    parameters: Mapping[str, Any] | None = None,
) -> ActionStrategy:
    return ActionStrategy(
        strategy_id,
        ActionMethod.GESTURE,
        idempotency,
        capability=capability,
        parameters=dict(parameters or {}),
    )


def element_capability(
    strategy_id: str,
    capability: str,
    *,
    idempotency: Idempotency,
    parameters: Mapping[str, Any] | None = None,
) -> ActionStrategy:
    return ActionStrategy(
        strategy_id,
        ActionMethod.ELEMENT,
        idempotency,
        capability=capability,
        parameters=dict(parameters or {}),
    )


def lifecycle_actions() -> dict[str, ActionBinding]:
    return {
        "reset_app": action("reset_app", direct("terminate-before-session", "app.terminate")),
        "launch_app": action("launch_app", direct("launch-registered-app", "app.launch")),
        "terminate_app": action("terminate_app", direct("terminate-registered-app", "app.terminate")),
    }
