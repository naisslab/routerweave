"""Verified pre-task cleanup through the native recent-apps UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .adapters.android import AndroidAdbAdapter
from .adapters.ios import IosWdaAdapter
from .platform import CommandResult
from .status import CommandStatus, Platform


RECENTS_CLEAR_CAPABILITY = "system.recents.clear"
RECENTS_CLEAR_METHOD = "app_switcher_swipe_up"


def close_android_target_tasks(*, serial: str, target_app_id: str, adapter=None) -> dict:
    """Close only this target's processes and recent tasks after capture ends."""
    adapter = adapter or AndroidAdbAdapter(serial, target_app_id)
    before = adapter.running_app_processes((target_app_id,))
    if before.get(target_app_id):
        adapter.execute_direct("app.terminate", {"app_id": target_app_id})
    tasks = adapter.dismiss_recent_app_tasks((target_app_id,))
    remaining = adapter.running_app_processes((target_app_id,))
    if set(remaining) != {target_app_id} or remaining[target_app_id]:
        raise RuntimeError("Target processes remain after collection cleanup")
    return {"target_app_id": target_app_id, "method": "identity_checked_native_recent_task_removal",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "processes_before": before, "remaining_processes": remaining, **tasks}


def reset_android_experiment_apps(*, serial: str, packages: tuple[str, ...], adapter=None) -> dict:
    """Reset only the registered experiment apps before background preparation."""
    if not serial or not packages:
        raise ValueError("Android reset requires a serial and explicit packages")
    adapter = adapter or AndroidAdbAdapter(serial, packages[0])
    receipts = []
    for package in packages:
        command = adapter.execute_direct("app.terminate", {"app_id": package})
        receipts.append({"package": package, "status": command.status.value})
    # A command receipt alone is insufficient; include colon-suffixed processes.
    remaining = adapter.running_app_processes(packages)
    return {"method": "registered_app_force_stop", "packages": list(packages),
            "remaining_processes": remaining, "commands": receipts,
            "success": set(remaining) == set(packages) and not any(remaining.values())}


@dataclass(frozen=True, slots=True)
class SessionIsolationResult:
    platform: str
    target_app_id: str
    method: str
    success: bool
    command_status: str
    detail: str
    swipes_attempted: int
    remaining_cards: int
    empty_verified: bool
    evidence: Mapping[str, Any] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    preserved_app_labels: tuple[str, ...] = ()
    preservation_verified: bool = False


def clear_recent_app_cards(
    *,
    platform: Platform,
    target_app_id: str,
    serial: str = "",
    wda_url: str = "http://127.0.0.1:8100",
    preserve_app_labels: tuple[str, ...] = (),
    clear_recents: Callable[[], CommandResult] | None = None,
) -> SessionIsolationResult:
    """Dismiss every visible recent-app card with upward swipes.

    This is one device-lifecycle operation. It deliberately does not enumerate
    packages or call Android force-stop/iOS terminate. The task target's old
    card is cleared along with every other card, then the task launches it.
    """

    preserved = tuple(
        dict.fromkeys(str(label).strip() for label in preserve_app_labels if str(label).strip())
    )
    if preserved and platform is not Platform.ANDROID:
        raise ValueError("preserving recent-app cards is supported only on Android")
    if platform is Platform.ANDROID and not serial and clear_recents is None:
        raise ValueError("serial is required for Android recent-app cleanup")

    def default_clear() -> CommandResult:
        adapter = (
            AndroidAdbAdapter(serial, target_app_id)
            if platform is Platform.ANDROID
            else IosWdaAdapter(target_app_id, wda_url=wda_url)
        )
        return adapter.execute_gesture(
            RECENTS_CLEAR_CAPABILITY,
            {"preserve_app_labels": preserved},
        )

    errors: list[str] = []
    try:
        command = (clear_recents or default_clear)()
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        return SessionIsolationResult(
            platform.value,
            target_app_id,
            RECENTS_CLEAR_METHOD,
            False,
            CommandStatus.UNKNOWN.value,
            detail,
            0,
            -1,
            False,
            {},
            (f"recent-app cleanup failed: {detail}",),
            preserved,
            False,
        )

    evidence = dict(command.evidence)
    swipes_attempted = _evidence_int(
        evidence,
        "swipes_attempted",
        default=_evidence_int(evidence, "dismissed_cards", default=0),
    )
    remaining_cards = _evidence_int(evidence, "remaining_cards", default=-1)
    empty_verified = evidence.get("empty_verified") is True and remaining_cards == 0
    preservation_verified = (
        evidence.get("preservation_verified") is True
        if preserved
        else empty_verified
    )
    if command.status is not CommandStatus.ACCEPTED:
        errors.append(
            f"recent-app cleanup was {command.status.value}: {command.detail}"
        )
    if evidence.get("method") != RECENTS_CLEAR_METHOD:
        errors.append("recent-app cleanup did not prove the swipe-up method")
    if preserved:
        if not preservation_verified:
            errors.append("recent-app cleanup did not verify the preservation allowlist")
    elif not empty_verified:
        errors.append("recent-app cleanup did not verify an empty app switcher")
    return SessionIsolationResult(
        platform.value,
        target_app_id,
        RECENTS_CLEAR_METHOD,
        not errors,
        command.status.value,
        command.detail,
        swipes_attempted,
        remaining_cards,
        empty_verified,
        evidence,
        tuple(errors),
        preserved,
        preservation_verified,
    )


def _evidence_int(evidence: Mapping[str, Any], key: str, *, default: int) -> int:
    value = evidence.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
