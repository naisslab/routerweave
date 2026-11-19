"""Verified pre-task target-app cache cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .adapters.android import AndroidAdbAdapter
from .platform import CommandResult
from .status import CommandStatus, Platform


@dataclass(frozen=True, slots=True)
class AppCacheCleanupResult:
    platform: str
    target_app_id: str
    method: str
    success: bool
    command_status: str
    detail: str
    postcondition_verified: bool
    evidence: Mapping[str, Any]
    errors: tuple[str, ...] = ()


def clear_target_app_cache(
    *,
    platform: Platform,
    target_app_id: str,
    serial: str,
    relative_paths: tuple[str, ...],
    adapter_factory: Callable[[str, str], AndroidAdbAdapter] = AndroidAdbAdapter,
) -> AppCacheCleanupResult:
    if platform is not Platform.ANDROID:
        return AppCacheCleanupResult(
            platform.value,
            target_app_id,
            "unsupported",
            False,
            CommandStatus.UNSUPPORTED.value,
            "pre-task cache clearing is supported only on Android",
            False,
            {},
            ("pre-task cache clearing is supported only on Android",),
        )
    if not serial:
        raise ValueError("serial is required for Android cache cleanup")
    adapter = adapter_factory(serial, target_app_id)
    result: CommandResult = adapter.execute_direct(
        "app.cache.clear",
        {
            "app_id": target_app_id,
            "relative_paths": relative_paths,
        },
    )
    evidence = dict(result.evidence)
    verified = evidence.get("postcondition_verified") is True
    success = result.status is CommandStatus.ACCEPTED and verified
    return AppCacheCleanupResult(
        platform.value,
        target_app_id,
        str(evidence.get("method") or "external_media_cache_paths"),
        success,
        result.status.value,
        result.detail,
        verified,
        evidence,
        () if success else (result.detail,),
    )
