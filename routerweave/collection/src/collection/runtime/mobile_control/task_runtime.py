"""Platform-neutral task request compilation, execution, and time windows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from collection_core.mobile_windows import network_windows_from_mobile_events
from enum import Enum
import json
from pathlib import Path
import secrets
from typing import Any, Mapping

from .adapters.android import AndroidAdbAdapter
from .adapters.ios import IosWdaAdapter
from .apps import (
    DouyuRoom,
    build_browsing_session,
    build_douyu_live_session,
    build_live_stream_session,
    build_long_video_session,
    build_music_session,
    build_short_video_session,
)
from .binding import AppBinding
from .catalog import MobileAppCatalog
from .cache_cleanup import clear_target_app_cache
from .engine import PlaybookRunner
from .events import CompositeEventSink, EventSink, JsonlEventSink
from .screenshot_evidence import ScreenshotEvidenceSink
from .playbook import Playbook
from .playbooks.human_activity import plan_human_activity
from .result import RunResult
from .session_isolation import clear_recent_app_cards
from .status import Platform


@dataclass(frozen=True, slots=True)
class MobileTaskRequest:
    platform: str
    app_name: str
    timeout_seconds: float = 12.0
    restart_app: bool = True
    leave_app_open: bool = False
    run_pause_resume: bool = True
    advance: bool = False
    advances: int = 0
    detail_visits: int = 0
    feed_scrolls: int = 0
    feed_refreshes: int = 0
    scroll_detail: bool = False
    monitor_seconds: float = 0.0
    room_id: str = ""
    room_anchor: str = ""
    switch_room_id: str = ""
    switch_room_anchor: str = ""
    random_actions: bool = True
    random_seed: int = 0
    browsing_activity_style: str = "standard"
    isolate_other_apps: bool = True
    preserve_recent_app_labels: tuple[str, ...] = ()
    clear_app_cache_before_run: bool = False

    @classmethod
    def from_path(cls, path: str | Path) -> "MobileTaskRequest":
        source = Path(path)
        try:
            payload = json.loads(source.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read mobile task request {source}: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("mobile task request must contain an object")
        if int(payload.get("schema_version", 1)) != 1:
            raise ValueError("unsupported mobile task request schema_version")
        known = {field.name for field in cls.__dataclass_fields__.values()}
        unknown = sorted(set(payload) - known - {"schema_version"})
        if unknown:
            raise ValueError(f"unknown mobile task request fields: {unknown}")
        request = cls(**{key: value for key, value in payload.items() if key in known})
        request.validate()
        return request

    def validate(self) -> None:
        try:
            if Platform(self.platform) not in (Platform.ANDROID, Platform.IOS):
                raise ValueError("not a mobile platform")
        except ValueError as exc:
            raise ValueError("platform must be 'android' or 'ios'") from exc
        if not self.app_name.strip():
            raise ValueError("app_name is required")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.monitor_seconds < 0:
            raise ValueError("monitor_seconds cannot be negative")
        for name in ("advances", "detail_visits", "feed_scrolls", "feed_refreshes"):
            if int(getattr(self, name)) < 0:
                raise ValueError(f"{name} cannot be negative")
        if self.switch_room_id and not self.room_id:
            raise ValueError("switch_room_id requires room_id")
        if int(self.random_seed) < 0:
            raise ValueError("random_seed cannot be negative")
        if self.browsing_activity_style not in {"standard", "rapid_feed"}:
            raise ValueError(
                "browsing_activity_style must be 'standard' or 'rapid_feed'"
            )
        if self.clear_app_cache_before_run and self.platform != Platform.ANDROID.value:
            raise ValueError("clear_app_cache_before_run is supported only on Android")
        if self.preserve_recent_app_labels and self.platform != Platform.ANDROID.value:
            raise ValueError("preserve_recent_app_labels is supported only on Android")
        if any(not str(label).strip() for label in self.preserve_recent_app_labels):
            raise ValueError("preserve_recent_app_labels cannot contain empty labels")


def resolve_mobile_task_request(request: MobileTaskRequest) -> MobileTaskRequest:
    """Resolve one reproducible seed before the task is compiled more than once."""

    request.validate()
    if request.random_actions and request.monitor_seconds > 0 and request.random_seed == 0:
        return replace(request, random_seed=secrets.randbelow(2_147_483_646) + 1)
    return request


def compile_mobile_task(
    request: MobileTaskRequest,
    catalog: MobileAppCatalog | None = None,
) -> tuple[AppBinding, Playbook]:
    request.validate()
    catalog = catalog or MobileAppCatalog.from_repository()
    app = catalog.require(Platform(request.platform), request.app_name)
    profile = catalog.profile(app.platform, app.name)
    ios_browsing_plan = (
        profile.get("ios_browsing_plan", {})
        if app.task_family == "browsing" and app.platform is Platform.IOS
        else {}
    )
    if not isinstance(ios_browsing_plan, Mapping):
        ios_browsing_plan = {}
    human_activity = (
        plan_human_activity(
            app.task_family,
            request.monitor_seconds,
            request.random_seed or 1,
            allow_pause=request.run_pause_resume,
            allow_switch=(
                True
                if app.task_family in {"music", "short_video"}
                else (
                    app.platform is Platform.ANDROID and request.advance
                    if app.task_family == "long_video"
                    else bool(
                        app.task_family == "live_stream"
                        and (
                            (app.name == "douyu" and request.switch_room_id)
                            or (
                                app.platform is Platform.IOS
                                and app.name in {"huya", "twitch"}
                                and request.advance
                            )
                        )
                    )
                )
            ),
            allow_detail=(
                app.platform is Platform.ANDROID
                or ios_browsing_plan.get("detail_entry_enabled") is True
            ),
            allow_detail_scroll=(
                ios_browsing_plan.get("detail_scroll_enabled") is not False
            ),
            allow_feed_refresh=(
                ios_browsing_plan.get("feed_refresh_enabled") is True
            ),
            allow_bidirectional_feed=(
                ios_browsing_plan.get("bidirectional_feed_enabled") is True
            ),
            browsing_activity_style=request.browsing_activity_style,
        )
        if request.random_actions
        else ()
    )
    common = {
        "leave_app_open": request.leave_app_open,
        # App-switcher isolation clears the target's previous card as well as
        # every other card. Do not follow that verified UI cleanup with a
        # redundant force-stop/terminate before launch.
        "restart_app": request.restart_app and not request.isolate_other_apps,
        "transition_timeout_seconds": request.timeout_seconds,
        "monitor_seconds": request.monitor_seconds,
        "human_activity": human_activity,
    }
    if app.task_family == "music":
        return build_music_session(
            app,
            run_pause_resume=request.run_pause_resume,
            advance_track=request.advance,
            **common,
        )
    if app.task_family == "short_video":
        return build_short_video_session(
            app,
            profile=profile,
            advances=request.advances if request.advance else 0,
            **common,
        )
    if app.task_family == "browsing":
        return build_browsing_session(
            app,
            profile,
            detail_visits=request.detail_visits,
            feed_scrolls=request.feed_scrolls,
            feed_refreshes=request.feed_refreshes,
            scroll_detail=request.scroll_detail,
            **common,
        )
    if app.task_family == "long_video":
        return build_long_video_session(
            app,
            profile,
            random_seed=request.random_seed,
            run_pause_resume=request.run_pause_resume,
            switch_video=request.advance,
            feed_scrolls=request.feed_scrolls,
            **common,
        )
    if app.name == "douyu" and (request.room_id or app.platform is Platform.IOS):
        return build_douyu_live_session(
            app.platform,
            DouyuRoom(request.room_id, request.room_anchor) if request.room_id else None,
            (
                DouyuRoom(request.switch_room_id, request.switch_room_anchor)
                if request.switch_room_id and request.advance
                else None
            ),
            run_pause_resume=request.run_pause_resume,
            **common,
        )
    return build_live_stream_session(
        app,
        profile,
        random_seed=request.random_seed,
        run_pause_resume=request.run_pause_resume,
        switch_room=(
            request.advance and not request.random_actions
            if app.platform is Platform.IOS and app.name in {"huya", "twitch"}
            else False
        ),
        **common,
    )


def run_mobile_task(
    request: MobileTaskRequest,
    *,
    out_dir: str | Path,
    serial: str = "",
    udid: str = "",
    wda_url: str = "http://127.0.0.1:8100",
    event_sink: EventSink | None = None,
    session_prepared: bool = False,
    cache_prepared: bool = False,
    network_capture_path: str | Path | None = None,
    adapter_transform=None,
) -> RunResult:
    request = resolve_mobile_task_request(request)
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    catalog = MobileAppCatalog.from_repository()
    binding, playbook = compile_mobile_task(request, catalog)
    registered_app = catalog.require(binding.platform, request.app_name)
    profile = catalog.profile(binding.platform, request.app_name)
    media_cache_paths = tuple(str(path) for path in profile.get("media_cache_paths", ()))
    if request.clear_app_cache_before_run and not cache_prepared:
        cache_cleanup = clear_target_app_cache(
            platform=binding.platform,
            target_app_id=binding.app_id,
            serial=serial,
            relative_paths=media_cache_paths,
        )
        _write_json(destination / "cache_cleanup.json", asdict(cache_cleanup))
        if not cache_cleanup.success:
            raise RuntimeError("target app cache cleanup failed: " + "; ".join(cache_cleanup.errors))
    if request.isolate_other_apps and not session_prepared:
        isolation = clear_recent_app_cards(
            platform=binding.platform,
            target_app_id=binding.app_id,
            serial=serial,
            wda_url=wda_url,
            preserve_app_labels=tuple(request.preserve_recent_app_labels),
        )
        _write_json(destination / "session_isolation.json", asdict(isolation))
        if not isolation.success:
            raise RuntimeError("session isolation failed: " + "; ".join(isolation.errors))
    _write_json(destination / "request.effective.json", {"schema_version": 1, **asdict(request)})
    _write_json(
        destination / "compiled_task.json",
        {
            "binding_id": binding.binding_id,
            "playbook_id": playbook.playbook_id,
            "platform": binding.platform.value,
            "app_id": binding.app_id,
            "task_family": binding.metadata.get("task_family"),
            "steps": [step.step_id for step in playbook.steps],
            "cleanup": [step.step_id for step in playbook.cleanup],
            "random_seed": request.random_seed,
            "human_activity": [
                {
                    "at_seconds": activity.at_seconds,
                    "label": activity.label,
                    "steps": [step.step_id for step in activity.steps],
                }
                for step in playbook.steps
                if step.sustain is not None
                for activity in step.sustain.activities
            ],
        },
    )
    if binding.platform is Platform.ANDROID:
        if not serial:
            raise ValueError("serial is required for an Android mobile task")
        adapter = AndroidAdbAdapter(serial, binding.app_id,
            ui_hierarchy_backend=str(profile.get("ui_hierarchy_backend") or "uiautomator"),
            ui_idle_fallback_backend=str(profile.get("ui_idle_fallback_backend") or ""),
            motion_player_resource_id=str(profile.get("motion_player_resource_id") or ""),
            ui_snapshot_timeout_seconds=profile.get("ui_snapshot_timeout_seconds", 8),
            ui_include_not_important_views=profile.get("ui_include_not_important_views", True))
    else:
        adapter = IosWdaAdapter(
            binding.app_id,
            wda_url=wda_url,
            network_capture_path=network_capture_path,
            blocker_probe_mode=str(
                binding.metadata.get("ios_blocker_probe_mode", "alert_endpoint")
            ),
            udid=udid,
            process_name=registered_app.process_name,
        )
    if adapter_transform is not None:
        adapter = adapter_transform(adapter, binding)
    durable_events = JsonlEventSink(destination / "events.jsonl")
    sinks: list[EventSink] = [durable_events]
    if event_sink is not None:
        sinks.append(event_sink)
    sinks.append(ScreenshotEvidenceSink(destination, adapter.capture_screenshot,
        top_level_steps=frozenset(step.step_id for step in playbook.steps)))
    events: EventSink = CompositeEventSink(*sinks)
    result = PlaybookRunner(adapter, binding, event_sink=events).run(playbook)
    _write_json(destination / "result.json", asdict(result))
    return result


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=_json_default) + "\n",
        encoding="utf-8",
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"cannot serialize {type(value).__name__}")
