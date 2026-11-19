"""Bindings for the shared short-video feed task family."""

from __future__ import annotations

from math import ceil
from typing import Any, Mapping

from ..binding import AppBinding, ElementObservationQuery
from ..catalog import MobileAppCatalog, RegisteredApp
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..playbook import Playbook, RetryPolicy, Step, WaitPolicy
from ..playbooks.short_video import (
    ShortVideoTask,
    ShortVideoPreparation,
    ShortVideoVerification,
    build_short_video_playbook,
)
from ..playbooks.human_activity import HumanActivityDecision
from ..perception import SemanticSelector
from ..status import Idempotency, Platform
from .common import action, direct, gesture, lifecycle_actions


_ANDROID_VIDEO_IDENTITY = {
    "douyin": "com.ss.android.ugc.aweme:id/title",
    "kuaishou": "com.kuaishou.nebula:id/user_name_text_view",
}


def _active_video_condition() -> Condition:
    return Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(
                ConditionKind.ANY,
                children=(
                    Condition(ConditionKind.STATE_EQUALS, "audio.playback", "playing"),
                    Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
                ),
            ),
        ),
    )


def build_short_video_session(
    app: RegisteredApp,
    *,
    profile: Mapping[str, Any] | None = None,
    advances: int = 2,
    leave_app_open: bool = False,
    restart_app: bool = True,
    transition_timeout_seconds: float = 8.0,
    monitor_seconds: float = 0.0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
) -> tuple[AppBinding, Playbook]:
    if app.task_family != "short_video":
        raise ValueError(f"{app.name!r} is not a short-video application")
    if app.platform is Platform.IOS:
        return _build_ios_short_video_session(
            app,
            profile=profile,
            advances=advances,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        )
    if app.platform is not Platform.ANDROID:
        raise NotImplementedError(f"unsupported short-video platform {app.platform.value!r}")
    profile = profile or {}
    identity_resource = _ANDROID_VIDEO_IDENTITY.get(app.name, "")
    ad_plan = profile.get("short_video_ad_plan")
    ad_plan = ad_plan if isinstance(ad_plan, Mapping) else {}
    ad_marker_regex = str(ad_plan.get("marker_regex") or "").strip()
    interest_prompt = profile.get("interest_prompt") or {}

    actions = lifecycle_actions()
    ensure_video_strategies = [
        direct(
            "android-input-media-play",
            "media.ensure_playing",
            parameters={"injection": "keyevent"},
        ),
        gesture(
            "relative-player-resume-fallback",
            "screen.tap.relative",
            idempotency=Idempotency.STATE_SETTING,
            parameters={"x_ratio": 0.5, "y_ratio": 0.45},
        ),
    ]
    actions.update(
        {
            "ensure_video_active": action(
                "ensure_video_active",
                *ensure_video_strategies,
            ),
            "advance_short_video": action(
                "advance_short_video",
                gesture(
                    "relative-feed-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"direction": "up", "duration_ms": 350},
                ),
            ),
        }
    )
    if ad_marker_regex:
        actions["skip_disallowed_short_video"] = action(
            "skip_disallowed_short_video",
            gesture(
                "relative-skip-ad-once",
                "screen.swipe.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={"direction": "up", "duration_ms": 350},
            ),
        )
    selectors = (
        {
            "video_identity": SemanticSelector(
                resource_ids=(identity_resource,),
                roles=("textview",),
                text_patterns=(r".+",),
            ),
        }
        if identity_resource
        else {}
    )
    active = _active_video_condition()
    if interest_prompt:
        selectors["short_video_interest_prompt"] = SemanticSelector(
            exact_texts=(str(interest_prompt["title"]),),
            attributes={"package": app.app_id},
            require_enabled=False,
        )
        active = Condition(
            ConditionKind.ALL,
            children=(active, Condition(
                ConditionKind.ELEMENT_ABSENT, "short_video_interest_prompt"
            )),
        )
        # This feed card explicitly offers a swipe to continue. Never tap its
        # preference choices or mistake card animation for video playback.
        actions["ensure_video_active"] = action("ensure_video_active", ensure_video_strategies[0])
        actions["skip_interest_card"] = action(
            "skip_interest_card",
            gesture(
                "skip-verified-interest-card",
                "screen.swipe.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={
                    "direction": "up",
                    "required_visible_texts": (
                        str(interest_prompt["title"]),
                        str(interest_prompt["swipe_hint"]),
                    ),
                },
            ),
        )
    content_allowed = Condition.true()
    if ad_marker_regex:
        selectors["short_video_ad_marker"] = SemanticSelector(
            text_patterns=(ad_marker_regex,),
            require_enabled=False,
        )
        content_allowed = Condition(
            ConditionKind.ELEMENT_ABSENT,
            "short_video_ad_marker",
        )
    binding = AppBinding(
        f"android-{app.name}-short-video",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            **(
                {"ad_policy": "exclude detected ad markers with one bounded feed advance"}
                if ad_marker_regex
                else {}
            ),
        },
    )
    playbook = build_short_video_playbook(
        ShortVideoTask(
            advances=advances,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        ShortVideoVerification(
            active=active,
            content_allowed=content_allowed,
            content_changed=Condition(
                ConditionKind.STATE_CHANGED,
                "visual.frame_fingerprint",
            ),
        ),
        ShortVideoPreparation(
            content_recovery_action="skip_disallowed_short_video" if ad_marker_regex else None,
            playback_preparation=(Step(
                "skip-interest-card", "skip_interest_card", active,
                skip_when=Condition(ConditionKind.ELEMENT_ABSENT, "short_video_interest_prompt"),
                wait=WaitPolicy(timeout_seconds=transition_timeout_seconds),
                retry=RetryPolicy(1),
            ),) if interest_prompt else (),
        ),
    )
    return binding, playbook


def _build_ios_short_video_session(
    app: RegisteredApp,
    *,
    profile: Mapping[str, Any] | None,
    advances: int,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    actions = lifecycle_actions()
    if app.name == "tiktok":
        actions["refresh_short_video_control"] = action(
            "refresh_short_video_control",
            direct("refresh-tiktok-wda-session", "control.session.refresh"),
        )
    actions.update(
        {
            "ensure_video_active": action(
                "ensure_video_active",
                *(
                    (
                        direct(
                            "ios-tiktok-refresh-active-feed",
                            "control.session.refresh",
                        ),
                    )
                    if app.name == "tiktok"
                    else (
                        gesture(
                            "ios-relative-video-resume-fallback",
                            "screen.tap.relative",
                            idempotency=Idempotency.STATE_SETTING,
                            parameters={"x_ratio": 0.5, "y_ratio": 0.45},
                        ),
                    )
                ),
            ),
            "advance_short_video": action(
                "advance_short_video",
                gesture(
                    "ios-relative-feed-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"direction": "up", "duration_ms": 450},
                ),
                *(
                    (
                        gesture(
                            "ios-native-relative-feed-swipe-up",
                            "screen.swipe.relative.native",
                            idempotency=Idempotency.NON_IDEMPOTENT,
                            parameters={"direction": "up", "duration_ms": 450},
                        ),
                    )
                    if app.name == "tiktok"
                    else ()
                ),
            ),
        }
    )
    selectors: dict[str, SemanticSelector] = {}
    element_queries: dict[str, ElementObservationQuery] = {}
    interruption_rules: list[InterruptionRule] = []
    feed_guard = None
    playback_surface_guard = None
    photo_preparation: tuple[Step, ...] = ()
    if app.name == "tiktok":
        profile = profile or MobileAppCatalog.from_repository().profile(app.platform, app.name)
        surface = str(profile.get("native_feed_surface") or "").strip()
        selected_value = str(profile.get("native_feed_selected_value") or "").strip()
        if not surface or not selected_value:
            raise ValueError("TikTok selected recommendation-feed evidence is required")
        selectors["short_video_feed_surface"] = SemanticSelector(
            accessibility_ids=(surface,), roles=("button",),
        )
        escaped_surface = surface.replace("\\", "\\\\").replace("'", "\\'")
        escaped_value = selected_value.replace("\\", "\\\\").replace("'", "\\'")
        element_queries["short_video_feed_surface"] = ElementObservationQuery(
            "observation.element.query",
            {"using": "predicate string", "value":
             f"type == 'XCUIElementTypeButton' AND name == '{escaped_surface}' "
             f"AND value == '{escaped_value}' AND visible == 1",
             "role": "button", "snapshot_max_depth": 15},
        )
        feed_guard = Condition(ConditionKind.ALL, children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "short_video_feed_surface"),
            Condition(ConditionKind.STATE_EQUALS, "visual.content_detail", "loaded"),
        ))
        playback_surface_guard = feed_guard
    if app.name == "douyin":
        profile = profile or MobileAppCatalog.from_repository().profile(app.platform, app.name)
        marker = str(profile.get("native_photo_marker") or "").strip()
        if marker:
            selectors["short_video_photo_marker"] = SemanticSelector(
                accessibility_ids=(marker,), roles=("image",), ambiguity_margin=0,
            )
            escaped = marker.replace("\\", "\\\\").replace("'", "\\'")
            element_queries["short_video_photo_marker"] = ElementObservationQuery(
                "observation.element.query",
                {"using": "predicate string", "value":
                 f"type == 'XCUIElementTypeImage' AND name == '{escaped}' AND visible == 1"},
            )
            no_photo = Condition(ConditionKind.ELEMENT_ABSENT, "short_video_photo_marker")
            playback_surface_guard = no_photo
            actions["skip_photo_card"] = action(
                "skip_photo_card",
                gesture(
                    "ios-skip-verified-photo-card",
                    "screen.swipe.relative.native",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"direction": "up", "duration_ms": 450,
                                "required_visible_names": (marker,)},
                ),
            )
            photo_preparation = (
                Step(
                    "skip-photo-card", "skip_photo_card",
                    Condition(ConditionKind.ALL, children=(
                        Condition(ConditionKind.APP_FOREGROUND), no_photo,
                    )),
                    wait=WaitPolicy(timeout_seconds=transition_timeout_seconds),
                    retry=RetryPolicy(1), skip_when=no_photo,
                ),
            )
    if app.name == "kuaishou":
        profile = profile or MobileAppCatalog.from_repository().profile(app.platform, app.name)
        feed_surface = str(profile.get("native_feed_surface") or "").strip()
        if not feed_surface:
            raise ValueError("iOS short-video feed surface evidence is required")
        selectors["short_video_feed_surface"] = SemanticSelector(
            accessibility_ids=(feed_surface,), roles=("scrollview",),
        )
        feed_guard = Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.ELEMENT_PRESENT, "short_video_feed_surface"),
            ),
        )
        playback_surface_guard = feed_guard
        interest_prompt = profile.get("interest_prompt") or {}
        marker_dependencies = {}
        if interest_prompt:
            selectors["short_video_interest_prompt"] = SemanticSelector(
                exact_texts=(str(interest_prompt["title"]),),
                roles=("statictext",),
            )
            playback_surface_guard = Condition(
                ConditionKind.ALL,
                children=(
                    feed_guard,
                    Condition(ConditionKind.ELEMENT_ABSENT, "short_video_interest_prompt"),
                ),
            )
            marker_dependencies[str(interest_prompt["title"])] = (
                str(interest_prompt["swipe_hint"]),
            )
        # A motion miss does not identify a video surface. A center tap can
        # activate Follow on a profile or a control on an in-app overlay.
        actions["ensure_video_active"] = action(
            "ensure_video_active",
            gesture(
                "ios-skip-inactive-verified-feed",
                "screen.swipe.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={
                    "direction": "up",
                    "required_visible_names": (feed_surface,),
                    "visible_marker_dependencies": marker_dependencies,
                },
            ),
        )
        notification_prompt = profile.get("notification_prompt") or {}
        if notification_prompt:
            selectors["short_video_notification_prompt"] = SemanticSelector(
                exact_texts=(str(notification_prompt["title"]),),
                roles=("statictext",),
            )
            selectors["short_video_notification_ignore"] = SemanticSelector(
                exact_texts=(str(notification_prompt["dismiss"]),),
                roles=("button",), require_clickable=True,
            )
            interruption_rules.append(
                InterruptionRule(
                    "short-video-ignore-notification-prompt",
                    InterruptionKind.BENIGN,
                    "short_video_notification_prompt",
                    "short_video_notification_ignore",
                    auto_resolve=True,
                    max_occurrences=1,
                )
            )
    binding = AppBinding(
        f"ios-{app.name}-short-video",
        app.platform,
        app.app_id,
        selectors=selectors,
        element_queries=element_queries,
        actions=actions,
        interruptions=tuple(interruption_rules),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "binding_source": "existing iOS relative-swipe profiles",
            "verification": "local motion plus local frame change",
            **(
                {"playback_recovery": "control-session refresh with native loaded-feed verification"}
                if app.name == "tiktok"
                else {}
            ),
            **(
                {"ios_blocker_probe_mode": "active_app_guard",
                 "verification_scope": "loaded recommendation-feed viewing; static photo cards allowed; not continuous video playback"}
                if app.name == "tiktok"
                else {}
            ),
        },
    )
    playbook = build_short_video_playbook(
        ShortVideoTask(
            advances=advances,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        ShortVideoVerification(
            active=Condition(
                ConditionKind.ALL,
                children=(
                    Condition(ConditionKind.APP_FOREGROUND),
                    *((playback_surface_guard,) if playback_surface_guard is not None else ()),
                    (
                        Condition(
                            ConditionKind.ANY,
                            children=(
                                Condition(
                                    ConditionKind.STATE_EQUALS,
                                    "motion.playback",
                                    "playing",
                                ),
                                Condition(
                                    ConditionKind.STATE_EQUALS,
                                    "motion.playback",
                                    "paused",
                                ),
                            ),
                        )
                        if app.name == "tiktok"
                        else Condition(
                            ConditionKind.STATE_EQUALS,
                            "motion.playback",
                            "playing",
                        )
                    ),
                ),
            ),
            content_changed=Condition(
                ConditionKind.STATE_CHANGED,
                "visual.frame_fingerprint",
            ),
            advance_guard=feed_guard,
        ),
        (
            ShortVideoPreparation(
                advance_recovery=(
                    Step(
                        "refresh-tiktok-control-session",
                        "refresh_short_video_control",
                        Condition(ConditionKind.APP_FOREGROUND),
                        skip_if_satisfied=False,
                    ),
                    Step(
                        "reassert-tiktok-foreground",
                        "launch_app",
                        Condition(ConditionKind.APP_FOREGROUND),
                        skip_if_satisfied=False,
                    ),
                ),
                advance_retry_attempts=2,
                max_consecutive_activity_failures=6,
            )
            if app.name == "tiktok"
            else (
                ShortVideoPreparation(
                    playback_retry_attempts=1,
                    max_playback_recoveries=min(12, 2 + ceil(monitor_seconds / 300)),
                )
                if app.name == "kuaishou"
                else ShortVideoPreparation(playback_preparation=photo_preparation)
                if photo_preparation else None
            )
        ),
    )
    return binding, playbook
