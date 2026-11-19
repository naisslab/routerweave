"""Shared long-video bindings assembled from existing control evidence."""

from __future__ import annotations

import re
from typing import Any, Mapping

from ..binding import AppBinding, ElementObservationQuery
from ..catalog import RegisteredApp
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..playbook import Playbook, RetryPolicy, Step, WaitPolicy
from ..playbooks.long_video import (
    LongVideoPreparation,
    LongVideoTask,
    LongVideoVerification,
    build_long_video_playbook,
)
from ..playbooks.human_activity import HumanActivityDecision
from ..perception import SemanticSelector
from ..status import Idempotency, ObservationLevel, Platform
from .common import action, direct, element_capability, gesture, lifecycle_actions, register_android_startup_anr_wait


_IOS_CONTROLS = {
    "bilibili": {
        "pause": "bbplayer_halfscreen_pause",
        "play": "bbplayer_halfscreen_play",
    },
    "iqiyi": {
        "pause": "player mini pausebutton iphone",
        "play": "继续播放正片",
    },
    "youtube": {
        "pause": "id.player.pause.button",
        "play": "id.player.play.button",
        "surface": "id.player",
    },
}


def build_long_video_session(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    *,
    run_pause_resume: bool = True,
    switch_video: bool = True,
    leave_app_open: bool = False,
    restart_app: bool = True,
    transition_timeout_seconds: float = 12.0,
    monitor_seconds: float = 0.0,
    feed_scrolls: int = 0,
    random_seed: int = 0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
) -> tuple[AppBinding, Playbook]:
    if app.task_family != "long_video":
        raise ValueError(f"{app.name!r} is not a long-video application")
    if feed_scrolls < 0:
        raise ValueError("feed_scrolls cannot be negative")
    if app.platform is Platform.ANDROID:
        return _build_android(
            app,
            profile,
            run_pause_resume=run_pause_resume,
            switch_video=switch_video,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            random_seed=random_seed,
            human_activity=human_activity,
        )
    if app.platform is Platform.IOS:
        if switch_video:
            raise NotImplementedError(
                f"{app.name!r} iOS video switching has no coordinate-free exit path yet"
            )
        return _build_ios(
            app,
            profile,
            run_pause_resume=run_pause_resume,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            feed_scrolls=feed_scrolls,
            human_activity=human_activity,
        )
    raise NotImplementedError(f"unsupported long-video platform {app.platform.value!r}")


def _build_android(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    **task_parameters: Any,
) -> tuple[AppBinding, Playbook]:
    random_seed = int(task_parameters.pop("random_seed", 0) or 1)
    card = profile.get("long_video_card_plan")
    card_plan = card if isinstance(card, Mapping) else {}
    startup_wait = float(card_plan.get("startup_observation_wait_seconds") or 0)
    observation_wait = float(card_plan.get("observation_wait_seconds") or 0)
    if not 0 <= startup_wait <= 90 or not 0 <= observation_wait <= 90:
        raise ValueError("observation wait must be bounded to 90 seconds")
    ad = profile.get("ad_interruption_plan")
    ad_plan = ad if isinstance(ad, Mapping) else {}
    prompt = profile.get("benign_prompt_plan")
    prompt_plan = prompt if isinstance(prompt, Mapping) else {}
    refresh = profile.get("feed_refresh_plan")
    refresh_plan = refresh if isinstance(refresh, Mapping) else {}
    refresh_enabled = refresh_plan.get("enabled") is True
    reselect = profile.get("completed_video_reselect_plan")
    reselect_plan = reselect if isinstance(reselect, Mapping) else {}
    reselect_enabled = reselect_plan.get("enabled") is True
    player_resource_id = str(card_plan.get("player_resource_id") or "").strip()
    candidate_parameters: dict[str, Any] | None = None
    if card_plan.get("card_include_regex"):
        candidate_parameters = {
            "include_pattern": str(card_plan["card_include_regex"]),
            "exclude_pattern": str(card_plan.get("card_exclude_regex") or ""),
            "role_pattern": str(card_plan.get("card_class_regex") or ""),
            "require_clickable": bool(card_plan.get("card_require_clickable", False)),
            "min_width_ratio": float(
                card_plan.get("card_min_width_ratio")
                or float(card_plan.get("card_min_width") or 0) / 720.0
            ),
            "min_height_ratio": float(
                card_plan.get("card_min_height_ratio")
                or float(card_plan.get("card_min_height") or 0) / 1640.0
            ),
            "max_bottom_ratio": float(card_plan.get("card_max_bottom_ratio") or 1.0),
        }
        selection_policy = str(
            card_plan.get("candidate_selection_policy") or "first_visible"
        ).strip()
        if selection_policy:
            candidate_parameters["selection_policy"] = selection_policy
        if selection_policy == "seeded_random":
            candidate_parameters["selection_seed"] = random_seed
        enter_strategy = element_capability(
            "android-semantic-long-video-card",
            "element.activate.candidate",
            idempotency=Idempotency.NON_IDEMPOTENT,
            parameters=candidate_parameters,
        )
        entry_evidence = "registry semantic duration/card filters"
    else:
        enter_strategy = element_capability(
            "android-duration-title-media-card",
            "element.activate.media_card",
            idempotency=Idempotency.NON_IDEMPOTENT,
            parameters={"minimum_duration_seconds": 60},
        )
        entry_evidence = "generic duration-title relation ported from existing runtime"
    actions = lifecycle_actions()
    resume_existing_player = (
        direct(
            "android-resume-existing-player",
            "media.ensure_playing",
            parameters={"injection": "keyevent"},
        ),
    ) if player_resource_id and not refresh_enabled else ()
    actions.update(
        {
            "enter_long_video": action(
                "enter_long_video",
                *resume_existing_player,
                enter_strategy,
            ),
            "ensure_playing": action(
                "ensure_playing",
                direct(
                    "android-media-keyevent-play",
                    "media.ensure_playing",
                    parameters={"injection": "keyevent"},
                ),
            ),
            "ensure_paused": action(
                "ensure_paused",
                direct(
                    "android-media-keyevent-pause",
                    "media.ensure_paused",
                    parameters={"injection": "keyevent"},
                ),
            ),
            "switch_long_video": action(
                "switch_long_video",
                direct(
                    "android-media-keyevent-next",
                    "media.next",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"injection": "keyevent"},
                ),
            ),
        }
    )
    controls = profile.get("player_control_plan")
    control_plan = controls if isinstance(controls, Mapping) else {}
    control_resource = str(control_plan.get("toggle_resource_id") or "").strip()
    reveal_resource = str(control_plan.get("reveal_resource_id") or "").strip()
    if control_resource and reveal_resource:
        for action_name, label_key in (("ensure_paused", "pause_accessibility_id"),
                                       ("ensure_playing", "play_accessibility_id")):
            label = str(control_plan.get(label_key) or "").strip()
            if not label:
                raise ValueError(f"player_control_plan.{label_key} is required")
            actions[action_name] = action(
                action_name,
                *actions[action_name].strategies,
                element_capability(
                    f"android-native-{action_name}", "element.activate.query",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"resource_id": control_resource, "accessibility_id": label,
                                "reveal_resource_id": reveal_resource},
                ),
            )
        # Human-pause holds use one native recovery attempt. Keeping the
        # direct/element retry pair here would violate the sustain contract.
        actions["recover_long_video_pause"] = action(
            "recover_long_video_pause", actions["ensure_paused"].strategies[-1],
        )
    if refresh_enabled:
        actions["refresh_long_video_feed"] = action(
            "refresh_long_video_feed",
            gesture(
                "android-refresh-long-video-feed",
                "screen.swipe.relative",
                idempotency=Idempotency.REPEATABLE,
                parameters={
                    "direction": "down",
                    "duration_ms": int(refresh_plan.get("duration_ms") or 700),
                },
            ),
        )
    if reselect_enabled:
        if candidate_parameters is None:
            raise ValueError(
                "completed_video_reselect_plan requires semantic long-video cards"
            )
        replacement_parameters = dict(candidate_parameters)
        if replacement_parameters.get("selection_policy") == "seeded_random":
            replacement_parameters["selection_seed"] = random_seed + 1
        actions.update(
            {
                "return_to_long_video_home": action(
                    "return_to_long_video_home",
                    direct(
                        "android-long-video-back-to-home",
                        "navigation.back",
                        idempotency=Idempotency.NON_IDEMPOTENT,
                    ),
                ),
                "advance_long_video_candidates": action(
                    "advance_long_video_candidates",
                    gesture(
                        "android-advance-long-video-feed",
                        "screen.swipe.relative",
                        idempotency=Idempotency.REPEATABLE,
                        parameters={
                            "direction": str(reselect_plan.get("direction") or "up"),
                            "duration_ms": int(reselect_plan.get("duration_ms") or 600),
                        },
                    ),
                ),
                "enter_replacement_long_video": action(
                    "enter_replacement_long_video",
                    element_capability(
                        "android-replacement-long-video-card",
                        "element.activate.candidate",
                        idempotency=Idempotency.NON_IDEMPOTENT,
                        parameters=replacement_parameters,
                    ),
                ),
            }
        )
    selectors: dict[str, SemanticSelector] = {}
    element_queries: dict[str, ElementObservationQuery] = {}
    interruption_rules: list[InterruptionRule] = []
    player_activity = str(card_plan.get("player_activity_contains") or "").strip()
    player_page = Condition(ConditionKind.APP_FOREGROUND)
    if player_activity:
        player_page = Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(
                    ConditionKind.STATE_CONTAINS,
                    "device.foreground_activity_class",
                    player_activity,
                ),
            ),
        )
    if player_resource_id:
        selectors["long_video_player_marker"] = SemanticSelector(
            resource_ids=(player_resource_id,),
        )
        if card_plan.get("player_marker_observation") != "structured":
            element_queries["long_video_player_marker"] = ElementObservationQuery(
                "observation.element.query",
                {"resource_id": player_resource_id},
            )
        player_page = Condition(
            ConditionKind.ALL,
            children=(
                player_page,
                Condition(ConditionKind.ELEMENT_PRESENT, "long_video_player_marker"),
            ),
        )
    refresh_ready = Condition(ConditionKind.TRUE)
    refresh_home_resource = str(refresh_plan.get("home_resource_id") or "").strip()
    if refresh_enabled:
        if not refresh_home_resource:
            raise ValueError("feed_refresh_plan.home_resource_id is required when enabled")
        selectors["long_video_feed_home"] = SemanticSelector(
            resource_ids=(refresh_home_resource,),
        )
        element_queries["long_video_feed_home"] = ElementObservationQuery(
            "observation.element.query",
            {"resource_id": refresh_home_resource},
        )
        refresh_ready = Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.ELEMENT_PRESENT, "long_video_feed_home"),
                Condition(ConditionKind.ELEMENT_ABSENT, "long_video_player_marker"),
            ),
        )
    reselect_home: Condition | None = None
    reselect_home_resource = str(reselect_plan.get("home_resource_id") or "").strip()
    if reselect_enabled:
        if not reselect_home_resource or not player_resource_id:
            raise ValueError(
                "completed_video_reselect_plan requires home_resource_id and player_resource_id"
            )
        selectors["long_video_reselect_home"] = SemanticSelector(
            resource_ids=(reselect_home_resource,),
        )
        reselect_home = Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.ELEMENT_PRESENT, "long_video_reselect_home"),
                Condition(ConditionKind.ELEMENT_ABSENT, "long_video_player_marker"),
            ),
        )
    ad_marker_regex = str(ad_plan.get("marker_regex") or "").strip()
    skip_texts = tuple(
        str(value).strip()
        for value in ad_plan.get("skip_exact_texts", ())
        if str(value).strip()
    )
    skip_text_regex = str(ad_plan.get("skip_text_regex") or "").strip()
    non_ad = Condition(ConditionKind.TRUE)
    if ad_marker_regex:
        selectors["long_video_ad_marker"] = SemanticSelector(
            text_patterns=(ad_marker_regex,),
            require_enabled=False,
        )
        non_ad = Condition(ConditionKind.ELEMENT_ABSENT, "long_video_ad_marker")
    if skip_texts or skip_text_regex:
        selectors["long_video_ad_skip"] = SemanticSelector(
            accessibility_ids=skip_texts,
            exact_texts=skip_texts,
            text_patterns=(skip_text_regex,) if skip_text_regex else (),
            require_clickable=True,
        )
        interruption_rules.append(
            InterruptionRule(
                "long-video-ad-skip",
                InterruptionKind.BENIGN,
                "long_video_ad_skip",
                "long_video_ad_skip",
                auto_resolve=True,
                timeout_seconds=8.0,
                max_occurrences=int(ad_plan.get("max_occurrences") or 4),
            )
        )
    prompt_marker_resource = str(prompt_plan.get("marker_resource_id") or "").strip()
    prompt_dismiss_resource = str(prompt_plan.get("dismiss_resource_id") or "").strip()
    prompt_marker_text = str(prompt_plan.get("marker_exact_text") or "").strip()
    prompt_dismiss_text = str(prompt_plan.get("dismiss_exact_text") or "").strip()
    if (prompt_marker_resource and prompt_dismiss_resource) or (prompt_marker_text and prompt_dismiss_text):
        selectors["long_video_benign_prompt"] = SemanticSelector(
            resource_ids=(prompt_marker_resource,) if prompt_marker_resource else (),
            exact_texts=(prompt_marker_text,) if prompt_marker_text else (),
        )
        selectors["long_video_benign_prompt_dismiss"] = SemanticSelector(
            resource_ids=(prompt_dismiss_resource,) if prompt_dismiss_resource else (),
            exact_texts=(prompt_dismiss_text,) if prompt_dismiss_text else (),
            require_clickable=bool(prompt_dismiss_resource),
        )
        if prompt_marker_resource:
            element_queries["long_video_benign_prompt"] = ElementObservationQuery(
                "observation.element.query", {"resource_id": prompt_marker_resource},
            )
        interruption_rules.append(
            InterruptionRule(
                "long-video-benign-prompt-dismiss",
                InterruptionKind.BENIGN,
                "long_video_benign_prompt",
                "long_video_benign_prompt_dismiss",
                auto_resolve=True,
                timeout_seconds=8.0,
                max_occurrences=int(prompt_plan.get("max_occurrences") or 2),
            )
        )
    register_android_startup_anr_wait(profile, app.app_id, selectors, interruption_rules)
    playback_evidence = str(card_plan.get("playback_evidence") or "").strip()
    if playback_evidence and playback_evidence != "media_session":
        raise ValueError(f"unsupported Android long-video playback evidence {playback_evidence!r}")
    playing_evidence = (
        Condition(ConditionKind.STATE_EQUALS, "media.playback", "playing")
        if playback_evidence == "media_session"
        else Condition(
            ConditionKind.ANY,
            children=(
                Condition(ConditionKind.STATE_EQUALS, "audio.playback", "playing"),
                Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
            ),
        )
    )
    active = Condition(
        ConditionKind.ALL,
        children=(
            player_page,
            non_ad,
            playing_evidence,
        ),
    )
    binding = AppBinding(
        f"android-{app.name}-long-video",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        interruptions=tuple(interruption_rules),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "entry_evidence": entry_evidence,
            "playback_transport": "ADB input keyevent",
            "ad_policy": (
                "wait for detected ads and safely activate an explicit skip control"
                if ad_marker_regex else "no app-specific ad policy"
            ),
            "completed_video_policy": (
                "return to the feed and select another eligible ordinary video"
                if reselect_enabled else "no app-specific completed-video reselection"
            ),
            "playback_evidence": playback_evidence or "audio_or_motion",
            "startup_observation_wait_seconds": startup_wait,
            "observation_wait_seconds": observation_wait,
        },
        element_queries=element_queries,
    )
    verification = LongVideoVerification(
        video_open=active,
        playing=active,
        paused=Condition(
            ConditionKind.ALL,
            children=(
                player_page,
                non_ad,
                Condition(
                    ConditionKind.STATE_EQUALS,
                    "media.playback" if playback_evidence == "media_session" else "audio.playback",
                    "paused" if playback_evidence == "media_session" else "inactive",
                ),
            ),
        ),
        video_changed=Condition(ConditionKind.STATE_CHANGED, "ui.fingerprint"),
    )
    monitor_recovery: tuple[Step, ...] = ()
    if reselect_enabled:
        assert reselect_home is not None
        active_or_home = Condition(
            ConditionKind.ANY,
            children=(active, reselect_home),
        )
        active_or_feed_changed = Condition(
            ConditionKind.ANY,
            children=(
                active,
                Condition(ConditionKind.STATE_CHANGED, "ui.layout_fingerprint"),
            ),
        )
        recovery_wait = WaitPolicy(
            timeout_seconds=min(float(task_parameters["transition_timeout_seconds"]), 8.0),
            poll_interval_seconds=0.5,
            observation_level=ObservationLevel.STRUCTURED,
        )
        monitor_recovery = (
            Step(
                "return-home-after-completed-video",
                "return_to_long_video_home",
                active_or_home,
                wait=recovery_wait,
                retry=RetryPolicy(1),
                skip_if_satisfied=True,
            ),
            Step(
                "advance-after-completed-video",
                "advance_long_video_candidates",
                active_or_feed_changed,
                wait=recovery_wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=True,
            ),
            Step(
                "enter-video-after-completed-video",
                "enter_replacement_long_video",
                active,
                wait=WaitPolicy(
                    timeout_seconds=max(
                        float(task_parameters["transition_timeout_seconds"]),
                        15.0,
                    ),
                    poll_interval_seconds=0.5,
                    observation_level=ObservationLevel.STRUCTURED,
                ),
                retry=RetryPolicy(1),
                skip_if_satisfied=True,
            ),
        )
    preparation = LongVideoPreparation(
        pause_recovery_action=("recover_long_video_pause"
                               if control_resource and reveal_resource else None),
        before_enter=(
            Step(
                "refresh-long-video-feed",
                "refresh_long_video_feed",
                refresh_ready,
                wait=WaitPolicy(
                    timeout_seconds=float(task_parameters["transition_timeout_seconds"]),
                    observation_level=ObservationLevel.STRUCTURED,
                ),
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
            ),
        ) if refresh_enabled else (),
        monitor_recovery=monitor_recovery,
        monitor_max_consecutive_misses=int(
            reselect_plan.get("monitor_max_consecutive_misses")
            or ad_plan.get("monitor_max_consecutive_misses")
            or 10
        ),
        monitor_max_recoveries=int(
            reselect_plan.get("monitor_max_recoveries")
            or ad_plan.get("monitor_max_recoveries")
            or 4
        ),
    )
    playbook = build_long_video_playbook(
        LongVideoTask(**task_parameters),
        verification,
        preparation,
    )
    return binding, playbook


def _build_ios(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    *,
    run_pause_resume: bool,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    feed_scrolls: int,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    try:
        controls = _IOS_CONTROLS[app.name]
    except KeyError as exc:
        raise NotImplementedError(f"no semantic iOS controls for {app.name!r}") from exc
    if app.name == "iqiyi":
        enter_strategy = element_capability(
            "ios-iqiyi-episode-card",
            "element.activate.query",
            idempotency=Idempotency.NON_IDEMPOTENT,
            parameters={
                "using": "xpath",
                "value": (
                    "(//XCUIElementTypeOther["
                    "@visible='true' and @width >= 150 and @width <= 200 and @height >= 120"
                    "][.//XCUIElementTypeStaticText["
                    "contains(@name,'更新至') or "
                    "contains(@name,'集全') or "
                    "contains(@name,'观看至第')"
                    "]]//XCUIElementTypeImage["
                    "@visible='true' and @width >= 150 and @height >= 80])[1]"
                ),
            },
        )
    elif app.name == "youtube":
        enter_strategy = element_capability(
            "ios-youtube-long-video-card",
            "element.activate.candidate",
            idempotency=Idempotency.NON_IDEMPOTENT,
            parameters={
                "include_pattern": r"播放视频",
                "exclude_pattern": r"Shorts|直播|广告|赞助商|竖屏|短视频",
                "accessibility_id_pattern": r"^eml\.vwc$",
                "role_pattern": "button",
                "require_clickable": True,
                "min_width_ratio": 0.8,
                "min_height_ratio": 0.1,
                # A single scroll avoids repeatedly selecting the fixed first
                # recommendation. Formal repeat samples can request more
                # feed_scrolls, and the selected semantic title is retained in
                # command evidence for cross-run distinctness checks.
                "candidate_initial_scrolls": max(1, feed_scrolls),
                "candidate_max_scrolls": 6,
                "candidate_scroll_duration_ms": 550,
                "candidate_scroll_not_before_seconds": 8.0,
                "candidate_snapshot_max_depth": 50,
                "candidate_wait_seconds": transition_timeout_seconds,
                "candidate_poll_seconds": 1.0,
            },
        )
    else:
        exclude_pattern = r"竖屏|短视频"
        enter_strategy = element_capability(
            "ios-duration-title-media-card",
            "element.activate.media_card",
            idempotency=Idempotency.NON_IDEMPOTENT,
            parameters={
                "minimum_duration_seconds": 60,
                "exclude_pattern": exclude_pattern,
                "candidate_snapshot_max_depth": 50,
                "candidate_wait_seconds": transition_timeout_seconds,
            },
        )
    pause_query = _ios_accessibility_query("ios-exact-pause", controls["pause"])
    play_query = (
        element_capability(
            "ios-reveal-exact-play",
            "element.activate.revealed_query",
            idempotency=Idempotency.STATE_SETTING,
            parameters={
                "using": "predicate string",
                "value": f"name == '{_predicate_escape(controls['play'])}'",
                "reveal_value": f"name == '{_predicate_escape(controls['surface'])}'",
                "reveal_wait_seconds": 0.5,
            },
        )
        if app.name == "youtube"
        else _ios_accessibility_query("ios-exact-play", controls["play"])
    )
    actions = lifecycle_actions()
    actions.update(
        {
            "enter_long_video": action("enter_long_video", enter_strategy),
            "ensure_playing": action(
                "ensure_playing",
                direct(
                    "ios-hid-media-play",
                    "media.ensure_playing",
                    parameters=(
                        {"duration_seconds": 0.1} if app.name == "youtube" else {}
                    ),
                ),
                play_query,
            ),
            "ensure_paused": action(
                "ensure_paused",
                direct(
                    "ios-hid-media-pause",
                    "media.ensure_paused",
                    parameters=(
                        {"duration_seconds": 0.1} if app.name == "youtube" else {}
                    ),
                ),
                pause_query,
            ),
        }
    )
    surface_id = controls.get("surface", "")
    player_surface_ids = tuple(
        value for value in (controls["pause"], controls["play"], surface_id) if value
    )
    player_surface = SemanticSelector(
        accessibility_ids=(surface_id,) if surface_id else player_surface_ids,
        text_patterns=((r"^\s*发布弹幕",) if app.name == "bilibili" else ()),
        roles=(("other",) if surface_id else ("button",)),
    )
    selectors = {
        "pause_control": SemanticSelector(
            accessibility_ids=(controls["pause"],),
            roles=("button",),
        ),
        "play_control": SemanticSelector(
            accessibility_ids=(controls["play"],),
            roles=("button",),
        ),
        "player_surface": player_surface,
    }
    if app.name == "iqiyi":
        selectors["iqiyi_player_page"] = SemanticSelector(
            exact_texts=("选集",),
            roles=("statictext",),
        )
    element_queries = {
        "pause_control": _ios_observation_query(controls["pause"]),
        "play_control": _ios_observation_query(controls["play"]),
        "player_surface": (
            _ios_observation_predicate("name BEGINSWITH '发布弹幕'")
            if app.name == "bilibili"
            else _ios_observation_predicate(
                " OR ".join(
                    f"name == '{_predicate_escape(value)}'"
                    for value in player_surface_ids
                )
            )
        ),
    }
    if app.name == "youtube":
        element_queries.pop("player_surface")
    if app.name == "iqiyi":
        element_queries["iqiyi_player_page"] = _ios_observation_predicate(
            "type == 'XCUIElementTypeStaticText' AND name == '选集'"
        )
    feed_home_prefix = str(profile.get("native_feed_home_prefix") or "").strip()
    if feed_home_prefix:
        selectors["feed_home"] = SemanticSelector(
            text_patterns=("^" + re.escape(feed_home_prefix),),
            roles=("other",),
        )
        element_queries["feed_home"] = _ios_observation_predicate(
            "type == 'XCUIElementTypeOther' AND name BEGINSWITH "
            f"'{_predicate_escape(feed_home_prefix)}'"
        )
    binding = AppBinding(
        f"ios-{app.name}-long-video",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        element_queries=element_queries,
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "playback_transport": "WDA HID first with exact accessibility fallback",
            "playback_verification": "local frame motion, independent of command acceptance",
            "video_switch": "disabled until coordinate-free exit is authored",
            "entry_feed_scrolls": max(1, feed_scrolls) if app.name == "youtube" else 0,
        },
    )
    motion_playing = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
        ),
    )
    video_open = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            (
                Condition(
                    ConditionKind.ANY,
                    children=(
                        Condition(ConditionKind.ELEMENT_PRESENT, "player_surface"),
                        Condition(ConditionKind.ELEMENT_PRESENT, "iqiyi_player_page"),
                    ),
                )
                if app.name == "iqiyi"
                else Condition(ConditionKind.ELEMENT_PRESENT, "player_surface")
            ),
        ),
    )
    verification = LongVideoVerification(
        video_open=video_open,
        playing=motion_playing,
        paused=Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.STATE_EQUALS, "motion.playback", "paused"),
            ),
        ),
    )
    refocus = Step(
        "refocus-long-video-app",
        "launch_app",
        Condition(ConditionKind.APP_FOREGROUND),
        wait=WaitPolicy(
            timeout_seconds=transition_timeout_seconds,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(2),
        skip_if_satisfied=False,
    )
    playbook = build_long_video_playbook(
        LongVideoTask(
            run_pause_resume=run_pause_resume,
            switch_video=False,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
        LongVideoPreparation(
            before_enter=(refocus,) + (
                (
                    Step(
                        "wait-long-video-content-surface",
                        None,
                        Condition(
                            ConditionKind.ALL,
                            children=(
                                Condition(ConditionKind.APP_FOREGROUND),
                                Condition(
                                    ConditionKind.ANY,
                                    children=(
                                        Condition(ConditionKind.ELEMENT_PRESENT, "player_surface"),
                                        Condition(ConditionKind.ELEMENT_PRESENT, "feed_home"),
                                    ),
                                ),
                            ),
                        ),
                        wait=WaitPolicy(
                            timeout_seconds=transition_timeout_seconds,
                            observation_level=ObservationLevel.STRUCTURED,
                        ),
                    ),
                ) if feed_home_prefix else ()
            )
        ),
    )
    return binding, playbook


def _ios_accessibility_query(strategy_id: str, accessibility_id: str):
    escaped = accessibility_id.replace("\\", "\\\\").replace("'", "\\'")
    return element_capability(
        strategy_id,
        "element.activate.query",
        idempotency=Idempotency.STATE_SETTING,
        parameters={"using": "predicate string", "value": f"name == '{escaped}'"},
    )


def _ios_observation_query(accessibility_id: str) -> ElementObservationQuery:
    escaped = _predicate_escape(accessibility_id)
    return _ios_observation_predicate(f"name == '{escaped}'")


def _ios_observation_predicate(predicate: str) -> ElementObservationQuery:
    return ElementObservationQuery(
        "observation.element.query",
        {"using": "predicate string", "value": predicate},
    )


def _predicate_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")
