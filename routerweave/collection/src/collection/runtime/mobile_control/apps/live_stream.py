"""Generic live-stream bindings built from shared player capabilities."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Mapping

from ..binding import ActionStrategy, AppBinding, ElementObservationQuery
from ..catalog import RegisteredApp
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..perception import SemanticSelector
from ..playbook import Playbook, RetryPolicy, Step, WaitPolicy
from ..playbooks.common import interruption_scan_step
from ..playbooks.live_stream import (
    LiveStreamPreparation,
    LiveStreamTask,
    LiveStreamVerification,
    build_live_stream_playbook,
)
from ..playbooks.human_activity import HumanActivityDecision
from ..status import ActionMethod, Idempotency, ObservationLevel, Platform
from .common import action, direct, element_capability, gesture, lifecycle_actions


def build_live_stream_session(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    *,
    run_pause_resume: bool = True,
    switch_room: bool = False,
    leave_app_open: bool = False,
    restart_app: bool = True,
    transition_timeout_seconds: float = 12.0,
    monitor_seconds: float = 0.0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
    random_seed: int = 0,
) -> tuple[AppBinding, Playbook]:
    if app.task_family != "live_stream":
        raise ValueError(f"{app.name!r} is not a live-stream application")
    if switch_room and not (
        app.platform is Platform.IOS and app.name in {"huya", "twitch"}
    ):
        raise NotImplementedError(
            "generic live-room switching requires a stable room identity; use the verified "
            "Douyu room-id binding or author one before enabling it"
        )
    if app.platform is Platform.ANDROID:
        return _build_android(
            app,
            profile,
            run_pause_resume=run_pause_resume,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
            random_seed=random_seed,
        )
    if app.platform is Platform.IOS and app.name == "twitch":
        return _build_ios_twitch(
            app,
            run_pause_resume=run_pause_resume,
            switch_room=switch_room,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        )
    if app.platform is Platform.IOS and app.name == "huya":
        return _build_ios_huya(
            app,
            run_pause_resume=run_pause_resume,
            switch_room=switch_room,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        )
    raise NotImplementedError(
        f"use the verified room-id binding for {app.platform.value}:{app.name}"
    )


def _build_android(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    *,
    random_seed: int = 0,
    **task_parameters: Any,
) -> tuple[AppBinding, Playbook]:
    raw = profile.get("live_stream_card_plan")
    plan = raw if isinstance(raw, Mapping) else {}
    startup_wait = float(plan.get("startup_observation_wait_seconds") or 0)
    if not 0 <= startup_wait <= 90:
        raise ValueError("startup observation wait must be bounded to 90 seconds")
    observation_wait = float(plan.get("observation_wait_seconds") or 0)
    if not 0 <= observation_wait <= 90:
        raise ValueError("observation wait must be bounded to 90 seconds")
    pause_hold_allows_playing = plan.get("pause_hold_allows_playing", False)
    if not isinstance(pause_hold_allows_playing, bool):
        raise ValueError("pause_hold_allows_playing must be boolean")
    inline_containers = plan.get("inline_containers")
    if inline_containers:
        if (not isinstance(inline_containers, Mapping)
                or inline_containers.get("package") != app.app_id
                or not str(inline_containers.get("activity_class") or "").startswith(app.app_id + ".")
                or not str(inline_containers.get("marker_resource_id") or "").startswith(app.app_id + ":id/")
                or not isinstance(inline_containers.get("resource_ids"), (list, tuple))
                or not inline_containers["resource_ids"]
                or any(not str(r).startswith(app.app_id + ":id/")
                       for r in inline_containers["resource_ids"])):
            raise ValueError("inline containers require exact app-scoped resources and player context")
        text_resources = inline_containers.get("text_resource_ids", ())
        if (not isinstance(text_resources, (list, tuple))
                or any(not str(r).startswith(app.app_id + ":id/") for r in text_resources)):
            raise ValueError("inline text resources must be exact app-scoped resource IDs")
    activity_hint = _activity_hint(str(plan.get("player_activity_contains") or ""))
    if not activity_hint:
        raise ValueError("live_stream_card_plan.player_activity_contains is required")
    playback_evidence = str(plan.get("playback_evidence") or "audio_or_motion")
    if playback_evidence not in {"audio_or_motion", "media_session", "motion"}:
        raise ValueError("unsupported live-stream playback_evidence")
    resource_id = str(plan.get("card_resource_id") or "").strip()
    selection_policy = str(
        plan.get("candidate_selection_policy") or "first_visible"
    ).strip().casefold()
    monitor_reselect = bool(plan.get("monitor_reselect_on_inactive", False))
    monitor_reselect_strategy = str(
        plan.get("monitor_reselect_strategy") or "home_reentry"
    ).strip().casefold()
    monitor_restart_on_inactive = bool(
        plan.get("monitor_restart_on_inactive", False)
    )
    feed_filter_resource_id = str(plan.get("feed_filter_resource_id") or "").strip()
    feed_filter_exact_text = str(plan.get("feed_filter_exact_text") or "").strip()
    if selection_policy not in {"first_visible", "nearest_point", "seeded_random"}:
        raise ValueError("unsupported live-stream candidate selection policy")
    if monitor_reselect_strategy not in {"home_reentry", "advance_feed"}:
        raise ValueError("unsupported live-stream monitor reselect strategy")
    if resource_id:
        entry_ids = [resource_id, *plan.get("alternate_entry_resource_ids", ())]
        card_parameters = {
            "include_pattern": r".+",
            "exclude_pattern": str(plan.get("card_exclude_regex") or ""),
            "resource_id_pattern": "^(?:" + "|".join(re.escape(value) for value in entry_ids) + ")$",
            "require_clickable": bool(plan.get("card_require_clickable", True)),
            "min_top_ratio": 0.1,
            "max_bottom_ratio": 0.9,
            "selection_policy": selection_policy,
        }
        entry_confidence = "registry resource-id plus semantic exclusions"
    else:
        card_parameters = {
            "include_pattern": str(plan.get("card_include_regex") or r".{2,}"),
            "exclude_pattern": str(
                plan.get("card_exclude_regex")
                or r"交友|语音|电台|聊天|陪伴|点唱|唱歌|才艺|团播|广告|推广"
            ),
            "role_pattern": str(
                plan.get("card_class_regex")
                or r"ViewGroup|FrameLayout|RelativeLayout|viewgroup|framelayout"
            ),
            "require_clickable": bool(plan.get("card_require_clickable", False)),
            "min_width_ratio": float(plan.get("card_min_width_ratio") or 0.3),
            "min_height_ratio": float(plan.get("card_min_height_ratio") or 0.1),
            "max_bottom_ratio": float(plan.get("card_max_bottom_ratio") or 0.9),
            "selection_policy": selection_policy,
        }
        entry_confidence = "registry semantic card filters; outcome requires player activity and audio"
    if selection_policy == "seeded_random":
        card_parameters["selection_seed"] = int(random_seed)
    actions = lifecycle_actions()
    selectors: dict[str, SemanticSelector] = {}
    element_queries: dict[str, ElementObservationQuery] = {}
    entry_button_strategies: tuple[ActionStrategy, ...] = ()
    entry_texts = tuple(plan.get("entry_button_exact_texts", ()))
    if entry_texts:
        selectors["live_watch_entry"] = SemanticSelector(
            exact_texts=entry_texts, require_clickable=True,
        )
        entry_button_strategies = (ActionStrategy(
            "android-live-watch-entry", ActionMethod.ELEMENT, Idempotency.NON_IDEMPOTENT,
            selector_key="live_watch_entry",
        ),)
    home_plan_raw = profile.get("live_stream_home_plan")
    home_plan = home_plan_raw if isinstance(home_plan_raw, Mapping) else {}
    before_enter: tuple[Step, ...] = ()
    if home_plan:
        tab_text = str(home_plan.get("tab_exact_text") or "").strip()
        ready_resource_id = str(home_plan.get("ready_marker_resource_id") or "").strip()
        ready_text = str(home_plan.get("ready_marker_exact_text") or "").strip()
        if not tab_text or not ready_resource_id or not ready_text:
            raise ValueError(
                "live_stream_home_plan requires tab_exact_text, ready_marker_resource_id, "
                "and ready_marker_exact_text"
            )
        selectors["live_home_ready"] = SemanticSelector(
            resource_ids=(ready_resource_id,),
            exact_texts=(ready_text,),
            roles=("textview",),
            minimum_score=200,
        )
        actions["open_live_home"] = action(
            "open_live_home",
            element_capability(
                "android-open-live-home-tab",
                "element.activate.query",
                idempotency=Idempotency.STATE_SETTING,
                parameters={"exact_text": tab_text},
            ),
        )
        before_enter = (
            Step(
                "open-live-home",
                "open_live_home",
                Condition(ConditionKind.ELEMENT_PRESENT, "live_home_ready"),
                wait=WaitPolicy(
                    timeout_seconds=min(
                        float(task_parameters["transition_timeout_seconds"]),
                        8.0,
                    ),
                    poll_interval_seconds=0.5,
                    observation_level=ObservationLevel.STRUCTURED,
                ),
            ),
        )
    actions.update(
        {
            "enter_live_room": action(
                "enter_live_room",
                *entry_button_strategies,
                element_capability(
                    "android-live-card-candidate",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=card_parameters,
                ),
            ),
            "ensure_live_active": action(
                "ensure_live_active",
                direct(
                    "android-input-media-play",
                    "media.ensure_playing",
                    parameters={"injection": "keyevent"},
                ),
            ),
            "ensure_paused": action(
                "ensure_paused",
                direct(
                    "android-input-media-pause",
                    "media.ensure_paused",
                    parameters={"injection": "keyevent"},
                ),
                gesture(
                    "android-input-player-surface-pause",
                    "screen.tap.relative",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"x_ratio": 0.5, "y_ratio": 0.35},
                ),
            ),
            "ensure_playing": action(
                "ensure_playing",
                direct(
                    "android-input-media-resume",
                    "media.ensure_playing",
                    parameters={"injection": "keyevent"},
                ),
                gesture(
                    "android-input-player-surface-resume",
                    "screen.tap.relative",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"x_ratio": 0.5, "y_ratio": 0.35},
                ),
            ),
            "advance_live_candidates": action(
                "advance_live_candidates",
                gesture(
                    "android-advance-live-card-feed",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "up", "duration_ms": 600},
                ),
            ),
        }
    )
    control_plan_raw = profile.get("player_control_plan")
    control_plan = control_plan_raw if isinstance(control_plan_raw, Mapping) else {}
    control_resource = str(control_plan.get("toggle_resource_id") or "").strip()
    if control_resource:
        for action_name in ("ensure_paused", "ensure_playing"):
            actions[action_name] = action(
                action_name,
                actions[action_name].strategies[0],
                element_capability(
                    f"android-native-{action_name}", "element.activate.query",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"resource_id": control_resource,
                                "reveal_resource_id": str(control_plan.get("reveal_resource_id") or "")},
                ),
            )
    if monitor_reselect_strategy == "advance_feed":
        advance_inactive_feed = gesture(
            "android-advance-inactive-live-feed-once",
            "screen.swipe.relative",
            idempotency=Idempotency.REPEATABLE,
            parameters={"direction": "up", "duration_ms": 600},
        )
        actions["enter_live_room"] = action(
            "enter_live_room",
            gesture(
                "android-advance-live-entry-feed",
                "screen.swipe.relative",
                idempotency=Idempotency.REPEATABLE,
                parameters={"direction": "up", "duration_ms": 600},
            ),
        )
        actions["ensure_live_active"] = action(
            "ensure_live_active",
            advance_inactive_feed,
        )
        actions["recover_live_stream"] = action(
            "recover_live_stream",
            advance_inactive_feed,
        )
    filter_enabled = bool(feed_filter_resource_id or feed_filter_exact_text)
    if filter_enabled:
        if not feed_filter_resource_id or not feed_filter_exact_text:
            raise ValueError(
                "live feed filter requires resource ID and exact text"
            )
        if re.fullmatch(
            re.escape(app.app_id) + r":id/[A-Za-z0-9_]+",
            feed_filter_resource_id,
        ) is None:
            raise ValueError("live feed filter resource ID is invalid")
        actions["select_live_feed_filter"] = action(
            "select_live_feed_filter",
            element_capability(
                "android-select-live-feed-filter",
                "element.activate.hierarchy_query",
                idempotency=Idempotency.STATE_SETTING,
                parameters={
                    "resource_id": feed_filter_resource_id,
                    "exact_text": feed_filter_exact_text,
                    "hierarchy_compressed": True,
                    "hierarchy_read_attempts": 3,
                    "hierarchy_retry_delay_seconds": 0.75,
                    "hierarchy_read_timeout_seconds": min(
                        float(task_parameters["transition_timeout_seconds"]),
                        8.0,
                    ),
                },
            ),
        )
    if monitor_reselect and monitor_reselect_strategy == "home_reentry":
        replacement_parameters = dict(card_parameters)
        if selection_policy == "seeded_random":
            replacement_parameters["selection_seed"] = int(random_seed) + 1
        actions.update(
            {
                "return_to_live_home": action(
                    "return_to_live_home",
                    direct(
                        "android-live-back-to-home",
                        "navigation.back",
                        idempotency=Idempotency.NON_IDEMPOTENT,
                    ),
                ),
                "enter_replacement_room": action(
                    "enter_replacement_room",
                    element_capability(
                        "android-live-replacement-card-candidate",
                        "element.activate.candidate",
                        idempotency=Idempotency.NON_IDEMPOTENT,
                        parameters=replacement_parameters,
                    ),
                ),
            }
        )
    room_marker = str(plan.get("room_marker_resource_id") or "").strip()
    portrait_conditions: tuple[Condition, ...] = ()
    portrait_steps: tuple[Step, ...] = ()
    if plan.get("preferred_orientation") == "portrait":
        portrait_conditions = (
            Condition(ConditionKind.STATE_EQUALS, "device.orientation", "portrait"),
            Condition(ConditionKind.STATE_EQUALS, "device.orientation_locked", True),
        )
        actions["ensure_portrait"] = action(
            "ensure_portrait",
            direct("android-lock-portrait", "device.orientation.set", parameters={"orientation": "portrait"}),
        )
        portrait_steps = (Step(
            "ensure-portrait", "ensure_portrait",
            Condition(ConditionKind.ALL, children=portrait_conditions),
            wait=WaitPolicy(timeout_seconds=8.0, poll_interval_seconds=0.5),
        ),)
    room_marker_conditions: tuple[Condition, ...] = ()
    if room_marker:
        selectors["live_room_marker"] = SemanticSelector(resource_ids=(room_marker,), require_enabled=False)
        if plan.get("room_marker_observation") == "activity_view":
            element_queries["live_room_marker"] = ElementObservationQuery(
                "observation.element.query", {"resource_id": room_marker},
            )
        room_marker_conditions = (
            Condition(ConditionKind.ELEMENT_PRESENT, "live_room_marker"),
        )
    room = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(
                ConditionKind.STATE_CONTAINS,
                "device.foreground_activity_class",
                activity_hint,
            ),
            *room_marker_conditions,
            *portrait_conditions,
        ),
    )
    playing_state = (
        Condition(ConditionKind.STATE_EQUALS, "media.playback", "playing")
        if playback_evidence == "media_session"
        else Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing")
        if playback_evidence == "motion"
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
        children=(room, playing_state),
    )
    eligible_active = active
    feed_filter_steps: tuple[Step, ...] = ()
    initial_filtered_advance: tuple[Step, ...] = ()
    if filter_enabled:
        selectors["live_feed_filter"] = SemanticSelector(
            resource_ids=(feed_filter_resource_id,),
            exact_texts=(feed_filter_exact_text,),
            attributes={"package": app.app_id},
            require_clickable=True,
            minimum_score=225,
        )
        changed_active = Condition(
            ConditionKind.ALL,
            children=(
                active,
                Condition(
                    ConditionKind.STATE_CHANGED,
                    "visual.frame_fingerprint",
                ),
            ),
        )
        feed_filter_steps = (
            Step(
                "wait-live-feed-filter", None,
                Condition(ConditionKind.ALL, children=(
                    Condition(ConditionKind.APP_FOREGROUND),
                    Condition(ConditionKind.ELEMENT_PRESENT, "live_feed_filter"),
                )),
                wait=WaitPolicy(
                    timeout_seconds=float(task_parameters["transition_timeout_seconds"]),
                    poll_interval_seconds=0.5,
                    observation_level=ObservationLevel.STRUCTURED,
                ),
                retry=RetryPolicy(1),
            ),
            Step(
                "select-live-feed-filter",
                "select_live_feed_filter",
                changed_active,
                wait=WaitPolicy(
                    timeout_seconds=max(
                        float(task_parameters["transition_timeout_seconds"]),
                        15.0,
                    ),
                    poll_interval_seconds=0.5,
                ),
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
            ),
        )
        initial_filtered_advance = (
            Step(
                "advance-filtered-live-feed",
                "recover_live_stream",
                changed_active,
                wait=WaitPolicy(
                    timeout_seconds=max(
                        float(task_parameters["transition_timeout_seconds"]),
                        15.0,
                    ),
                    poll_interval_seconds=0.5,
                ),
                retry=RetryPolicy(1),
                skip_if_satisfied=False,
            ),
        )
    home_guards: tuple[Step, ...] = ()
    home: Condition | None = None
    home_marker = str(plan.get("home_marker_resource_id") or "").strip()
    if home_marker and room_marker:
        selectors["live_entry_home"] = SemanticSelector(resource_ids=(home_marker,))
        if element_queries:
            element_queries["live_entry_home"] = ElementObservationQuery(
                "observation.element.query", {"resource_id": home_marker},
            )
        home = Condition(ConditionKind.ALL, children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "live_entry_home"),
            Condition(ConditionKind.ELEMENT_ABSENT, "live_room_marker"),
        ))
        home_guards = (Step(
            "verify-live-entry-home", None,
            home,
            wait=WaitPolicy(timeout_seconds=6.0, poll_interval_seconds=0.5),
            retry=RetryPolicy(1),
        ),)
    if (
        monitor_reselect
        and monitor_reselect_strategy == "home_reentry"
        and home is None
    ):
        raise ValueError(
            "monitor_reselect_on_inactive requires room_marker_resource_id and "
            "home_marker_resource_id"
        )
    interruptions = []
    startup_overlay = plan.get("startup_overlay")
    if isinstance(startup_overlay, Mapping):
        marker_id = str(startup_overlay.get("marker_resource_id") or "")
        timeout = float(startup_overlay.get("timeout_seconds", 8.0))
        if not marker_id.startswith(app.app_id + ":id/") or not 0 < timeout <= 15:
            raise ValueError("startup overlay requires an app-scoped marker and bounded timeout")
        selectors["live_startup_overlay"] = SemanticSelector(
            resource_ids=(marker_id,), attributes={"package": app.app_id},
        )
        interruptions.append(InterruptionRule(
            "live-startup-overlay-dismissal", InterruptionKind.BENIGN,
            "live_startup_overlay", wait_for_dismissal=True,
            timeout_seconds=timeout, max_occurrences=1,
            step_ids=("launch-app", "enter-live-room", "scan-live-entry-interruptions"),
        ))
    for index, overlay in enumerate(plan.get("benign_overlays") or ()):
        marker_key = f"live_overlay_{index}"
        close_key = f"live_overlay_close_{index}"
        selectors[marker_key] = SemanticSelector(
            attributes={"package": app.app_id},
            text_patterns=(str(overlay["marker_text_pattern"]),),
            roles=(str(overlay["marker_role"]),),
        )
        selectors[close_key] = SemanticSelector(
            exact_texts=(str(overlay["close_text"]),),
            roles=(str(overlay["close_role"]),),
            attributes={"package": app.app_id},
        )
        interruptions.append(InterruptionRule(
            f"live-known-overlay-{index}", InterruptionKind.BENIGN,
            marker_key, close_key, auto_resolve=True,
            max_occurrences=2, timeout_seconds=6.0,
        ))
    binding = AppBinding(
        f"android-{app.name}-live-stream",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        element_queries=element_queries,
        interruptions=tuple(interruptions),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "entry_evidence": entry_confidence,
            "playback_transport": (
                "one bounded feed advance after locally observed inactive playback"
                if monitor_reselect_strategy == "advance_feed"
                else "ADB input keyevent, then relative input tap fallback"
            ),
            "room_switch": (
                "one bounded feed advance, then app restart if playback remains inactive"
                if monitor_reselect and monitor_reselect_strategy == "advance_feed"
                else "bounded return-to-home and seeded semantic replacement after inactive room"
                if monitor_reselect
                else "requires stable room identity"
            ),
            "playback_evidence": playback_evidence,
            "inline_containers": plan.get("inline_containers"),
            "observation_wait_seconds": observation_wait,
            "startup_observation_wait_seconds": plan.get("startup_observation_wait_seconds", 0),
        },
    )
    verification = LiveStreamVerification(
        room_entered=(
            eligible_active
            if monitor_reselect_strategy == "advance_feed"
            else room
        ),
        active=active,
        paused=Condition(
            ConditionKind.ALL,
            children=(
                room,
                Condition(
                    ConditionKind.STATE_EQUALS,
                    "media.playback" if playback_evidence == "media_session" else "motion.playback",
                    "paused",
                ),
            ),
        ),
        playing=active,
    )
    if pause_hold_allows_playing:
        verification = replace(
            verification,
            pause_hold=Condition(
                ConditionKind.ANY,
                children=(verification.paused, verification.playing),
            ),
        )
    recovery_wait = WaitPolicy(
        timeout_seconds=min(float(task_parameters["transition_timeout_seconds"]), 6.0),
        poll_interval_seconds=0.5,
        observation_level=ObservationLevel.STRUCTURED,
    )
    monitor_recovery: tuple[Step, ...] = (
        *(replace(step, step_id="restore-portrait") for step in portrait_steps),
        Step("restore-live-playback", "ensure_live_active", active, wait=recovery_wait),
    ) if portrait_steps else ()
    monitor_max_consecutive_misses = 2
    monitor_max_recoveries = 2
    if monitor_reselect:
        try:
            monitor_max_consecutive_misses = int(
                plan.get("monitor_max_consecutive_misses", 3)
            )
            monitor_max_recoveries = int(plan.get("monitor_max_recoveries", 4))
            monitor_advance_attempts = int(plan.get("monitor_advance_attempts", 2))
        except (TypeError, ValueError) as exc:
            raise ValueError("live-stream monitor recovery limits must be integers") from exc
        if not 1 <= monitor_max_consecutive_misses <= 60:
            raise ValueError("live-stream monitor miss limit is outside the bounded range")
        if not 1 <= monitor_max_recoveries <= 10:
            raise ValueError("live-stream monitor recovery limit is outside the bounded range")
        if not 1 <= monitor_advance_attempts <= 2:
            raise ValueError("live-stream monitor advance attempts are outside the bounded range")
        if monitor_reselect_strategy == "advance_feed":
            restart_recovery: tuple[Step, ...] = ()
            if monitor_restart_on_inactive:
                restart_recovery = (
                    Step(
                        "reset-live-app-after-inactive-feed",
                        "reset_app",
                        Condition(
                            ConditionKind.NOT,
                            children=(Condition(ConditionKind.APP_FOREGROUND),),
                        ),
                        wait=WaitPolicy(
                            timeout_seconds=min(
                                float(task_parameters["transition_timeout_seconds"]),
                                4.0,
                            ),
                            poll_interval_seconds=0.5,
                        ),
                        retry=RetryPolicy(1),
                        skip_if_satisfied=False,
                    ),
                    Step(
                        "relaunch-live-app-after-inactive-feed",
                        "launch_app",
                        Condition(ConditionKind.APP_FOREGROUND),
                        wait=recovery_wait,
                        retry=RetryPolicy(1),
                    ),
                    *(replace(step, step_id=f"restart-{step.step_id}") for step in portrait_steps),
                    *(replace(step, step_id=f"restart-{step.step_id}") for step in feed_filter_steps),
                )
            monitor_recovery = (
                Step(
                    "advance-live-after-inactive-stream",
                    "recover_live_stream",
                    eligible_active,
                    wait=WaitPolicy(
                        timeout_seconds=max(
                            float(task_parameters["transition_timeout_seconds"]),
                            15.0,
                        ),
                        poll_interval_seconds=0.5,
                    ),
                    retry=RetryPolicy(
                        monitor_advance_attempts if restart_recovery else 1
                    ),
                    recovery=restart_recovery,
                    skip_if_satisfied=False,
                ),
            )
        else:
            assert home is not None
            home_or_active = Condition(
                ConditionKind.ANY,
                children=(home, active),
            )
            monitor_recovery = (
                Step(
                    "restore-live-playback-or-reselect",
                    "ensure_live_active",
                    active,
                    wait=recovery_wait,
                    retry=RetryPolicy(2),
                    recovery=(
                        Step(
                            "return-live-home-after-inactive-room",
                            "return_to_live_home",
                            home_or_active,
                            wait=recovery_wait,
                            retry=RetryPolicy(1),
                            skip_if_satisfied=True,
                        ),
                        Step(
                            "advance-live-replacement-candidates",
                            "advance_live_candidates",
                            Condition(ConditionKind.STATE_CHANGED, "ui.layout_fingerprint"),
                            wait=recovery_wait,
                            retry=RetryPolicy(2),
                            skip_if_satisfied=False,
                        ),
                        Step(
                            "enter-live-replacement-room",
                            "enter_replacement_room",
                            active,
                            wait=WaitPolicy(
                                timeout_seconds=max(
                                    float(task_parameters["transition_timeout_seconds"]),
                                    15.0,
                                ),
                                poll_interval_seconds=0.5,
                            ),
                            retry=RetryPolicy(1),
                            skip_if_satisfied=False,
                        ),
                    ),
                    safe_retry_after_recovery=True,
                    skip_if_satisfied=True,
                ),
            )
    feed_entry_recovery = (
        Step(
            "advance-live-entry-candidates",
            (
                "recover_live_stream"
                if monitor_reselect_strategy == "advance_feed"
                else "advance_live_candidates"
            ),
            eligible_active,
            wait=WaitPolicy(
                timeout_seconds=max(
                    float(task_parameters["transition_timeout_seconds"]),
                    15.0,
                ),
                poll_interval_seconds=0.5,
            ),
            retry=RetryPolicy(
                1 if monitor_reselect_strategy == "advance_feed" else 2
            ),
            skip_if_satisfied=False,
        ),
    )
    preparation = LiveStreamPreparation(
        before_enter=(*portrait_steps, *before_enter, *feed_filter_steps),
        enter_recovery=feed_entry_recovery if monitor_reselect_strategy == "advance_feed" else (
            interruption_scan_step("scan-live-entry-interruptions", recovery_wait),
            *home_guards,
            Step(
                "advance-live-entry-candidates",
                "advance_live_candidates",
                Condition(ConditionKind.STATE_CHANGED, "ui.layout_fingerprint"),
                wait=recovery_wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
            ),
        ),
        enter_retry_safe=True,
        before_active=initial_filtered_advance,
        monitor_recovery=monitor_recovery,
        monitor_max_consecutive_misses=monitor_max_consecutive_misses,
        monitor_max_recoveries=monitor_max_recoveries,
    )
    playbook = build_live_stream_playbook(
        LiveStreamTask(switch_room=False, **task_parameters),
        verification,
        preparation,
    )
    return binding, playbook


def _build_ios_twitch(
    app: RegisteredApp,
    *,
    run_pause_resume: bool,
    switch_room: bool,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    """Build the native iOS Twitch live-room flow proven on the live feed.

    Twitch exposes full-width live-feed cells whose descendant accessibility
    text contains the viewer count.  One bounded pre-scroll avoids repeatedly
    entering the same first card, and ``max_bottom_ratio`` rejects partially
    hidden cells that overlap the bottom create/broadcast control.
    """

    card_parameters = {
        "include_pattern": r"名观众",
        "exclude_pattern": r"剪辑|广告|推广",
        "role_pattern": r"cell",
        "require_clickable": True,
        "min_width_ratio": 0.8,
        "min_height_ratio": 0.25,
        "max_bottom_ratio": 0.93,
        "candidate_initial_scrolls": 1,
        "candidate_max_scrolls": 4,
        "candidate_scroll_duration_ms": 550,
        "candidate_snapshot_max_depth": 50,
        "candidate_wait_seconds": transition_timeout_seconds,
        "candidate_poll_seconds": 1.0,
        "candidate_history_key": "twitch_live_room",
        "candidate_avoid_recent": 1,
    }
    actions = lifecycle_actions()
    actions.update(
        {
            "enter_live_room": action(
                "enter_live_room",
                element_capability(
                    "ios-twitch-visible-live-card",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=card_parameters,
                ),
            ),
            "ensure_live_active": action(
                "ensure_live_active",
                direct("ios-twitch-observe-foreground", "app.observe_foreground"),
                direct(
                    "ios-twitch-hid-play",
                    "media.ensure_playing",
                    parameters={"duration_seconds": 0.1},
                ),
            ),
            "ensure_paused": action(
                "ensure_paused",
                direct(
                    "ios-twitch-hid-pause",
                    "media.ensure_paused",
                    parameters={"duration_seconds": 0.1},
                ),
            ),
            "ensure_playing": action(
                "ensure_playing",
                direct(
                    "ios-twitch-hid-resume",
                    "media.ensure_playing",
                    parameters={"duration_seconds": 0.1},
                ),
            ),
            "return_to_live_home": action(
                "return_to_live_home",
                gesture(
                    "ios-twitch-player-swipe-down-to-feed",
                    "screen.swipe.relative.native",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={
                        "direction": "down",
                        "x_ratio": 0.5,
                        "start_y_ratio": 0.20,
                        "end_y_ratio": 0.84,
                        "duration_ms": 500,
                        "native_hold_ms": 80,
                    },
                ),
            ),
            "switch_live_room": action(
                "switch_live_room",
                element_capability(
                    "ios-twitch-alternate-live-card",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=card_parameters,
                ),
            ),
        }
    )
    selectors = {
        "twitch_theater": SemanticSelector(
            accessibility_ids=("theater-view",),
            roles=("other",),
        ),
        "twitch_home_tab": SemanticSelector(
            accessibility_ids=("Feed",),
            exact_texts=("主页",),
            roles=("button",),
        ),
        "twitch_turbo_offer": SemanticSelector(
            text_patterns=(r"Twitch Turbo|免费获取 Twitch 无广告观赏",),
            require_enabled=False,
        ),
        "twitch_turbo_later": SemanticSelector(
            accessibility_ids=("下次再说",),
            exact_texts=("下次再说",),
            roles=("button",),
            require_clickable=True,
        ),
    }
    element_queries = {
        "twitch_theater": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": "name == 'theater-view'",
                "result_limit": 1,
                "attribute_names": ("name", "visible"),
                "defaults": {"visible": True, "enabled": True},
            },
        ),
        "twitch_home_tab": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "accessibility id",
                "value": "Feed",
                "result_limit": 1,
                "attribute_names": ("name", "label", "visible"),
                "defaults": {"visible": True, "enabled": True},
            },
        ),
    }
    binding = AppBinding(
        "ios-twitch-live-stream",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        interruptions=(
            InterruptionRule(
                "twitch-turbo-offer-dismiss",
                InterruptionKind.BENIGN,
                "twitch_turbo_offer",
                "twitch_turbo_later",
                auto_resolve=True,
                timeout_seconds=8.0,
                max_occurrences=2,
                step_ids=("launch-app", "enter-live-room"),
            ),
        ),
        element_queries=element_queries,
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "entry_evidence": (
                "full-width live-feed cell with viewer-count descendant text, "
                "bounded pre-scroll, and at least one native theater marker"
            ),
            "playback_transport": "WDA HID media controls",
            "playback_evidence": (
                "entry and pause/resume use local frame motion; sustained monitoring "
                "uses frame motion or recent host-filtered capture activity"
            ),
            "room_switch": "new feed card selected on each restarted sample",
        },
    )
    room = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "twitch_theater"),
        ),
    )
    playing = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
        ),
    )
    paused = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.STATE_EQUALS, "motion.playback", "paused"),
        ),
    )
    monitored_playing = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(
                ConditionKind.ANY,
                children=(
                    Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
                    Condition(
                        ConditionKind.STATE_EQUALS,
                        "network.capture_activity",
                        "active",
                    ),
                ),
            ),
        ),
    )
    home = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "twitch_home_tab"),
        ),
    )
    recovery_wait = WaitPolicy(
        timeout_seconds=min(transition_timeout_seconds, 8.0),
        poll_interval_seconds=0.5,
        observation_level=ObservationLevel.VISUAL,
    )
    needs_room_switch = switch_room or any(
        decision.label == "switch_room" for decision in human_activity
    )
    preparation = LiveStreamPreparation(
        before_switch=(
            Step(
                "return-twitch-home-before-switch",
                "return_to_live_home",
                home,
                wait=recovery_wait,
                skip_if_satisfied=False,
            ),
        ) if needs_room_switch else (),
        active_recovery=(
            Step(
                "restore-twitch-playback",
                "ensure_playing",
                playing,
                wait=recovery_wait,
                skip_if_satisfied=True,
            ),
        ),
        monitor_recovery=(
            Step(
                "restore-twitch-playback-monitor",
                "ensure_playing",
                monitored_playing,
                wait=recovery_wait,
                retry=RetryPolicy(2),
                recovery=(
                    Step(
                        "return-twitch-home-after-ended-room",
                        "return_to_live_home",
                        home,
                        wait=recovery_wait,
                        retry=RetryPolicy(1),
                        skip_if_satisfied=True,
                    ),
                    Step(
                        "enter-twitch-replacement-room",
                        "enter_live_room",
                        playing,
                        wait=WaitPolicy(
                            timeout_seconds=max(transition_timeout_seconds, 20.0),
                            poll_interval_seconds=0.5,
                            observation_level=ObservationLevel.VISUAL,
                        ),
                        retry=RetryPolicy(1),
                        skip_if_satisfied=False,
                    ),
                ),
                safe_retry_after_recovery=True,
                skip_if_satisfied=True,
            ),
        ),
        monitor_max_consecutive_misses=30,
        monitor_max_recoveries=3,
    )
    playbook = build_live_stream_playbook(
        LiveStreamTask(
            run_pause_resume=run_pause_resume,
            switch_room=switch_room,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        LiveStreamVerification(
            room_entered=room,
            active=playing,
            paused=paused,
            playing=playing,
            room_switched=playing,
            monitored_active=monitored_playing,
        ),
        preparation,
    )
    return binding, playbook


def _build_ios_huya(
    app: RegisteredApp,
    *,
    run_pause_resume: bool,
    switch_room: bool,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    def room_card_parameters(
        *,
        initial_scrolls: int = 0,
        avoid_recent: int = 0,
        selection_policy: str = "first_visible",
    ) -> dict[str, Any]:
        return {
            "include_pattern": r".{2,}",
            "exclude_pattern": (
                r"付费|交友|语音|电台|聊天|陪伴|点唱|唱歌|才艺|团播|"
                r"广告|推广|星秀"
            ),
            "accessibility_id_pattern": r"^HYGuessYouLikeCell$",
            "role_pattern": r"cell",
            "require_clickable": True,
            "min_width_ratio": 0.4,
            "max_width_ratio": 0.55,
            "min_height_ratio": 0.2,
            "max_bottom_ratio": 0.9,
            "candidate_initial_scrolls": initial_scrolls,
            "candidate_max_scrolls": max(initial_scrolls, 4),
            "candidate_scroll_duration_ms": 550,
            "candidate_snapshot_max_depth": 50,
            "candidate_wait_seconds": transition_timeout_seconds,
            "candidate_poll_seconds": 1.0,
            "candidate_history_key": "huya_live_room",
            "candidate_avoid_recent": avoid_recent,
            "selection_policy": selection_policy,
        }

    actions = lifecycle_actions()
    actions.update(
        {
            "enter_live_room": action(
                "enter_live_room",
                element_capability(
                    "ios-huya-semantic-room-card",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=room_card_parameters(),
                ),
            ),
            "ensure_live_active": action(
                "ensure_live_active",
                direct("ios-huya-observe-foreground", "app.observe_foreground"),
            ),
            "ensure_playing": action(
                "ensure_playing",
                direct("ios-huya-observe-playing", "app.observe_foreground"),
            ),
            "return_to_live_home": action(
                "return_to_live_home",
                gesture(
                    "ios-huya-edge-swipe-room-back",
                    "screen.swipe.relative.native",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={
                        "direction": "right",
                        "start_x_ratio": 0.01,
                        "end_x_ratio": 0.82,
                        "y_ratio": 0.5,
                        "duration_ms": 450,
                        "native_hold_ms": 80,
                    },
                ),
            ),
            "switch_live_room": action(
                "switch_live_room",
                element_capability(
                    "ios-huya-scrolled-alternate-room-card",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=room_card_parameters(
                        initial_scrolls=1,
                        avoid_recent=2,
                        selection_policy="nearest_point",
                    ),
                ),
            ),
            "advance_live_candidates": action(
                "advance_live_candidates",
                gesture(
                    "ios-huya-advance-home-feed",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "up", "duration_ms": 550},
                ),
            ),
            "refresh_live_home": action(
                "refresh_live_home",
                gesture(
                    "ios-huya-pull-to-refresh-live-home",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "down", "duration_ms": 700},
                ),
            ),
        }
    )
    binding = AppBinding(
        "ios-huya-live-stream",
        app.platform,
        app.app_id,
        selectors={
            "huya_home_feed": SemanticSelector(
                accessibility_ids=("recommend_page_collectionview",),
                roles=("collectionview",),
            ),
        },
        actions=actions,
        element_queries={
            "huya_home_feed": ElementObservationQuery(
                "observation.element.query",
                {
                    "using": "predicate string",
                    "value": "name == 'recommend_page_collectionview'",
                    "result_limit": 1,
                    "attribute_names": ("name", "visible"),
                    "defaults": {"visible": True, "enabled": True},
                },
            ),
        },
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "entry_evidence": (
                "native HYGuessYouLikeCell excluding paid/social/star-show cards, "
                "plus verified frame motion"
            ),
            "pause_resume": "disabled because Huya exposes pause only in full screen",
            "room_switch": (
                "source-free relative edge-swipe room back, one bounded home-feed scroll, random target-aware "
                "semantic card excluding the two most recent rooms, and renewed frame motion"
            ),
            "static_frame_policy": (
                "entry and room switches require renewed frame motion; after verified entry, "
                "monitoring tolerates local motion state paused because Huya has no pause action"
            ),
        },
    )
    active = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
        ),
    )
    monitored_active = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(
                ConditionKind.ANY,
                children=(
                    Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
                    Condition(ConditionKind.STATE_EQUALS, "motion.playback", "paused"),
                ),
            ),
        ),
    )
    changed_active = Condition(
        ConditionKind.ALL,
        children=(
            active,
            Condition(ConditionKind.STATE_CHANGED, "visual.frame_fingerprint"),
        ),
    )
    switch_wait = WaitPolicy(
        timeout_seconds=transition_timeout_seconds,
        poll_interval_seconds=0.5,
        observation_level=ObservationLevel.STRUCTURED,
    )
    home_ready = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "huya_home_feed"),
        ),
    )
    preparation = LiveStreamPreparation(
        before_enter=(
            Step(
                "wait-huya-home-ready",
                "refresh_live_home",
                home_ready,
                wait=switch_wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=True,
            ),
        ),
        enter_recovery=(
            Step(
                "return-huya-home-before-entry-retry",
                "return_to_live_home",
                home_ready,
                wait=switch_wait,
                skip_if_satisfied=True,
            ),
            Step(
                "advance-huya-entry-candidates",
                "advance_live_candidates",
                Condition(ConditionKind.STATE_CHANGED, "ui.layout_fingerprint"),
                wait=switch_wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=False,
            ),
        ),
        enter_retry_safe=True,
        before_switch=(
            Step(
                "return-huya-live-home",
                "return_to_live_home",
                home_ready,
                wait=switch_wait,
                retry=RetryPolicy(3),
                skip_if_satisfied=False,
            ),
            Step(
                "ensure-huya-home-feed-loaded",
                "refresh_live_home",
                home_ready,
                wait=switch_wait,
                retry=RetryPolicy(2),
                skip_if_satisfied=True,
            ),
        ),
        monitor_max_consecutive_misses=10,
    )
    verification = LiveStreamVerification(
        room_entered=changed_active,
        active=active,
        monitored_active=monitored_active,
        paused=Condition(
            ConditionKind.ALL,
            children=(
                active,
                Condition(ConditionKind.STATE_EQUALS, "motion.playback", "paused"),
            ),
        ),
        playing=active,
        room_switched=changed_active,
    )
    playbook = build_live_stream_playbook(
        LiveStreamTask(
            run_pause_resume=False,
            switch_room=switch_room,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
        preparation,
    )
    return binding, playbook


def _activity_hint(value: str) -> str:
    if "/" not in value:
        return value
    package, activity = value.split("/", 1)
    return package + activity if activity.startswith(".") else activity
