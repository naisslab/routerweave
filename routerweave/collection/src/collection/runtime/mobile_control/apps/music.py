"""Bindings for the shared music task family."""

from __future__ import annotations

from ..binding import ActionStrategy, AppBinding, ElementObservationQuery
from ..catalog import MobileAppCatalog, RegisteredApp
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..playbook import Playbook
from ..playbooks.music import MusicTask, MusicVerification, build_music_playbook
from ..playbooks.human_activity import HumanActivityDecision
from ..perception import SemanticSelector
from ..status import ActionMethod, Idempotency, Platform
from .common import action, direct, lifecycle_actions


_ANDROID_PLAY_RESOURCE = {
    "qqmusic": "com.tencent.qqmusic:id/fze",
    "netease": "com.netease.cloudmusic:id/minPlayBtn",
    "spotify": "com.spotify.music:id/play_pause_button",
}


def _element_query(
    strategy_id: str,
    *,
    resource_id: str = "",
    exact_text: str = "",
) -> ActionStrategy:
    parameters = {
        key: value
        for key, value in {"resource_id": resource_id, "exact_text": exact_text}.items()
        if value
    }
    return ActionStrategy(
        strategy_id,
        ActionMethod.ELEMENT,
        Idempotency.STATE_SETTING,
        capability="element.activate.query",
        parameters=parameters,
    )


def _ios_element_query(
    strategy_id: str,
    value: str,
    idempotency: Idempotency,
    *,
    using: str = "xpath",
    match_index: int | None = None,
) -> ActionStrategy:
    parameters: dict[str, object] = {"using": using, "value": value}
    if match_index is not None:
        parameters["match_index"] = match_index
    return ActionStrategy(
        strategy_id,
        ActionMethod.ELEMENT,
        idempotency,
        capability="element.activate.query",
        parameters=parameters,
    )


_IOS_QQMUSIC_MINI = (
    "//XCUIElementTypeOther[@visible='true' and @hittable='true' and "
    "XCUIElementTypeButton[@name='MiniPlayerSongListButton' and @visible='true']]"
)


def _build_ios_qqmusic_session(
    app: RegisteredApp,
    *,
    leave_app_open: bool,
    restart_app: bool,
    run_pause_resume: bool,
    advance_track: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    play_xpath = (
        f"{_IOS_QQMUSIC_MINI}/XCUIElementTypeButton"
        "[@name='播放' and @visible='true' and @accessible='true']"
    )
    pause_xpath = (
        f"{_IOS_QQMUSIC_MINI}/XCUIElementTypeButton"
        "[@name='暂停' and @visible='true' and @accessible='true']"
    )
    next_xpath = (
        f"{_IOS_QQMUSIC_MINI}/XCUIElementTypeButton"
        "[@name='下一首' and @visible='true']"
    )
    track_xpath = (
        f"{_IOS_QQMUSIC_MINI}/XCUIElementTypeOther"
        "[@accessible='true' and @visible='true'][1]"
    )
    return _build_ios_native_music_session(
        app,
        play_query=("xpath", play_xpath),
        pause_query=("xpath", pause_xpath),
        track_query=("xpath", track_xpath),
        play_selector=SemanticSelector(
            accessibility_ids=("播放",),
            roles=("button",),
            attributes={"hittable": True},
        ),
        pause_selector=SemanticSelector(
            accessibility_ids=("暂停",),
            roles=("button",),
            attributes={"hittable": True},
        ),
        next_strategy=_ios_element_query(
            "ios-mini-player-next",
            next_xpath,
            Idempotency.NON_IDEMPOTENT,
        ),
        playback_transport="exact native controls",
        hid_policy="capability available but excluded by current app evidence",
        leave_app_open=leave_app_open,
        restart_app=restart_app,
        run_pause_resume=run_pause_resume,
        advance_track=advance_track,
        transition_timeout_seconds=transition_timeout_seconds,
        monitor_seconds=monitor_seconds,
        human_activity=human_activity,
    )


def _build_ios_spotify_session(
    app: RegisteredApp,
    **task_parameters,
) -> tuple[AppBinding, Playbook]:
    control_id = "SPTNowPlayingPlayButton"
    play_query = (
        "predicate string",
        f"name == '{control_id}' AND label == '播放' AND visible == 1",
    )
    pause_query = (
        "predicate string",
        f"name == '{control_id}' AND label == '暂停' AND visible == 1",
    )
    track_query = (
        "predicate string",
        "name == 'Components.UI.PageInformationUnitNowPlayingBar' AND visible == 1",
    )
    open_player_strategy = _ios_element_query(
        "ios-spotify-open-first-playable-row",
        "name == 'Components.UI.RetrievalRowElementUI_Loaded' AND visible == 1",
        Idempotency.NON_IDEMPOTENT,
        using="predicate string",
        match_index=0,
    )
    return _build_ios_native_music_session(
        app,
        play_query=play_query,
        pause_query=pause_query,
        track_query=track_query,
        play_selector=SemanticSelector(
            accessibility_ids=(control_id,),
            text_patterns=(r"^播放$",),
            roles=("button",),
            attributes={"hittable": True},
        ),
        pause_selector=SemanticSelector(
            accessibility_ids=(control_id,),
            text_patterns=(r"^暂停$",),
            roles=("button",),
            attributes={"hittable": True},
        ),
        next_strategy=direct(
            "ios-spotify-hid-next",
            "media.next",
            idempotency=Idempotency.NON_IDEMPOTENT,
        ),
        open_player_strategy=open_player_strategy,
        playback_transport="exact native play/pause control plus HID next",
        hid_policy="next only; play and pause use the exposed native control",
        **task_parameters,
    )


def _build_ios_netease_session(
    app: RegisteredApp,
    *,
    leave_app_open: bool,
    restart_app: bool,
    run_pause_resume: bool,
    advance_track: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    profile = MobileAppCatalog.from_repository().profile(app.platform, app.name)
    native_play_control = str(profile.get("native_play_control") or "")
    native_play_fallback = ()
    if native_play_control:
        native_play_fallback = (
            _ios_element_query(
                "ios-netease-native-play-fallback",
                "type == 'XCUIElementTypeButton' AND "
                f"name == '{native_play_control}' AND visible == 1",
                Idempotency.STATE_SETTING,
                using="predicate string",
            ),
        )
    actions = lifecycle_actions()
    actions.update(
        {
            "start_music_playback": action(
                "start_music_playback",
                direct("ios-netease-hid-play", "media.ensure_playing"),
                *native_play_fallback,
            ),
            "ensure_playing": action(
                "ensure_playing",
                direct("ios-netease-hid-resume", "media.ensure_playing"),
                *native_play_fallback,
            ),
            "ensure_paused": action(
                "ensure_paused",
                direct("ios-netease-hid-pause", "media.ensure_paused"),
            ),
            "advance_track": action(
                "advance_track",
                direct(
                    "ios-netease-hid-next",
                    "media.next",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                ),
            ),
        }
    )
    binding = AppBinding(
        f"ios-{app.name}-music",
        app.platform,
        app.app_id,
        actions=actions,
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "playback_transport": "iOS HID media controls with native play fallback",
            "hid_policy": "play, pause, and next with local mini-player glyph evidence; native play fallback after an ineffective HID command",
            "visual_evidence": "bottom music mini-player state and track fingerprint",
        },
    )
    verification = MusicVerification(
        player_ready=Condition(
            ConditionKind.ANY,
            children=(
                Condition(
                    ConditionKind.STATE_EQUALS,
                    "visual.music_mini_player.playback",
                    "playing",
                ),
                Condition(
                    ConditionKind.STATE_EQUALS,
                    "visual.music_mini_player.playback",
                    "paused",
                ),
            ),
        ),
        playing=Condition(
            ConditionKind.STATE_EQUALS,
            "visual.music_mini_player.playback",
            "playing",
        ),
        paused=Condition(
            ConditionKind.STATE_EQUALS,
            "visual.music_mini_player.playback",
            "paused",
        ),
        track_changed=Condition(
            ConditionKind.STATE_CHANGED,
            "visual.music_mini_player.identity",
        ),
    )
    return binding, build_music_playbook(
        MusicTask(
            open_player=False,
            run_pause_resume=run_pause_resume,
            advance_track=advance_track,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )


def _build_ios_native_music_session(
    app: RegisteredApp,
    *,
    play_query: tuple[str, str],
    pause_query: tuple[str, str],
    track_query: tuple[str, str],
    play_selector: SemanticSelector,
    pause_selector: SemanticSelector,
    next_strategy: ActionStrategy,
    open_player_strategy: ActionStrategy | None = None,
    playback_transport: str,
    hid_policy: str,
    leave_app_open: bool,
    restart_app: bool,
    run_pause_resume: bool,
    advance_track: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    def query_strategy(strategy_id: str, query: tuple[str, str]) -> ActionStrategy:
        return _ios_element_query(
            strategy_id,
            query[1],
            Idempotency.STATE_SETTING,
            using=query[0],
        )

    actions = lifecycle_actions()
    actions.update(
        {
            "start_music_playback": action(
                "start_music_playback",
                query_strategy("ios-native-player-play", play_query),
            ),
            "ensure_playing": action(
                "ensure_playing",
                query_strategy("ios-native-player-resume", play_query),
            ),
            "ensure_paused": action(
                "ensure_paused",
                query_strategy("ios-native-player-pause", pause_query),
            ),
            "advance_track": action("advance_track", next_strategy),
        }
    )
    if open_player_strategy is not None:
        actions["open_music_player"] = action(
            "open_music_player",
            open_player_strategy,
        )
    binding = AppBinding(
        f"ios-{app.name}-music",
        app.platform,
        app.app_id,
        selectors={
            "player_play": play_selector,
            "player_pause": pause_selector,
            "track_identity": SemanticSelector(
                text_patterns=(r".+",),
                roles=("other",),
                ambiguity_margin=0,
            ),
        },
        actions=actions,
        element_queries={
            "player_play": ElementObservationQuery(
                "observation.element.query",
                {"using": play_query[0], "value": play_query[1]},
            ),
            "player_pause": ElementObservationQuery(
                "observation.element.query",
                {"using": pause_query[0], "value": pause_query[1]},
            ),
            "track_identity": ElementObservationQuery(
                "observation.element.query",
                {"using": track_query[0], "value": track_query[1]},
            ),
        },
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "playback_transport": playback_transport,
            "hid_policy": hid_policy,
        },
    )
    verification = MusicVerification(
        player_ready=Condition(
            ConditionKind.ANY,
            children=(
                Condition(ConditionKind.ELEMENT_PRESENT, "player_play"),
                Condition(ConditionKind.ELEMENT_PRESENT, "player_pause"),
            ),
        ),
        playing=Condition(ConditionKind.ELEMENT_PRESENT, "player_pause"),
        paused=Condition(ConditionKind.ELEMENT_PRESENT, "player_play"),
        track_changed=Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "track_identity"),
    )
    playbook = build_music_playbook(
        MusicTask(
            open_player=open_player_strategy is not None,
            run_pause_resume=run_pause_resume,
            advance_track=advance_track,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )
    return binding, playbook


def build_music_session(
    app: RegisteredApp,
    *,
    leave_app_open: bool = False,
    restart_app: bool = True,
    run_pause_resume: bool = True,
    advance_track: bool = True,
    transition_timeout_seconds: float = 10.0,
    monitor_seconds: float = 0.0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
) -> tuple[AppBinding, Playbook]:
    if app.task_family != "music":
        raise ValueError(f"{app.name!r} is not a music application")
    if app.platform is Platform.IOS:
        builder = {
            "qqmusic": _build_ios_qqmusic_session,
            "netease": _build_ios_netease_session,
            "spotify": _build_ios_spotify_session,
        }.get(app.name)
        if builder is None:
            raise NotImplementedError(f"no verified iOS music binding for {app.name!r}")
        return builder(
            app,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            run_pause_resume=run_pause_resume,
            advance_track=advance_track,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        )
    if app.platform is not Platform.ANDROID:
        raise NotImplementedError(f"unsupported music platform {app.platform.value!r}")

    profile = MobileAppCatalog.from_repository().profile(app.platform, app.name)
    play_resources = tuple(profile.get("music_play_resource_ids") or
                           (_ANDROID_PLAY_RESOURCE.get(app.name, ""),))
    start_strategies: tuple[ActionStrategy, ...]
    control_fallbacks: tuple[ActionStrategy, ...]
    if all(play_resources):
        start_strategies = tuple(
            _element_query("activate-current-player" + (f"-{index}" if index else ""), resource_id=resource)
            for index, resource in enumerate(play_resources)
        )
        control_fallbacks = tuple(
            _element_query("activate-current-player-fallback" + (f"-{index}" if index else ""), resource_id=resource)
            for index, resource in enumerate(play_resources)
        )
        pause_fallbacks = tuple(
            _element_query("activate-current-player-pause" + (f"-{index}" if index else ""), resource_id=resource)
            for index, resource in enumerate(play_resources)
        )
        selectors = {
            "play_control": SemanticSelector(
                resource_ids=play_resources,
                require_clickable=app.name != "spotify",
            )
        }
    else:
        raise NotImplementedError(f"no verified Android music binding for {app.name!r}")

    play_strategies = (
        direct(
            "android-media-keyevent-play",
            "media.ensure_playing",
            parameters={"injection": "keyevent"},
        ),
        *control_fallbacks,
    )
    pause_strategies = (
        direct(
            "android-media-keyevent-pause",
            "media.ensure_paused",
            parameters={"injection": "keyevent"},
        ),
        *pause_fallbacks,
    )

    actions = lifecycle_actions()
    actions.update(
        {
            "start_music_playback": action("start_music_playback", *start_strategies),
            "ensure_playing": action(
                "ensure_playing",
                *play_strategies,
            ),
            "ensure_paused": action(
                "ensure_paused",
                *pause_strategies,
            ),
            "advance_track": action(
                "advance_track",
                direct(
                    "android-media-next",
                    "media.next",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters={"injection": "keyevent"},
                ),
            ),
        }
    )
    prompt = profile.get("notification_prompt")
    interruptions = []
    if prompt:
        selectors["notification_prompt"] = SemanticSelector(
            exact_texts=(str(prompt["title"]),),
            attributes={"package": app.app_id},
        )
        selectors["notification_prompt_deny"] = SemanticSelector(
            exact_texts=(str(prompt["deny_text"]),),
            attributes={"package": app.app_id},
            require_clickable=True,
        )
        interruptions.append(InterruptionRule(
            "music-notification-prompt-deny", InterruptionKind.PERMISSION,
            "notification_prompt", "notification_prompt_deny", auto_resolve=True,
            max_occurrences=2, timeout_seconds=6.0,
        ))
    invitation = profile.get("optional_invitation")
    if invitation:
        selectors["optional_invitation"] = SemanticSelector(
            exact_texts=(str(invitation["title"]),),
            attributes={"package": app.app_id},
        )
        selectors["optional_invitation_decline"] = SemanticSelector(
            exact_texts=(str(invitation["decline_text"]),),
            attributes={"package": app.app_id},
        )
        interruptions.append(InterruptionRule(
            "music-optional-invitation-decline", InterruptionKind.BENIGN,
            "optional_invitation", "optional_invitation_decline", auto_resolve=True,
            max_occurrences=2, timeout_seconds=6.0,
        ))
    binding = AppBinding(
        f"android-{app.name}-music",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        interruptions=tuple(interruptions),
        metadata={"app_name": app.name, "task_family": app.task_family},
    )
    verification = MusicVerification(
        player_ready=Condition(ConditionKind.ELEMENT_PRESENT, "play_control"),
        playing=Condition(ConditionKind.STATE_EQUALS, "media.playback", "playing"),
        paused=Condition(ConditionKind.STATE_EQUALS, "media.playback", "paused"),
        track_changed=Condition(ConditionKind.STATE_CHANGED, "media.identity"),
    )
    playbook = build_music_playbook(
        MusicTask(
            open_player=False,
            run_pause_resume=run_pause_resume,
            advance_track=advance_track,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )
    return binding, playbook
