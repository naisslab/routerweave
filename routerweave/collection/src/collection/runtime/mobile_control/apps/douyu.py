"""Verified Android and iOS bindings for the shared live-stream task family."""

from __future__ import annotations

from dataclasses import dataclass

from ..binding import (
    ActionBinding,
    ActionStrategy,
    AppBinding,
    ElementObservationQuery,
)
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..perception import PageDefinition, SemanticSelector
from ..playbook import Playbook, RetryPolicy, Step, WaitPolicy
from ..playbooks.live_stream import (
    LiveStreamPreparation,
    LiveStreamTask,
    LiveStreamVerification,
    build_live_stream_playbook,
)
from ..playbooks.human_activity import HumanActivityDecision
from ..status import ActionMethod, Idempotency, ObservationLevel, Platform


ANDROID_APP_ID = "air.tv.douyu.android"
IOS_APP_ID = "tv.douyu.live"


@dataclass(frozen=True, slots=True)
class DouyuRoom:
    room_id: str
    anchor: str = ""

    def validate(self) -> None:
        if not self.room_id.isascii() or not self.room_id.isdigit():
            raise ValueError("Douyu room_id must contain ASCII digits only")

    @property
    def identity_texts(self) -> tuple[str, str]:
        return (
            f"斗鱼 房间号:{self.room_id}",
            f"斗鱼 房间号: {self.room_id}",
        )


def _action(name: str, *strategies: ActionStrategy) -> ActionBinding:
    return ActionBinding(name, tuple(strategies))


def _quick_wait(timeout: float = 1.0) -> WaitPolicy:
    return WaitPolicy(
        timeout_seconds=timeout,
        poll_interval_seconds=0.2,
        observation_level=ObservationLevel.FAST,
    )


def _preparation_step(step_id: str, semantic_action: str) -> Step:
    return Step(
        step_id,
        semantic_action,
        Condition.true(),
        wait=_quick_wait(),
        retry=RetryPolicy(max_attempts=1),
        skip_if_satisfied=False,
    )


def _scan_step(step_id: str) -> Step:
    return Step(
        step_id,
        None,
        Condition.true(),
        wait=_quick_wait(),
        retry=RetryPolicy(max_attempts=1),
        skip_if_satisfied=False,
    )


def _xpath_literal(value: str) -> str:
    """Return an XPath 1.0 string literal without accepting query injection."""

    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    joined: list[str] = []
    for index, part in enumerate(parts):
        if part:
            joined.append(f"'{part}'")
        if index < len(parts) - 1:
            joined.append('"\'"')
    return "concat(" + ",".join(joined) + ")"


def _base_selectors(primary_room: DouyuRoom | None) -> dict[str, SemanticSelector]:
    selectors = {
        "room_identity": SemanticSelector(
            text_patterns=(r"^斗鱼\s*房间号:\s*\d+$",),
            roles=("textview", "statictext"),
        ),
    }
    if primary_room is not None:
        selectors["primary_room_identity"] = SemanticSelector(
            exact_texts=primary_room.identity_texts,
            roles=("textview", "statictext"),
        )
    return selectors


def _common_actions() -> dict[str, ActionBinding]:
    return {
        "reset_app": _action(
            "reset_app",
            ActionStrategy(
                "terminate-before-session",
                ActionMethod.DIRECT,
                Idempotency.STATE_SETTING,
                capability="app.terminate",
            ),
        ),
        "launch_app": _action(
            "launch_app",
            ActionStrategy(
                "launch-douyu",
                ActionMethod.DIRECT,
                Idempotency.STATE_SETTING,
                capability="app.launch",
            ),
        ),
        "terminate_app": _action(
            "terminate_app",
            ActionStrategy(
                "terminate-douyu",
                ActionMethod.DIRECT,
                Idempotency.STATE_SETTING,
                capability="app.terminate",
            ),
        ),
    }


def _android_binding(
    primary_room: DouyuRoom,
    switch_room: DouyuRoom | None,
) -> tuple[AppBinding, LiveStreamPreparation, LiveStreamVerification]:
    selectors = _base_selectors(primary_room)
    selectors.update(
        {
            "loading_retry": SemanticSelector(
                resource_ids=(f"{ANDROID_APP_ID}:id/ag1",),
                exact_texts=("重试",),
                roles=("button",),
                require_clickable=True,
            ),
            "floating_ad_close": SemanticSelector(
                resource_ids=(f"{ANDROID_APP_ID}:id/dc1",),
                roles=("imageview",),
                require_clickable=True,
            ),
            "panel_close": SemanticSelector(
                resource_ids=(f"{ANDROID_APP_ID}:id/a60",),
                roles=("imageview",),
                require_clickable=True,
            ),
        }
    )
    actions = _common_actions()
    actions.update(
        {
            "enter_live_room": _action(
                "enter_live_room",
                ActionStrategy(
                    "open-douyu-room-deeplink",
                    ActionMethod.DIRECT,
                    Idempotency.STATE_SETTING,
                    capability="app.open_url",
                    parameters={"url": f"douyuapp://room?rid={primary_room.room_id}"},
                ),
            ),
            "ensure_live_active": _action(
                "ensure_live_active",
                ActionStrategy(
                    "retry-failed-live-load",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={"resource_id": f"{ANDROID_APP_ID}:id/ag1"},
                ),
            ),
        }
    )
    if switch_room is not None:
        actions["switch_live_room"] = _action(
            "switch_live_room",
            ActionStrategy(
                "open-next-douyu-room-deeplink",
                ActionMethod.DIRECT,
                Idempotency.STATE_SETTING,
                capability="app.open_url",
                parameters={"url": f"douyuapp://room?rid={switch_room.room_id}"},
            ),
        )

    preparation = LiveStreamPreparation(
        active_recovery=(
            _scan_step("scan-known-interruptions-initial-active"),
        ),
        switched_active_recovery=(
            _scan_step("scan-known-interruptions-switched-active"),
        ),
    )
    verification = LiveStreamVerification(
        room_entered=Condition(ConditionKind.ELEMENT_PRESENT, "primary_room_identity"),
        active=Condition(ConditionKind.STATE_EQUALS, "audio.playback", "playing"),
        paused=Condition(ConditionKind.STATE_EQUALS, "audio.playback", "inactive"),
        playing=Condition(ConditionKind.STATE_EQUALS, "audio.playback", "playing"),
        room_switched=Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "room_identity"),
    )
    binding = AppBinding(
        "douyu-android-live",
        Platform.ANDROID,
        ANDROID_APP_ID,
        selectors=selectors,
        pages={"live_room": PageDefinition(required=("room_identity",))},
        actions=actions,
        interruptions=(
            InterruptionRule(
                "douyu-floating-ad",
                InterruptionKind.BENIGN,
                "floating_ad_close",
                "floating_ad_close",
                auto_resolve=True,
                timeout_seconds=4.0,
                max_occurrences=1,
                step_ids=("scan-known-interruptions",),
            ),
            InterruptionRule(
                "douyu-panel-close",
                InterruptionKind.BENIGN,
                "panel_close",
                "panel_close",
                auto_resolve=True,
                timeout_seconds=4.0,
                max_occurrences=1,
                step_ids=("scan-known-interruptions",),
            ),
        ),
        metadata={
            "entry_path": "verified douyuapp room deep link",
            "playback_control": "current Android build does not expose stable pause/resume",
            "room_switch": "verified room-id deep link plus identity change",
        },
    )
    return binding, preparation, verification


def _ios_binding(
    primary_room: DouyuRoom | None,
    switch_room: DouyuRoom | None,
) -> tuple[AppBinding, LiveStreamPreparation, LiveStreamVerification]:
    game_categories = (
        "DOTA2",
        "英雄联盟",
        "炉石传说",
        "使命召唤",
        "无畏契约",
        "王者荣耀",
        "和平精英",
        "穿越火线",
        "CS2",
        "永劫无间",
        "三角洲行动",
        "燕云十六声",
    )
    game_category_predicate = " or ".join(
        f"@name = {_xpath_literal(category)}" for category in game_categories
    )
    game_card_candidates_xpath = (
        "//XCUIElementTypeCell[@visible='true']["
        ".//XCUIElementTypeButton[@visible='true' and ("
        f"{game_category_predicate}"
        ")]]"
    )
    game_card_xpath = f"({game_card_candidates_xpath})[1]"
    replacement_game_card_xpath = f"({game_card_candidates_xpath})[2]"
    game_card_candidate_parameters = {
        "include_pattern": "|".join(game_categories),
        "exclude_pattern": (
            r"交友|语音|电台|聊天|陪伴|点唱|唱歌|才艺|团播|广告|推广"
        ),
        "role_pattern": r"cell",
        "require_clickable": True,
        "min_width_ratio": 0.35,
        "min_height_ratio": 0.15,
        "max_bottom_ratio": 0.95,
        "candidate_max_scrolls": 2,
        "candidate_snapshot_max_depth": 50,
        "candidate_wait_seconds": 20.0,
        "candidate_poll_seconds": 1.0,
        "candidate_history_key": "douyu_game_live_room",
    }
    selectors = _base_selectors(primary_room)
    selectors["room_identity"] = SemanticSelector(
        text_patterns=(r"^斗鱼\s*房间号:\s*\d+$",),
        roles=("statictext",),
        require_visible=False,
    )
    selectors.update(
        {
            "home_search": SemanticSelector(
                accessibility_ids=("home_search_nav2",),
                roles=("image",),
                require_clickable=True,
            ),
            "home_game_category": SemanticSelector(
                exact_texts=game_categories,
                roles=("statictext",),
                ambiguity_margin=0,
            ),
            "home_game_card": SemanticSelector(
                roles=("cell",),
                require_clickable=True,
                minimum_score=20,
                ambiguity_margin=0,
            ),
            "room_search_field": SemanticSelector(
                roles=("textfield",),
                minimum_score=20,
            ),
            "young_mode_marker": SemanticSelector(
                accessibility_ids=("dy_home_young_center",),
                roles=("image",),
            ),
            "young_mode_dismiss": SemanticSelector(
                exact_texts=("我知道了",),
                roles=("button",),
                require_clickable=True,
            ),
            "banner_ad_close": SemanticSelector(
                accessibility_ids=("xhAd rainbowBanner close dark",),
                roles=("button",),
                require_clickable=True,
            ),
            "pendant_ad_close": SemanticSelector(
                accessibility_ids=("pendant container close",),
                roles=("button",),
                require_clickable=True,
            ),
            "player_paused_state": SemanticSelector(
                accessibility_ids=("btn player pause",),
                roles=("button",),
                attributes={"value": "1"},
                require_visible=False,
            ),
        }
    )
    if primary_room is not None:
        selectors["primary_room_identity"] = SemanticSelector(
            exact_texts=primary_room.identity_texts,
            roles=("statictext",),
            require_visible=False,
        )
        selectors["room_search_result"] = SemanticSelector(
            text_patterns=(rf"房号\s*{primary_room.room_id}\b",),
            roles=("statictext",),
        )
    actions = _common_actions()
    room_predicates: list[str] = []
    if primary_room is not None:
        room_predicates.append(
            ".//XCUIElementTypeStaticText["
            f"contains(@name,{_xpath_literal(f'房号 {primary_room.room_id}')})]"
        )
    if primary_room is not None and primary_room.anchor:
        room_predicates.append(
            ".//XCUIElementTypeStaticText["
            f"@name = {_xpath_literal(primary_room.anchor)}]"
        )
    room_xpath = (
        "//XCUIElementTypeCell[" + " and ".join(room_predicates) + "]"
        if room_predicates
        else game_card_xpath
    )
    actions.update(
        {
            "open_room_search": _action(
                "open_room_search",
                ActionStrategy(
                    "activate-native-home-search",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeImage' AND visible == 1 AND "
                            "name == 'home_search_nav2'"
                        ),
                    },
                ),
            ),
            "replace_room_search": _action(
                "replace_room_search",
                ActionStrategy(
                    "replace-native-room-search-field",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.replace_text.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeTextField' AND visible == 1"
                        ),
                        "text": primary_room.room_id if primary_room is not None else "",
                    },
                ),
            ),
            "enter_live_room": _action(
                "enter_live_room",
                ActionStrategy(
                    "activate-room-id-search-result",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={"using": "xpath", "value": room_xpath},
                ),
            ),
            "exit_player_fullscreen": _action(
                "exit_player_fullscreen",
                ActionStrategy(
                    "activate-visible-fullscreen-toggle-for-exit",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeButton' AND visible == 1 AND "
                            "name == 'rpbplayer room icon fullscreen'"
                        ),
                    },
                ),
            ),
            "exit_live_room": _action(
                "exit_live_room",
                ActionStrategy(
                    "activate-native-live-room-back",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeButton' AND visible == 1 AND "
                            "name == 'rainbow top back black'"
                        ),
                    },
                ),
            ),
            "select_game_live_room": _action(
                "select_game_live_room",
                ActionStrategy(
                    "activate-first-visible-game-tagged-card",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={"using": "xpath", "value": game_card_xpath},
                ),
            ),
            "select_replacement_game_live_room": _action(
                "select_replacement_game_live_room",
                ActionStrategy(
                    "activate-second-visible-game-tagged-card-as-replacement",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "xpath",
                        "value": replacement_game_card_xpath,
                    },
                ),
                ActionStrategy(
                    "fallback-to-first-visible-game-tagged-card",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "xpath",
                        "value": game_card_xpath,
                    },
                ),
            ),
            "reveal_portrait_player_controls": _action(
                "reveal_portrait_player_controls",
                ActionStrategy(
                    "tap-portrait-player-surface",
                    ActionMethod.GESTURE,
                    Idempotency.NON_IDEMPOTENT,
                    capability="screen.tap.relative",
                    parameters={
                        "x_ratio": 0.5,
                        "y_ratio": 0.33,
                        "refresh_session_before": True,
                    },
                ),
            ),
            "enter_player_fullscreen": _action(
                "enter_player_fullscreen",
                ActionStrategy(
                    "activate-visible-fullscreen-control",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeButton' AND visible == 1 AND "
                            "name == 'rpbplayer room icon fullscreen'"
                        ),
                    },
                ),
            ),
            "reveal_fullscreen_player_controls": _action(
                "reveal_fullscreen_player_controls",
                ActionStrategy(
                    "tap-fullscreen-player-surface",
                    ActionMethod.GESTURE,
                    Idempotency.NON_IDEMPOTENT,
                    capability="screen.tap.relative",
                    parameters={
                        "x_ratio": 0.5,
                        "y_ratio": 0.48,
                        "refresh_session_before": True,
                    },
                ),
            ),
            "ensure_paused": _action(
                "ensure_paused",
                ActionStrategy(
                    "pause-douyu-with-native-player-control",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.candidate",
                    parameters={
                        "include_pattern": r"rpbplayer room icon pause",
                        "accessibility_id_pattern": r"^rpbplayer room icon pause$",
                        "role_pattern": r"button",
                        "require_clickable": True,
                        "candidate_snapshot_max_depth": 50,
                        "candidate_wait_seconds": 3.0,
                        "candidate_poll_seconds": 0.25,
                    },
                ),
            ),
            "ensure_playing": _action(
                "ensure_playing",
                ActionStrategy(
                    "resume-douyu-with-native-player-control",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.candidate",
                    parameters={
                        "include_pattern": r"rpbplayer room icon pause",
                        "accessibility_id_pattern": r"^rpbplayer room icon pause$",
                        "role_pattern": r"button",
                        "require_clickable": True,
                        "candidate_snapshot_max_depth": 50,
                        "candidate_wait_seconds": 3.0,
                        "candidate_poll_seconds": 0.25,
                    },
                ),
            ),
            "scroll_game_live_feed": _action(
                "scroll_game_live_feed",
                ActionStrategy(
                    "scroll-to-another-visible-game-card",
                    ActionMethod.GESTURE,
                    Idempotency.NON_IDEMPOTENT,
                    capability="screen.swipe.relative",
                    parameters={"direction": "up", "duration_ms": 450},
                ),
            ),
            "ensure_live_active": _action(
                "ensure_live_active",
                ActionStrategy(
                    "keep-douyu-playing-with-ios-hid",
                    ActionMethod.DIRECT,
                    Idempotency.STATE_SETTING,
                    capability="media.ensure_playing",
                ),
                ActionStrategy(
                    "reveal-controls-for-live-verification",
                    ActionMethod.GESTURE,
                    Idempotency.STATE_SETTING,
                    capability="screen.tap.relative",
                    parameters={"x_ratio": 0.5, "y_ratio": 0.48},
                ),
            ),
            "refresh_inactive_player": _action(
                "refresh_inactive_player",
                ActionStrategy(
                    "activate-visible-player-refresh",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeButton' AND visible == 1 AND "
                            "name == 'btn player refresh'"
                        ),
                    },
                ),
            ),
            "open_more_live": _action(
                "open_more_live",
                ActionStrategy(
                    "activate-more-live",
                    ActionMethod.ELEMENT,
                    Idempotency.STATE_SETTING,
                    capability="element.activate.query",
                    parameters={
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeButton' AND visible == 1 AND "
                            "name == '更多直播'"
                        ),
                    },
                ),
            ),
            "switch_live_room": _action(
                "switch_live_room",
                ActionStrategy(
                    "activate-first-visible-recommendation",
                    ActionMethod.ELEMENT,
                    Idempotency.NON_IDEMPOTENT,
                    capability="element.activate.query",
                    parameters={
                        "using": "xpath",
                        "value": (
                            "//XCUIElementTypeCollectionView[@visible='true' and "
                            "@width > 300 and @height > 300]"
                            "//XCUIElementTypeCell[@visible='true'][1]"
                        ),
                    },
                ),
            ),
        }
    )
    if primary_room is None:
        actions["enter_live_room"] = _action(
            "enter_live_room",
            ActionStrategy(
                "activate-current-game-tagged-card",
                ActionMethod.ELEMENT,
                Idempotency.STATE_SETTING,
                capability="element.activate.candidate",
                parameters=game_card_candidate_parameters,
            ),
            ActionStrategy(
                "fallback-to-first-visible-game-tagged-card",
                ActionMethod.ELEMENT,
                Idempotency.STATE_SETTING,
                capability="element.activate.query",
                parameters={"using": "xpath", "value": game_card_xpath},
            ),
        )
        actions["select_replacement_game_live_room"] = _action(
            "select_replacement_game_live_room",
            ActionStrategy(
                "activate-replacement-game-tagged-card",
                ActionMethod.ELEMENT,
                Idempotency.STATE_SETTING,
                capability="element.activate.candidate",
                parameters={
                    **game_card_candidate_parameters,
                    "candidate_initial_scrolls": 1,
                    "candidate_avoid_recent": 1,
                },
            ),
            ActionStrategy(
                "fallback-to-first-visible-game-tagged-card",
                ActionMethod.ELEMENT,
                Idempotency.STATE_SETTING,
                capability="element.activate.query",
                parameters={"using": "xpath", "value": game_card_xpath},
            ),
        )

    scan_open_search = _scan_step("scan-known-interruptions-open-search-recovery")
    scan_replace_search = _scan_step("scan-known-interruptions-replace-search-recovery")
    scan_enter = _scan_step("scan-known-interruptions-enter-recovery")
    reveal_portrait = _preparation_step(
        "reveal-portrait-controls-before-fullscreen",
        "reveal_portrait_player_controls",
    )
    enter_fullscreen = Step(
        "enter-player-fullscreen",
        "enter_player_fullscreen",
        Condition(ConditionKind.STATE_EQUALS, "device.orientation", "landscape"),
        wait=WaitPolicy(
            timeout_seconds=5.0,
            poll_interval_seconds=0.25,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(max_attempts=2),
        recovery=(
            _preparation_step(
                "reveal-portrait-controls-fullscreen-recovery",
                "reveal_portrait_player_controls",
            ),
        ),
        skip_if_satisfied=True,
    )
    reveal_pause = _preparation_step(
        "reveal-portrait-controls-before-pause",
        "reveal_portrait_player_controls",
    )
    reveal_resume = _preparation_step(
        "reveal-portrait-controls-before-resume",
        "reveal_portrait_player_controls",
    )
    reveal_initial_active = _preparation_step(
        "reveal-fullscreen-controls-before-initial-active",
        "reveal_fullscreen_player_controls",
    )
    reveal_switch = _preparation_step(
        "reveal-fullscreen-controls-before-switch",
        "reveal_fullscreen_player_controls",
    )
    open_more = _preparation_step("open-more-live-before-switch", "open_more_live")
    resume_monitor_recovery = (
        Step(
            "recover-live-room-verify-active",
            "ensure_playing",
            Condition(
                ConditionKind.ALL,
                children=(
                    Condition(ConditionKind.APP_FOREGROUND),
                    Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
                ),
            ),
            wait=_quick_wait(8.0),
            retry=RetryPolicy(max_attempts=1),
            skip_if_satisfied=False,
        ),
    )
    refocus_after_evidence_start = Step(
        "refocus-douyu-after-evidence-start",
        "launch_app",
        Condition(ConditionKind.APP_FOREGROUND),
        wait=WaitPolicy(
            timeout_seconds=5.0,
            poll_interval_seconds=0.25,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(max_attempts=2),
        skip_if_satisfied=False,
    )
    open_room_search = Step(
        "open-room-search",
        "open_room_search",
        Condition(ConditionKind.ELEMENT_PRESENT, "room_search_field"),
        wait=WaitPolicy(
            timeout_seconds=8.0,
            poll_interval_seconds=0.25,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(max_attempts=2),
        recovery=(scan_open_search,),
    )
    replace_room_search = Step(
        "replace-room-search",
        "replace_room_search",
        Condition(ConditionKind.ELEMENT_PRESENT, "room_search_result"),
        wait=WaitPolicy(
            timeout_seconds=8.0,
            poll_interval_seconds=0.25,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(max_attempts=2),
        recovery=(scan_replace_search,),
    )
    wait_game_live_card = Step(
        "wait-game-tagged-live-card",
        None,
        Condition(ConditionKind.ELEMENT_PRESENT, "home_game_card"),
        wait=WaitPolicy(
            timeout_seconds=20.0,
            poll_interval_seconds=0.25,
            observation_level=ObservationLevel.FAST,
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    verified_playing = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "room_identity"),
            Condition(ConditionKind.STATE_EQUALS, "motion.playback", "playing"),
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
    game_card_monitor_recovery = (
        Step(
            "exit-inactive-game-live-room",
            "exit_live_room",
            Condition(
                ConditionKind.NOT,
                children=(
                    Condition(ConditionKind.ELEMENT_PRESENT, "room_identity"),
                ),
            ),
            wait=_quick_wait(8.0),
            retry=RetryPolicy(max_attempts=2),
            skip_if_satisfied=False,
        ),
        Step(
            "wait-replacement-game-tagged-live-card",
            None,
            Condition(ConditionKind.ELEMENT_PRESENT, "home_game_card"),
            wait=WaitPolicy(
                timeout_seconds=20.0,
                poll_interval_seconds=0.25,
                observation_level=ObservationLevel.FAST,
            ),
            retry=RetryPolicy(max_attempts=1),
        ),
        Step(
            "select-replacement-game-live-room",
            "select_replacement_game_live_room",
            Condition(ConditionKind.ELEMENT_PRESENT, "room_identity"),
            wait=_quick_wait(12.0),
            retry=RetryPolicy(max_attempts=2),
            recovery=(_scan_step("scan-known-interruptions-game-room-entry"),),
            skip_if_satisfied=False,
        ),
        Step(
            "verify-replacement-game-live-active",
            None,
            monitored_playing,
            wait=_quick_wait(20.0),
            retry=RetryPolicy(max_attempts=1),
            skip_if_satisfied=True,
        ),
    )
    game_card_initial_recovery = (
        Step(
            "exit-initial-inactive-game-live-room",
            "exit_live_room",
            Condition(
                ConditionKind.NOT,
                children=(
                    Condition(ConditionKind.ELEMENT_PRESENT, "room_identity"),
                ),
            ),
            wait=_quick_wait(8.0),
            retry=RetryPolicy(max_attempts=2),
            recovery=(
                _preparation_step(
                    "reveal-controls-before-exiting-initial-inactive-game-live-room",
                    "reveal_portrait_player_controls",
                ),
            ),
            skip_if_satisfied=False,
        ),
        Step(
            "scroll-to-initial-replacement-game-live-card",
            "scroll_game_live_feed",
            Condition.true(),
            wait=_quick_wait(4.0),
            retry=RetryPolicy(max_attempts=1),
            skip_if_satisfied=False,
        ),
        Step(
            "wait-initial-replacement-game-tagged-live-card",
            None,
            Condition(ConditionKind.ELEMENT_PRESENT, "home_game_card"),
            wait=WaitPolicy(
                timeout_seconds=20.0,
                poll_interval_seconds=0.25,
                observation_level=ObservationLevel.FAST,
            ),
            retry=RetryPolicy(max_attempts=1),
        ),
        Step(
            "select-initial-replacement-game-live-room",
            "select_replacement_game_live_room",
            Condition(ConditionKind.ELEMENT_PRESENT, "room_identity"),
            wait=_quick_wait(12.0),
            retry=RetryPolicy(max_attempts=2),
            recovery=(
                _scan_step("scan-known-interruptions-initial-game-room-entry"),
            ),
            skip_if_satisfied=False,
        ),
    )
    preparation = LiveStreamPreparation(
        before_enter=(
            (refocus_after_evidence_start, open_room_search, replace_room_search)
            if primary_room is not None
            else (refocus_after_evidence_start, wait_game_live_card)
        ),
        enter_recovery=(scan_enter,),
        before_active=(),
        active_recovery=(
            (
                _scan_step("scan-known-interruptions-initial-active"),
                _preparation_step(
                    "reveal-player-controls-initial-active-recovery",
                    "reveal_fullscreen_player_controls",
                ),
                _preparation_step(
                    "refresh-inactive-player-initial-active-recovery",
                    "refresh_inactive_player",
                ),
                _preparation_step(
                    "reveal-after-refresh-initial-active-recovery",
                    "reveal_fullscreen_player_controls",
                ),
            )
            if primary_room is not None
            else game_card_initial_recovery
        ),
        before_pause=(reveal_pause,),
        pause_recovery=(
            _scan_step("scan-known-interruptions-pause"),
            _preparation_step(
                "reveal-portrait-controls-pause-recovery",
                "reveal_portrait_player_controls",
            ),
        ),
        before_resume=(reveal_resume,),
        resume_recovery=(
            _scan_step("scan-known-interruptions-resume"),
            _preparation_step(
                "reveal-portrait-controls-resume-recovery",
                "reveal_portrait_player_controls",
            ),
        ),
        before_switch=(reveal_switch, open_more),
        switch_recovery=(
            _scan_step("scan-known-interruptions-switch"),
            _preparation_step(
                "reveal-fullscreen-controls-switch-recovery",
                "reveal_fullscreen_player_controls",
            ),
            _preparation_step("open-more-live-switch-recovery", "open_more_live"),
        ),
        before_switched_active=(
            _preparation_step(
                "reveal-player-controls-before-switched-active",
                "reveal_fullscreen_player_controls",
            ),
        ),
        switched_active_recovery=(
            _scan_step("scan-known-interruptions-switched-active"),
            _preparation_step(
                "reveal-player-controls-switched-active-recovery",
                "reveal_fullscreen_player_controls",
            ),
            _preparation_step(
                "refresh-inactive-player-switched-active-recovery",
                "refresh_inactive_player",
            ),
            _preparation_step(
                "reveal-after-refresh-switched-active-recovery",
                "reveal_fullscreen_player_controls",
            ),
        ),
        monitor_recovery=(
            resume_monitor_recovery
            if primary_room is not None
            else game_card_monitor_recovery
        ),
        monitor_max_consecutive_misses=(30 if primary_room is None else 2),
        monitor_max_recoveries=2,
    )
    verification = LiveStreamVerification(
        room_entered=Condition(
            ConditionKind.ELEMENT_PRESENT,
            "primary_room_identity" if primary_room is not None else "room_identity",
        ),
        active=verified_playing,
        paused=Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.STATE_EQUALS, "motion.playback", "paused"),
            ),
        ),
        playing=verified_playing,
        room_switched=Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "room_identity"),
        monitored_active=(monitored_playing if primary_room is None else None),
    )
    interruptions = (
        InterruptionRule(
            "douyu-young-mode",
            InterruptionKind.BENIGN,
            "young_mode_marker",
            "young_mode_dismiss",
            auto_resolve=True,
            timeout_seconds=5.0,
            max_occurrences=1,
            step_ids=("scan-known-interruptions",),
        ),
        InterruptionRule(
            "douyu-banner-ad",
            InterruptionKind.BENIGN,
            "banner_ad_close",
            "banner_ad_close",
            auto_resolve=True,
            timeout_seconds=4.0,
            max_occurrences=1,
            step_ids=("scan-known-interruptions",),
        ),
        InterruptionRule(
            "douyu-pendant-ad",
            InterruptionKind.BENIGN,
            "pendant_ad_close",
            "pendant_ad_close",
            auto_resolve=True,
            timeout_seconds=4.0,
            max_occurrences=1,
            step_ids=("scan-known-interruptions",),
        ),
    )
    element_queries = {
        "room_search_field": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": "type == 'XCUIElementTypeTextField' AND visible == 1",
                "role": "textfield",
                "attribute_names": (),
                "defaults": {"visible": True, "enabled": True},
            },
        ),
        "home_game_category": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": (
                    "type == 'XCUIElementTypeStaticText' AND visible == 1 AND ("
                    + " OR ".join(f"name == '{category}'" for category in game_categories)
                    + ")"
                ),
                "role": "statictext",
                "attribute_names": ("name",),
            },
        ),
        "home_game_card": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "xpath",
                "value": game_card_xpath,
                "role": "cell",
                "attribute_names": (),
                "defaults": {"visible": True, "enabled": True},
            },
        ),
        "room_identity": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": (
                    "type == 'XCUIElementTypeStaticText' AND "
                    "name BEGINSWITH '斗鱼 房间号:'"
                ),
                "role": "statictext",
                "attribute_names": ("name",),
            },
        ),
        "player_paused_state": ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": (
                    "type == 'XCUIElementTypeButton' AND "
                    "name == 'btn player pause' AND value == '1'"
                ),
                "role": "button",
                "attribute_names": ("name", "value"),
                "defaults": {"visible": False, "enabled": True},
            },
        ),
    }
    if primary_room is not None:
        element_queries["room_search_result"] = ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": (
                    "type == 'XCUIElementTypeStaticText' AND "
                    f"name CONTAINS '{primary_room.room_id}'"
                ),
                "role": "statictext",
                "attribute_names": ("name",),
            },
        )
        element_queries["primary_room_identity"] = ElementObservationQuery(
            "observation.element.query",
            {
                "using": "predicate string",
                "value": (
                    "type == 'XCUIElementTypeStaticText' AND ("
                    f"name == '斗鱼 房间号:{primary_room.room_id}' OR "
                    f"name == '斗鱼 房间号: {primary_room.room_id}')"
                ),
                "role": "statictext",
                "attribute_names": ("name",),
            },
        )
    binding = AppBinding(
        "douyu-ios-live",
        Platform.IOS,
        IOS_APP_ID,
        selectors=selectors,
        pages={"live_room": PageDefinition(required=("room_identity",))},
        actions=actions,
        interruptions=interruptions,
        metadata={
            "entry_path": (
                "native room-id search, native text replacement, verified result cell"
                if primary_room is not None
                else "first visible native card carrying an allowlisted game category label"
            ),
            "playback_control": (
                "fullscreen semantic toggle; native paused state and local frame-motion "
                "playing evidence"
            ),
            "switch_path": "first visible More Live recommendation",
            "requested_switch_room": switch_room.room_id if switch_room else None,
        },
        element_queries=element_queries,
    )
    return binding, preparation, verification


def build_douyu_live_session(
    platform: Platform,
    primary_room: DouyuRoom | None,
    switch_room: DouyuRoom | None = None,
    *,
    run_pause_resume: bool = True,
    leave_app_open: bool = False,
    restart_app: bool = True,
    transition_timeout_seconds: float = 12.0,
    monitor_seconds: float = 0.0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
) -> tuple[AppBinding, Playbook]:
    """Compile an Agent-selected room into the shared live-stream playbook."""

    if primary_room is not None:
        primary_room.validate()
    if switch_room is not None:
        switch_room.validate()
    if platform is Platform.ANDROID:
        if primary_room is None:
            raise ValueError("Android Douyu requires an explicit room_id")
        if run_pause_resume:
            raise NotImplementedError(
                "current Android Douyu build has no stable pause/resume capability; "
                "use room entry/switch or author new verified evidence"
            )
        binding, preparation, verification = _android_binding(primary_room, switch_room)
    elif platform is Platform.IOS:
        binding, preparation, verification = _ios_binding(primary_room, switch_room)
    else:  # pragma: no cover - Platform currently has exactly two values
        raise ValueError(f"unsupported platform {platform!r}")
    playbook = build_live_stream_playbook(
        LiveStreamTask(
            room_query=(primary_room.anchor or primary_room.room_id) if primary_room else None,
            run_pause_resume=run_pause_resume,
            switch_room=switch_room is not None,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
        preparation,
    )
    binding.validate()
    playbook.validate()
    return binding, playbook
