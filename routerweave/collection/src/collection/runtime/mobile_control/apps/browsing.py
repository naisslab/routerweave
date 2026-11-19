"""Registry-backed bindings for the shared browsing task family."""

from __future__ import annotations

from typing import Any, Mapping

from ..binding import AppBinding, ElementObservationQuery
from ..catalog import RegisteredApp
from ..condition import Condition, ConditionKind
from ..interruption import InterruptionKind, InterruptionRule
from ..perception import SemanticSelector
from ..playbook import Playbook
from ..playbooks.browsing import BrowsingTask, BrowsingVerification, build_browsing_playbook
from ..playbooks.human_activity import HumanActivityDecision
from ..status import Idempotency, Platform
from .common import (action, direct, element_capability, gesture, lifecycle_actions,
                     register_android_session_anr_wait)


def build_browsing_session(
    app: RegisteredApp,
    profile: Mapping[str, Any],
    *,
    detail_visits: int = 1,
    feed_scrolls: int = 0,
    feed_refreshes: int = 0,
    scroll_detail: bool = True,
    leave_app_open: bool = False,
    restart_app: bool = True,
    transition_timeout_seconds: float = 10.0,
    monitor_seconds: float = 0.0,
    human_activity: tuple[HumanActivityDecision, ...] = (),
) -> tuple[AppBinding, Playbook]:
    if app.task_family != "browsing":
        raise ValueError(f"{app.name!r} is not a browsing application")
    if app.platform is Platform.IOS:
        ios_plan = profile.get("ios_browsing_plan")
        detail_enabled = (
            isinstance(ios_plan, Mapping)
            and ios_plan.get("detail_entry_enabled") is True
        )
        if detail_visits and not detail_enabled:
            raise NotImplementedError(
                f"{app.name!r} iOS has no coordinate-free semantic detail-entry evidence"
            )
        if isinstance(ios_plan, Mapping):
            return _build_ios_native_browsing_session(
                app,
                ios_plan,
                detail_visits=detail_visits,
                feed_scrolls=feed_scrolls,
                feed_refreshes=feed_refreshes,
                scroll_detail=scroll_detail,
                leave_app_open=leave_app_open,
                restart_app=restart_app,
                transition_timeout_seconds=transition_timeout_seconds,
                monitor_seconds=monitor_seconds,
                human_activity=human_activity,
            )
        if feed_refreshes:
            raise NotImplementedError(
                f"{app.name!r} iOS has no verified semantic feed-refresh evidence"
            )
        return _build_ios_feed_session(
            app,
            feed_scrolls=feed_scrolls,
            feed_refreshes=feed_refreshes,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        )
    if app.platform is not Platform.ANDROID:
        raise NotImplementedError(f"unsupported browsing platform {app.platform.value!r}")
    plan = _mapping(profile.get("browsing_feed_plan"), "browsing_feed_plan")
    startup_wait = float(plan.get("startup_observation_wait_seconds") or 0)
    observation_wait = float(plan.get("observation_wait_seconds") or 0)
    if not 0 <= startup_wait <= 90 or not 0 <= observation_wait <= 90:
        raise ValueError("observation wait must be bounded to 90 seconds")
    content = _mapping(plan.get("content_node"), "browsing_feed_plan.content_node")
    feed_activity = _activity_hint(plan, "feed_focus_contains")
    detail_activity = _activity_hint(plan, "detail_focus_contains")
    candidate_parameters = _candidate_parameters(content)

    feed_marker_pattern = str(plan.get("feed_marker_pattern") or "").strip()
    feed_tab = plan.get("feed_tab_component")
    selectors = {}
    element_queries = {}
    detail_open = Condition(ConditionKind.STATE_CONTAINS, "device.foreground_activity_class", detail_activity)
    detail_finished = None
    end_texts = tuple(plan.get("detail_end_texts") or ())
    if end_texts:
        selectors["detail_end"] = SemanticSelector(
            exact_texts=end_texts, roles=("textview",),
            attributes={"package": app.app_id}, ambiguity_margin=0,
        )
        detail_finished = Condition(ConditionKind.ALL, children=(
            Condition(ConditionKind.APP_FOREGROUND), detail_open,
            Condition(ConditionKind.ELEMENT_PRESENT, "detail_end"),
        ))
    alternate_detail = plan.get("alternate_article_surface")
    if isinstance(alternate_detail, Mapping):
        article_class = str(alternate_detail["container_class"])
        selectors["native_article_body"] = SemanticSelector(
            attributes={"class": article_class}, minimum_score=25, ambiguity_margin=0)
        element_queries["native_article_body"] = ElementObservationQuery(
            "observation.element.query", {"class_name": article_class})
        detail_open = Condition(ConditionKind.ANY, children=(
            detail_open,
            Condition(ConditionKind.ALL, children=(
                Condition(ConditionKind.STATE_CONTAINS, "device.foreground_activity_class",
                          str(alternate_detail["activity_contains"])),
                Condition(ConditionKind.ELEMENT_PRESENT, "native_article_body"),
            )),
        ))
    feed_ready = Condition(
        ConditionKind.STATE_CONTAINS,
        "device.foreground_activity_class",
        feed_activity,
    )
    if feed_marker_pattern:
        selectors["feed_marker"] = SemanticSelector(
            text_patterns=(feed_marker_pattern,),
            roles=("textview",),
            minimum_score=70,
            ambiguity_margin=0,
        )
        feed_ready = Condition(
            ConditionKind.ALL,
            children=(
                Condition(ConditionKind.APP_FOREGROUND),
                Condition(ConditionKind.ELEMENT_PRESENT, "feed_marker"),
            ),
        )

    actions = lifecycle_actions()
    ensure_feed_strategy = direct(
        "android-back-to-known-feed",
        "navigation.back",
        idempotency=Idempotency.NON_IDEMPOTENT,
    )
    if isinstance(feed_tab, Mapping):
        ensure_feed_strategy = element_capability(
            "activate-current-feed-tab-component",
            "element.activate.candidate",
            idempotency=Idempotency.REPEATABLE,
            parameters=_feed_tab_parameters(feed_tab),
        )
    actions.update(
        {
            "ensure_content_feed": action(
                "ensure_content_feed",
                ensure_feed_strategy,
            ),
            "recover_content_feed": action(
                "recover_content_feed",
                direct(
                    "android-return-from-non-root-surface",
                    "navigation.back",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                ),
            ),
            "open_feed_content": action(
                "open_feed_content",
                element_capability(
                    "activate-semantic-feed-candidate",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=candidate_parameters,
                ),
            ),
            "scroll_content": action(
                "scroll_content",
                gesture(
                    "relative-detail-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={
                        "direction": "up",
                        "duration_ms": int(plan.get("scroll_duration_ms") or 650),
                    },
                ),
            ),
            "return_to_feed": action(
                "return_to_feed",
                direct(
                    "android-back-from-detail",
                    "navigation.back",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                ),
            ),
            "advance_feed": action(
                "advance_feed",
                gesture(
                    "relative-feed-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={
                        "direction": "up",
                        "duration_ms": int(plan.get("scroll_duration_ms") or 600),
                    },
                ),
            ),
        }
    )
    recovery_refresh = plan.get("recovery_refresh_component")
    if isinstance(recovery_refresh, Mapping):
        actions["refresh_feed"] = action(
            "refresh_feed",
            element_capability(
                "refresh-through-current-feed-component", "element.activate.candidate",
                idempotency=Idempotency.REPEATABLE,
                parameters=_candidate_parameters(recovery_refresh),
            ),
        )
    interruption_rules: list[InterruptionRule] = []
    register_android_session_anr_wait(profile, app.app_id, selectors, interruption_rules)
    binding = AppBinding(
        f"android-{app.name}-browsing",
        app.platform,
        app.app_id,
        selectors=selectors,
        element_queries=element_queries,
        actions=actions,
        interruptions=tuple(interruption_rules),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "binding_source": "configs/android_app_profiles.json",
            "coordinate_policy": "current semantic bounds only",
            "nonblocking_login_banner": dict(plan.get("nonblocking_login_banner") or {}),
            "startup_observation_wait_seconds": startup_wait,
            "observation_wait_seconds": observation_wait,
        },
    )
    verification = BrowsingVerification(
        feed_ready=feed_ready,
        feed_progressed=_browsing_progressed(),
        detail_open=detail_open,
        detail_progressed=_browsing_progressed(),
        detail_scroll_finished=detail_finished,
        detail_closed=Condition(
            ConditionKind.NOT,
            children=(detail_open,),
        ),
    )
    playbook = build_browsing_playbook(
        BrowsingTask(
            detail_visits=detail_visits,
            content_open_attempts=plan.get("content_open_attempts", 3),
            refresh_candidates_on_failure=isinstance(recovery_refresh, Mapping),
            feed_scrolls=feed_scrolls,
            feed_refreshes=feed_refreshes,
            scroll_detail=scroll_detail,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )
    return binding, playbook


def _build_ios_native_browsing_session(
    app: RegisteredApp,
    plan: Mapping[str, Any],
    *,
    detail_visits: int,
    feed_scrolls: int,
    feed_refreshes: int,
    scroll_detail: bool,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    home_query = _required_query(plan, "home_button_query")
    selected_tab_query = _required_query(plan, "selected_feed_tab_query")
    home_query_using = str(plan.get("home_button_query_using") or "predicate string")
    feed_root_query = str(plan.get("feed_root_query") or home_query).strip()
    feed_root_query_using = str(
        plan.get("feed_root_query_using") or home_query_using
    )
    selected_tab_query_using = str(
        plan.get("selected_feed_tab_query_using") or "predicate string"
    )
    feed_root_role = str(plan.get("feed_root_role") or "button")
    selected_feed_tab_role = str(plan.get("selected_feed_tab_role") or "button")
    home_selector_pattern = str(plan.get("home_selector_pattern") or r"百度")
    selected_feed_tab_selector_pattern = str(
        plan.get("selected_feed_tab_selector_pattern") or r"推荐"
    )
    ensure_feed_mode = str(plan.get("ensure_feed_mode") or "query").strip()
    recover_feed_mode = str(plan.get("recover_feed_mode") or "query").strip()
    refresh_mode = str(plan.get("refresh_mode") or "query").strip()
    detail_return_mode = str(plan.get("detail_return_mode") or "query").strip()
    content_activation_mode = str(
        plan.get("content_activation_mode") or "query"
    ).strip()
    if refresh_mode not in {"query", "pull_down"}:
        raise ValueError(f"unsupported iOS browsing refresh_mode {refresh_mode!r}")
    if detail_return_mode not in {"query", "candidate", "edge_swipe"}:
        raise ValueError(
            f"unsupported iOS browsing detail_return_mode {detail_return_mode!r}"
        )
    if ensure_feed_mode not in {"query", "launch"}:
        raise ValueError(f"unsupported iOS browsing ensure_feed_mode {ensure_feed_mode!r}")
    if recover_feed_mode not in {
        "query",
        "launch",
        "candidate",
        "relative_tap",
        "edge_swipe",
    }:
        raise ValueError(
            f"unsupported iOS browsing recover_feed_mode {recover_feed_mode!r}"
        )
    if content_activation_mode not in {"query", "candidate"}:
        raise ValueError(
            "unsupported iOS browsing content_activation_mode "
            f"{content_activation_mode!r}"
        )
    refresh_query = (
        _required_query(plan, "refresh_feed_query") if refresh_mode == "query" else ""
    )
    detail_back_query = (
        _required_query(plan, "detail_back_query")
        if detail_return_mode == "query"
        else ""
    )
    detail_back_candidate_parameters = plan.get(
        "detail_back_candidate_parameters", {}
    )
    if not isinstance(detail_back_candidate_parameters, Mapping):
        raise ValueError("detail_back_candidate_parameters must be an object")
    detail_back_candidate_fallback_parameters = plan.get(
        "detail_back_candidate_fallback_parameters", {}
    )
    if not isinstance(detail_back_candidate_fallback_parameters, Mapping):
        raise ValueError(
            "detail_back_candidate_fallback_parameters must be an object"
        )
    recover_feed_candidate_parameters = plan.get(
        "recover_feed_candidate_parameters", {}
    )
    if not isinstance(recover_feed_candidate_parameters, Mapping):
        raise ValueError("recover_feed_candidate_parameters must be an object")
    recover_feed_tap_parameters = plan.get("recover_feed_tap_parameters", {})
    if not isinstance(recover_feed_tap_parameters, Mapping):
        raise ValueError("recover_feed_tap_parameters must be an object")
    detail_surface_query = str(plan.get("detail_surface_query") or "").strip()
    live_surface_query = str(plan.get("live_surface_query") or "").strip()
    detail_surface_observation_mode = str(
        plan.get("detail_surface_observation_mode") or "query"
    ).strip()
    if detail_surface_observation_mode not in {"query", "structured"}:
        raise ValueError(
            "unsupported iOS browsing detail_surface_observation_mode "
            f"{detail_surface_observation_mode!r}"
        )
    feed_identity_query = _required_query(plan, "feed_identity_query")
    content_query = (
        _required_query(plan, "content_query")
        if content_activation_mode == "query"
        else ""
    )
    content_query_using = str(plan.get("content_query_using") or "predicate string")
    content_query_wait_seconds = float(plan.get("content_query_wait_seconds", 0.0))
    content_query_poll_seconds = float(plan.get("content_query_poll_seconds", 0.75))
    content_candidate_parameters = plan.get("content_candidate_parameters", {})
    if not isinstance(content_candidate_parameters, Mapping):
        raise ValueError("content_candidate_parameters must be an object")
    feed_identity_query_using = str(
        plan.get("feed_identity_query_using") or "predicate string"
    )

    selectors = {
        "home_navigation": SemanticSelector(
            text_patterns=(home_selector_pattern,),
            roles=(feed_root_role,),
            minimum_score=1 if home_selector_pattern == ".*" else 20,
            ambiguity_margin=0,
        ),
        "selected_feed_tab": SemanticSelector(
            text_patterns=(selected_feed_tab_selector_pattern,),
            roles=(selected_feed_tab_role,),
            minimum_score=(
                1 if selected_feed_tab_selector_pattern == ".*" else 20
            ),
            ambiguity_margin=0,
        ),
        "feed_identity": SemanticSelector(
            text_patterns=(r".+",),
            roles=("statictext",),
            minimum_score=1,
            ambiguity_margin=0,
        ),
        "authentication_surface": SemanticSelector(
            text_patterns=("手机登录|账号登录|获取动态码|请输入手机验证码",),
            minimum_score=55,
            ambiguity_margin=0,
        ),
        "splash_surface": SemanticSelector(
            accessibility_ids=("splash_ad",),
            minimum_score=110,
            ambiguity_margin=0,
        ),
    }
    if detail_back_query:
        selectors["detail_back"] = SemanticSelector(
            text_patterns=(r"返回",),
            roles=("button",),
            minimum_score=20,
            ambiguity_margin=0,
        )
    if detail_surface_query:
        detail_surface_role = str(plan.get("detail_surface_role") or "button")
        detail_surface_pattern = str(
            plan.get("detail_surface_selector_pattern") or r".+"
        )
        selectors["detail_surface"] = SemanticSelector(
            text_patterns=(detail_surface_pattern,),
            roles=(detail_surface_role,),
            minimum_score=1,
            ambiguity_margin=0,
        )
    if live_surface_query:
        selectors["live_surface"] = SemanticSelector(
            text_patterns=(
                str(plan.get("live_surface_selector_pattern") or r"更多直播|下次开播提醒我"),
            ),
            roles=(str(plan.get("live_surface_role") or "statictext"),),
            minimum_score=1,
            ambiguity_margin=0,
        )
    if detail_return_mode == "query":
        return_to_feed_strategies = (
            element_capability(
                "ios-activate-detail-back",
                "element.activate.query",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={
                    "using": "predicate string",
                    "value": detail_back_query,
                },
            ),
        )
    elif detail_return_mode == "candidate":
        return_to_feed_strategies = [
            element_capability(
                "ios-activate-current-detail-back",
                "element.activate.candidate",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters=dict(detail_back_candidate_parameters),
            )
        ]
        if detail_back_candidate_fallback_parameters:
            return_to_feed_strategies.append(
                element_capability(
                    "ios-activate-current-detail-back-fallback",
                    "element.activate.candidate",
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=dict(detail_back_candidate_fallback_parameters),
                )
            )
        return_to_feed_strategies = tuple(return_to_feed_strategies)
    else:
        return_to_feed_strategies = (
            gesture(
                "ios-edge-swipe-back-from-detail",
                "screen.swipe.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={
                    "direction": "right",
                    "y_ratio": 0.5,
                    "start_x_ratio": 0.02,
                    "end_x_ratio": 0.88,
                    "duration_ms": 650,
                },
            ),
        )

    if recover_feed_mode == "query":
        recover_feed_strategies = (
            element_capability(
                "ios-recover-home-navigation",
                "element.activate.query",
                idempotency=Idempotency.STATE_SETTING,
                parameters={"using": home_query_using, "value": home_query},
            ),
        )
    elif recover_feed_mode == "launch":
        recover_feed_strategies = (
            direct("ios-recover-feed-app", "app.launch"),
        )
    elif recover_feed_mode == "candidate":
        if not recover_feed_candidate_parameters:
            raise ValueError(
                "recover_feed_candidate_parameters are required for candidate recovery"
            )
        recover_feed_strategies = (
            element_capability(
                "ios-activate-current-recovery-back",
                "element.activate.candidate",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters=dict(recover_feed_candidate_parameters),
            ),
        )
    elif recover_feed_mode == "relative_tap":
        if not recover_feed_tap_parameters:
            raise ValueError(
                "recover_feed_tap_parameters are required for relative-tap recovery"
            )
        recover_feed_strategies = (
            gesture(
                "ios-tap-current-recovery-back",
                "screen.tap.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters=dict(recover_feed_tap_parameters),
            ),
        )
    else:
        recover_feed_strategies = (
            gesture(
                "ios-edge-swipe-recover-feed",
                "screen.swipe.relative",
                idempotency=Idempotency.NON_IDEMPOTENT,
                parameters={
                    "direction": "right",
                    "y_ratio": 0.5,
                    "start_x_ratio": 0.02,
                    "end_x_ratio": 0.88,
                    "duration_ms": 650,
                },
            ),
        )

    actions = lifecycle_actions()
    actions.update(
        {
            "ensure_content_feed": action(
                "ensure_content_feed",
                (
                    element_capability(
                        "ios-activate-home-navigation",
                        "element.activate.query",
                        idempotency=Idempotency.STATE_SETTING,
                        parameters={"using": home_query_using, "value": home_query},
                    )
                    if ensure_feed_mode == "query"
                    else direct("ios-reassert-feed-app", "app.launch")
                ),
            ),
            "recover_content_feed": action(
                "recover_content_feed",
                *recover_feed_strategies,
            ),
            "open_feed_content": action(
                "open_feed_content",
                element_capability(
                    (
                        "ios-activate-current-feed-card"
                        if content_activation_mode == "candidate"
                        else "ios-activate-semantic-feed-title"
                    ),
                    (
                        "element.activate.candidate"
                        if content_activation_mode == "candidate"
                        else "element.activate.query"
                    ),
                    idempotency=Idempotency.NON_IDEMPOTENT,
                    parameters=(
                        dict(content_candidate_parameters)
                        if content_activation_mode == "candidate"
                        else {
                            "using": content_query_using,
                            "value": content_query,
                            "query_wait_seconds": content_query_wait_seconds,
                            "query_poll_seconds": content_query_poll_seconds,
                        }
                    ),
                ),
            ),
            "scroll_content": action(
                "scroll_content",
                gesture(
                    "ios-relative-detail-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "up", "duration_ms": 780},
                ),
            ),
            "return_to_feed": action(
                "return_to_feed",
                *return_to_feed_strategies,
            ),
            "advance_feed": action(
                "advance_feed",
                gesture(
                    "ios-relative-feed-swipe",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "up", "duration_ms": 700},
                ),
            ),
            "refresh_feed": action(
                "refresh_feed",
                (
                    element_capability(
                        "ios-reactivate-selected-feed-tab",
                        "element.activate.query",
                        idempotency=Idempotency.REPEATABLE,
                        parameters={"using": "predicate string", "value": refresh_query},
                    )
                    if refresh_mode == "query"
                    else gesture(
                        "ios-pull-down-to-refresh-feed",
                        "screen.swipe.relative",
                        idempotency=Idempotency.REPEATABLE,
                        parameters={
                            "direction": "down",
                            "x_ratio": 0.5,
                            "start_y_ratio": 0.2,
                            "end_y_ratio": 0.78,
                            "duration_ms": 800,
                        },
                    )
                ),
            ),
        }
    )
    element_queries = {
        "home_navigation": _ios_query(
            feed_root_query,
            feed_root_role,
            1,
            using=feed_root_query_using,
        ),
        "selected_feed_tab": _ios_query(
            selected_tab_query,
            selected_feed_tab_role,
            1,
            using=selected_tab_query_using,
        ),
        "feed_identity": _ios_query(
            feed_identity_query,
            "statictext",
            5,
            using=feed_identity_query_using,
        ),
        "authentication_surface": _ios_query(
            "(label CONTAINS '手机登录' OR label CONTAINS '账号登录' "
            "OR label CONTAINS '获取动态码' OR label CONTAINS '请输入手机验证码') "
            "AND visible == 1",
            "statictext",
            1,
        ),
        "splash_surface": _ios_query("name == 'splash_ad' AND visible == 1", "", 1),
    }
    if detail_back_query:
        element_queries["detail_back"] = _ios_query(detail_back_query, "button", 1)
    if detail_surface_query and detail_surface_observation_mode == "query":
        element_queries["detail_surface"] = _ios_query(
            detail_surface_query,
            str(plan.get("detail_surface_role") or "button"),
            1,
            using=str(
                plan.get("detail_surface_query_using") or "predicate string"
            ),
        )
    binding = AppBinding(
        f"ios-{app.name}-native-browsing",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        interruptions=(
            InterruptionRule(
                "ios-browsing-authentication",
                InterruptionKind.AUTHENTICATION,
                "authentication_surface",
                auto_resolve=False,
                step_ids=("scan-browsing-interruptions",),
            ),
        ),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "coverage": "bidirectional feed, semantic article detail, return, and refresh",
            "coordinate_policy": "current semantic bounds and viewport ratios only",
        },
        element_queries=element_queries,
    )
    feed_ready_children = [
        Condition(ConditionKind.APP_FOREGROUND),
        Condition(ConditionKind.ELEMENT_PRESENT, "home_navigation"),
        Condition(ConditionKind.ELEMENT_PRESENT, "selected_feed_tab"),
        Condition(ConditionKind.ELEMENT_ABSENT, "authentication_surface"),
        Condition(ConditionKind.ELEMENT_ABSENT, "splash_surface"),
    ]
    if detail_back_query:
        feed_ready_children.insert(
            3, Condition(ConditionKind.ELEMENT_ABSENT, "detail_back")
        )
    if detail_surface_query:
        feed_ready_children.insert(
            3, Condition(ConditionKind.ELEMENT_ABSENT, "detail_surface")
        )
    if live_surface_query:
        feed_ready_children.insert(
            3, Condition(ConditionKind.ELEMENT_ABSENT, "live_surface")
        )
    feed_ready = Condition(ConditionKind.ALL, children=tuple(feed_ready_children))
    detail_open_children = [Condition(ConditionKind.APP_FOREGROUND)]
    if plan.get("detail_positive_evidence_sufficient") is not True:
        detail_open_children.extend(
            (
                Condition(ConditionKind.ELEMENT_ABSENT, "home_navigation"),
                Condition(ConditionKind.ELEMENT_ABSENT, "selected_feed_tab"),
            )
        )
    detail_open_children.extend(
        (
            Condition(ConditionKind.ELEMENT_ABSENT, "authentication_surface"),
            Condition(ConditionKind.ELEMENT_ABSENT, "splash_surface"),
        )
    )
    if detail_surface_query:
        detail_open_children.insert(
            1, Condition(ConditionKind.ELEMENT_PRESENT, "detail_surface")
        )
    if live_surface_query:
        detail_open_children.insert(
            2, Condition(ConditionKind.ELEMENT_ABSENT, "live_surface")
        )
    detail_open = Condition(ConditionKind.ALL, children=tuple(detail_open_children))
    feed_change = (
        _browsing_progressed()
        if plan.get("feed_progress_evidence") == "visual_or_layout"
        else Condition(ConditionKind.ELEMENT_TEXT_CHANGED, "feed_identity")
    )
    verification = BrowsingVerification(
        feed_ready=feed_ready,
        feed_progressed=Condition(
            ConditionKind.ALL,
            children=(
                feed_ready,
                feed_change,
            ),
        ),
        detail_open=detail_open,
        detail_progressed=_browsing_progressed(),
        detail_closed=feed_ready,
    )
    playbook = build_browsing_playbook(
        BrowsingTask(
            detail_visits=detail_visits,
            feed_scrolls=feed_scrolls,
            feed_refreshes=feed_refreshes,
            refresh_open_recovery=plan.get("refresh_open_recovery") is not False,
            bidirectional_feed=plan.get("bidirectional_feed_enabled") is True,
            scroll_detail=scroll_detail,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )
    return binding, playbook


def _build_ios_feed_session(
    app: RegisteredApp,
    *,
    feed_scrolls: int,
    feed_refreshes: int,
    leave_app_open: bool,
    restart_app: bool,
    transition_timeout_seconds: float,
    monitor_seconds: float,
    human_activity: tuple[HumanActivityDecision, ...],
) -> tuple[AppBinding, Playbook]:
    selectors = {
        "root_navigation": SemanticSelector(
            roles=("tabbar",),
            minimum_score=20,
            ambiguity_margin=0,
        ),
        "authentication_surface": SemanticSelector(
            text_patterns=("手机登录|账号登录|获取动态码|请输入手机验证码",),
            minimum_score=55,
            ambiguity_margin=0,
        ),
        "splash_surface": SemanticSelector(
            accessibility_ids=("splash_ad",),
            minimum_score=110,
            ambiguity_margin=0,
        ),
    }
    actions = lifecycle_actions()
    actions.update(
        {
            # This action is normally skipped because launch_app already proves
            # the feed app is foreground. Keeping it explicit preserves the
            # same cross-platform playbook contract.
            "ensure_content_feed": action(
                "ensure_content_feed",
                direct("ios-reassert-feed-app", "app.launch"),
            ),
            "recover_content_feed": action(
                "recover_content_feed",
                direct("ios-recover-feed-app", "app.launch"),
            ),
            "advance_feed": action(
                "advance_feed",
                gesture(
                    "ios-relative-feed-swipe-up",
                    "screen.swipe.relative",
                    idempotency=Idempotency.REPEATABLE,
                    parameters={"direction": "up", "duration_ms": 700},
                ),
            ),
        }
    )
    binding = AppBinding(
        f"ios-{app.name}-feed-browsing",
        app.platform,
        app.app_id,
        selectors=selectors,
        actions=actions,
        interruptions=(
            InterruptionRule(
                "ios-browsing-authentication",
                InterruptionKind.AUTHENTICATION,
                "authentication_surface",
                auto_resolve=False,
                step_ids=("scan-browsing-interruptions",),
            ),
        ),
        metadata={
            "app_name": app.name,
            "task_family": app.task_family,
            "coverage": "feed browsing only",
            "detail_entry": "unsupported until semantic evidence is authored",
        },
        element_queries={
            "root_navigation": ElementObservationQuery(
                "observation.element.query",
                {
                    "using": "predicate string",
                    "value": "type == 'XCUIElementTypeTabBar' AND visible == 1",
                    "role": "tabbar",
                    "result_limit": 1,
                },
            ),
            "authentication_surface": ElementObservationQuery(
                "observation.element.query",
                {
                    "using": "predicate string",
                    "value": (
                        "(label CONTAINS '手机登录' OR label CONTAINS '账号登录' "
                        "OR label CONTAINS '获取动态码' OR label CONTAINS '请输入手机验证码') "
                        "AND visible == 1"
                    ),
                    "role": "statictext",
                    "result_limit": 1,
                },
            ),
            "splash_surface": ElementObservationQuery(
                "observation.element.query",
                {
                    "using": "predicate string",
                    "value": "name == 'splash_ad' AND visible == 1",
                    "result_limit": 1,
                },
            ),
        },
    )
    feed_ready = Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(ConditionKind.ELEMENT_PRESENT, "root_navigation"),
            Condition(ConditionKind.ELEMENT_ABSENT, "authentication_surface"),
            Condition(ConditionKind.ELEMENT_ABSENT, "splash_surface"),
        ),
    )
    verification = BrowsingVerification(
        feed_ready=feed_ready,
        feed_progressed=Condition(
            ConditionKind.ALL,
            children=(feed_ready, _browsing_progressed()),
        ),
        detail_closed=Condition(ConditionKind.APP_FOREGROUND),
    )
    playbook = build_browsing_playbook(
        BrowsingTask(
            detail_visits=0,
            feed_scrolls=feed_scrolls,
            feed_refreshes=feed_refreshes,
            scroll_detail=False,
            leave_app_open=leave_app_open,
            restart_app=restart_app,
            transition_timeout_seconds=transition_timeout_seconds,
            monitor_seconds=monitor_seconds,
            human_activity=human_activity,
        ),
        verification,
    )
    return binding, playbook


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"registry profile is missing {path}")
    return value


def _required_query(plan: Mapping[str, Any], name: str) -> str:
    value = str(plan.get(name) or "").strip()
    if not value:
        raise ValueError(f"ios_browsing_plan is missing {name}")
    return value


def _ios_query(
    predicate: str,
    role: str,
    result_limit: int,
    *,
    using: str = "predicate string",
) -> ElementObservationQuery:
    parameters: dict[str, Any] = {
        "using": using,
        "value": predicate,
        "result_limit": result_limit,
    }
    if role:
        parameters["role"] = role
    return ElementObservationQuery("observation.element.query", parameters)


def _browsing_progressed() -> Condition:
    return Condition(
        ConditionKind.ALL,
        children=(
            Condition(ConditionKind.APP_FOREGROUND),
            Condition(
                ConditionKind.ANY,
                children=(
                    Condition(ConditionKind.STATE_CHANGED, "ui.layout_fingerprint"),
                    Condition(
                        ConditionKind.STATE_CHANGED,
                        "visual.frame_fingerprint",
                    ),
                ),
            ),
        ),
    )


def _activity_hint(plan: Mapping[str, Any], name: str) -> str:
    value = str(plan.get(name) or "").strip()
    if not value:
        raise ValueError(f"registry browsing plan is missing {name}")
    if "/" not in value:
        return value
    package, activity = value.split("/", 1)
    return package + activity if activity.startswith(".") else activity


def _candidate_parameters(content: Mapping[str, Any]) -> Mapping[str, Any]:
    include = str(content.get("include_regex") or "").strip()
    if not include:
        raise ValueError("registry content_node is missing include_regex")
    # Historical filters were authored against the repository's 720x1640
    # Android reference device. Convert dimensions to ratios at the boundary;
    # fixed tap coordinates are intentionally not imported.
    return {
        "include_pattern": include,
        "resource_id_pattern": str(content.get("resource_id_regex") or ""),
        "exclude_pattern": str(content.get("exclude_regex") or ""),
        "exclude_identity_pattern": str(
            content.get("exclude_identity_regex")
            or r"search|query|input|login|navigation|nav_|tab_|toolbar|header|footer"
        ),
        "role_pattern": str(content.get("class_regex") or ""),
        "require_clickable": bool(content.get("require_clickable", True)),
        "min_width_ratio": min(1.0, float(content.get("min_width") or 0) / 720.0),
        "max_width_ratio": min(1.0, float(content.get("max_width") or 720) / 720.0),
        "min_height_ratio": min(1.0, float(content.get("min_height") or 0) / 1640.0),
        "max_height_ratio": min(1.0, float(content.get("max_height") or 1640) / 1640.0),
        "selection_policy": "first_visible",
        "hierarchy_compressed": bool(content.get("hierarchy_compressed", False)),
        "hierarchy_read_attempts": int(content.get("hierarchy_read_attempts") or 1),
        "hierarchy_settle_seconds": float(content.get("hierarchy_settle_seconds") or 0.0),
        "hierarchy_retry_delay_seconds": float(
            content.get("hierarchy_retry_delay_seconds") or 0.5
        ),
        "hierarchy_read_timeout_seconds": float(
            content.get("hierarchy_read_timeout_seconds") or 15.0
        ),
    }


def _feed_tab_parameters(component: Mapping[str, Any]) -> Mapping[str, Any]:
    resource_id = str(component.get("resource_id_regex") or "").strip()
    if not resource_id:
        raise ValueError("feed_tab_component is missing resource_id_regex")
    return {
        "include_pattern": str(component.get("include_regex") or ".*"),
        "resource_id_pattern": resource_id,
        "role_pattern": str(component.get("class_regex") or ""),
        "require_clickable": bool(component.get("require_clickable", True)),
        "max_height_ratio": float(component.get("max_height_ratio") or 0.12),
        "selection_policy": "first_visible",
    }
