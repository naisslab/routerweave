"""iOS capability adapter backed by a direct WebDriverAgent session."""

from __future__ import annotations

import base64
from dataclasses import replace
from io import BytesIO
import json
from pathlib import Path
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Mapping

from ..capability import (
    CapabilityCatalog,
    CapabilityDescriptor,
    CapabilityHealth,
    CapabilityKind,
    CapabilityProbe,
    CapabilityReport,
)
from ..observation import ElementNode, Observation
from ..motion import FrameMotionConfig, frame_fingerprint, sample_frame_motion
from ..media_card import select_media_card
from ..music_visual import bottom_music_player_state
from ..network_activity import CaptureGrowthProbe
from ..platform import CommandResult
from ..semantic_candidate import select_semantic_candidate
from ..status import ActionMethod, CommandStatus, ObservationLevel, Platform
from ..wda import WdaClient, WdaRequestError, WdaRequestTimeout
from .process import ProcessExecutor, SubprocessExecutor


_BUNDLE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
_CLICKABLE_TYPES = {
    "XCUIElementTypeButton",
    "XCUIElementTypeCell",
    "XCUIElementTypeLink",
    "XCUIElementTypeImage",
    "XCUIElementTypeTab",
    "XCUIElementTypeSwitch",
}
_HID_MEDIA_CONTROLS = {
    "play": (12, 176),
    "pause": (12, 177),
    "next": (12, 181),
}
_KNOWN_POST_ISOLATION_ALERTS = frozenset(
    (
        "无法安装“Device Kit”",
        "Unable to Install “Device Kit”",
    )
)


def _springboard_home_visual_evidence(frame: bytes) -> dict[str, Any]:
    """Recognize the repeated large icon geometry in the SpringBoard dock."""

    try:
        import cv2
        import numpy as np
        from PIL import Image

        image = np.asarray(Image.open(BytesIO(frame)).convert("RGB"))
        height, width = image.shape[:2]
        dock_top = round(height * 0.82)
        gray = cv2.cvtColor(image[dock_top:], cv2.COLOR_RGB2GRAY)
        edges = cv2.Canny(gray, 60, 150)
        contours, _ = cv2.findContours(
            edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE
        )
        candidates: list[tuple[int, int, int, int]] = []
        for contour in contours:
            x, y, box_width, box_height = cv2.boundingRect(contour)
            y += dock_top
            if not (
                width * 0.10 <= box_width <= width * 0.20
                and height * 0.06 <= box_height <= height * 0.13
                and y >= height * 0.82
            ):
                continue
            center = (x + box_width / 2, y + box_height / 2)
            if any(
                abs(center[0] - (left + prior_width / 2)) <= width * 0.03
                and abs(center[1] - (top + prior_height / 2)) <= height * 0.03
                for left, top, prior_width, prior_height in candidates
            ):
                continue
            candidates.append((x, y, box_width, box_height))
        centers = sorted(x + box_width / 2 for x, _, box_width, _ in candidates)
        separated = any(
            right - left >= width * 0.15
            for left, right in zip(centers, centers[1:])
        )
        return {
            "is_home": len(candidates) >= 2 and separated,
            "dock_icon_rects": candidates,
            "screen_pixels": (width, height),
        }
    except Exception as exc:
        return {
            "is_home": False,
            "dock_icon_rects": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def _control(name: str, method: ActionMethod, description: str) -> CapabilityDescriptor:
    return CapabilityDescriptor(name, CapabilityKind.CONTROL, method, description)


def _observe(name: str, description: str) -> CapabilityDescriptor:
    return CapabilityDescriptor(name, CapabilityKind.OBSERVATION, None, description)


IOS_CAPABILITIES = CapabilityCatalog(
    (
        _control("app.launch", ActionMethod.DIRECT, "Launch an app through WebDriverAgent"),
        _control("app.terminate", ActionMethod.DIRECT, "Terminate an app through WebDriverAgent"),
        _control(
            "app.observe_foreground",
            ActionMethod.DIRECT,
            "Read the active app without mutating application state",
        ),
        _control(
            "control.session.refresh",
            ActionMethod.DIRECT,
            "Replace the WDA gesture session without terminating the target app",
        ),
        _control("media.ensure_playing", ActionMethod.DIRECT, "Inject the iOS HID play usage"),
        _control("media.ensure_paused", ActionMethod.DIRECT, "Inject the iOS HID pause usage"),
        _control("media.next", ActionMethod.DIRECT, "Inject the iOS HID next-track usage"),
        _control("element.activate", ActionMethod.ELEMENT, "Resolve and click an XCUI element"),
        _control(
            "element.activate.query",
            ActionMethod.ELEMENT,
            "Resolve and click one native WDA semantic query",
        ),
        _control(
            "element.activate.revealed_query",
            ActionMethod.ELEMENT,
            "Reveal a hidden control, then activate one exact native WDA query",
        ),
        _control(
            "element.replace_text.query",
            ActionMethod.ELEMENT,
            "Resolve one native text field and replace its value",
        ),
        _control(
            "element.activate.candidate",
            ActionMethod.ELEMENT,
            "Select and activate one current semantic feed/catalog candidate",
        ),
        _control(
            "element.activate.media_card",
            ActionMethod.ELEMENT,
            "Activate a visible long-form media title paired with its duration label",
        ),
        _control("screen.tap.relative", ActionMethod.GESTURE, "Tap a screen-relative point"),
        _control("screen.swipe.relative", ActionMethod.GESTURE, "Swipe using screen-relative W3C actions"),
        _control(
            "screen.swipe.relative.native",
            ActionMethod.GESTURE,
            "Swipe using WDA's native drag route and current viewport ratios",
        ),
        _control(
            "system.recents.clear",
            ActionMethod.GESTURE,
            "Use AssistiveTouch to open App Switcher, swipe cards up, and verify SpringBoard",
        ),
        _observe("observation.fast", "Read the active iOS application"),
        _observe("observation.blocker", "Read the current XCUI system alert, if any"),
        _observe(
            "observation.element.query",
            "Read a small native XCUI query without serializing the full hierarchy",
        ),
        _observe("observation.viewport", "Read the current WDA viewport and orientation"),
        _observe("observation.frame", "Fingerprint one local frame without a visual Agent"),
        _observe("observation.motion", "Measure local frame motion without a visual Agent"),
        _observe("observation.structured", "Read the XCUI accessibility hierarchy"),
    )
)


class IosWdaAdapter:
    def __init__(
        self,
        bundle_id: str,
        *,
        wda_url: str = "http://127.0.0.1:8100",
        client: WdaClient | None = None,
        command_timeout_seconds: float = 20.0,
        motion_config: FrameMotionConfig | None = None,
        network_capture_path: str | Path | None = None,
        blocker_probe_mode: str = "alert_endpoint",
        udid: str = "",
        process_name: str = "",
        executor: ProcessExecutor | None = None,
        device_screenshot: Callable[[], bytes] | None = None,
        process_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.bundle_id = self._valid_bundle_id(bundle_id)
        if blocker_probe_mode not in {
            "alert_endpoint",
            "active_app_guard",
            "device_service_guard",
        }:
            raise ValueError(f"unsupported iOS blocker probe mode {blocker_probe_mode!r}")
        self._client = client or WdaClient(wda_url, command_timeout_seconds)
        self._timeout = command_timeout_seconds
        self._blocker_probe_mode = blocker_probe_mode
        self._target_seen_foreground = False
        self._udid = udid.strip()
        self._process_name = process_name.strip()
        self._executor = executor or SubprocessExecutor()
        self._device_screenshot = device_screenshot
        self._process_probe = process_probe
        self._cached_window_size: tuple[int, int] | None = None
        if blocker_probe_mode == "device_service_guard" and (
            not self._udid or not self._process_name
        ):
            raise ValueError(
                "device_service_guard requires an iOS UDID and exact process name"
            )
        self._motion_config = motion_config or FrameMotionConfig()
        self._network_activity = (
            CaptureGrowthProbe(network_capture_path)
            if network_capture_path is not None
            else None
        )
        self._generation = 0
        self._semantic_candidate_history: dict[str, list[str]] = {}

    @property
    def platform(self) -> Platform:
        return Platform.IOS

    @property
    def capabilities(self) -> CapabilityCatalog:
        return IOS_CAPABILITIES

    def probe_capabilities(self) -> CapabilityReport:
        transport_started = time.monotonic()
        try:
            status = self._client.request("/status", timeout_seconds=5.0)
            self._client.session_id()
            ready = True
            detail = "WDA status and session are available"
        except Exception as exc:
            status = {}
            ready = False
            detail = f"{type(exc).__name__}: {exc}"
        transport_duration = time.monotonic() - transport_started
        if not ready:
            return CapabilityReport(
                "wda",
                tuple(
                    CapabilityProbe(
                        descriptor.name,
                        CapabilityHealth.UNAVAILABLE,
                        detail,
                        transport_duration,
                    )
                    for descriptor in self.capabilities.descriptors
                ),
            )

        source_started = time.monotonic()
        try:
            observation = self.observe(ObservationLevel.STRUCTURED, "capability-probe")
            structured_errors = tuple(
                error for error in observation.errors if error.startswith("structured:")
            )
            if not observation.elements:
                source_health = CapabilityHealth.UNAVAILABLE
            elif structured_errors:
                source_health = CapabilityHealth.DEGRADED
            else:
                source_health = CapabilityHealth.AVAILABLE
            fast_health = (
                CapabilityHealth.AVAILABLE
                if observation.app_id is not None
                else CapabilityHealth.UNAVAILABLE
            )
            source_detail = (
                f"{len(observation.elements)} XCUI nodes"
                if observation.elements
                else "; ".join(observation.errors) or "XCUI hierarchy was empty"
            )
        except Exception as exc:
            source_health = CapabilityHealth.UNAVAILABLE
            fast_health = CapabilityHealth.UNAVAILABLE
            source_detail = f"{type(exc).__name__}: {exc}"
        source_duration = time.monotonic() - source_started

        blocker_started = time.monotonic()
        try:
            blocker_observation = self.observe(
                ObservationLevel.FAST,
                "capability-probe-blocker",
                frozenset(("blocker",)),
            )
            blocker_health = (
                CapabilityHealth.UNAVAILABLE
                if any(error.startswith("blocker:") for error in blocker_observation.errors)
                else CapabilityHealth.AVAILABLE
            )
            blocker_detail = (
                "; ".join(blocker_observation.errors)
                or "WDA alert endpoint is available"
            )
        except Exception as exc:
            blocker_health = CapabilityHealth.UNAVAILABLE
            blocker_detail = f"{type(exc).__name__}: {exc}"
        blocker_duration = time.monotonic() - blocker_started

        probes: list[CapabilityProbe] = []
        for descriptor in self.capabilities.descriptors:
            if descriptor.name == "observation.structured":
                probes.append(
                    CapabilityProbe(
                        descriptor.name,
                        source_health,
                        source_detail,
                        source_duration,
                    )
                )
            elif descriptor.name == "observation.blocker":
                probes.append(
                    CapabilityProbe(
                        descriptor.name,
                        blocker_health,
                        blocker_detail,
                        blocker_duration,
                    )
                )
            else:
                probes.append(
                    CapabilityProbe(
                        descriptor.name,
                        (
                            fast_health
                            if descriptor.name == "observation.fast"
                            else CapabilityHealth.UNKNOWN
                        ),
                        (
                            "WDA observation transport ready"
                            if descriptor.kind is CapabilityKind.OBSERVATION
                            else "WDA transport ready; mutating action intentionally not invoked"
                        ),
                        transport_duration,
                        {"status": status},
                    )
                )
        return CapabilityReport("wda", tuple(probes))

    def _settled_active_app_info(self) -> dict[str, Any]:
        """Passively recheck a transient system surface; never infer the app."""
        response = self._client.session_request("/wda/activeAppInfo", timeout_seconds=5.0)
        polls = 0
        while self._target_seen_foreground and polls < 5:
            value = response.get("value")
            info = value if isinstance(value, dict) else response
            if info.get("bundleId") != "com.apple.springboard":
                break
            time.sleep(1.0)
            response = self._client.session_request("/wda/activeAppInfo", timeout_seconds=5.0)
            polls += 1
        return {**response, "foreground_settle_polls": polls}

    def observe(
        self,
        level: ObservationLevel,
        reason: str,
        signals: frozenset[str] = frozenset(),
    ) -> Observation:
        errors: list[str] = []
        app_id: str | None = None
        elements: tuple[ElementNode, ...] = ()
        state: dict[str, Any] = {"device": {"foreground_app": None}}
        requested = signals or frozenset(
            ("foreground", "ui")
            if level in (ObservationLevel.STRUCTURED, ObservationLevel.VISUAL)
            else ("foreground",)
        )
        alert_node: ElementNode | None = None
        foreground_observed = False
        if "blocker" in requested and self._blocker_probe_mode == "device_service_guard":
            try:
                running = self._target_process_running()
                state["device"]["blocker_probe"] = "device_service_guard"
                state["device"]["target_process_running"] = running
                foreground_observed = True
                if running:
                    app_id = self.bundle_id
                    state["device"]["foreground_app"] = app_id
                else:
                    # Exact process absence proves the target is not in the
                    # foreground even though this AX-free probe cannot name
                    # whichever app or SpringBoard currently is.  Preserve a
                    # concrete non-target identity so terminate postconditions
                    # remain independently verifiable.
                    app_id = "ios:target-process-not-running"
                    state["device"]["foreground_app"] = app_id
                    if self._target_seen_foreground:
                        alert_node = ElementNode(
                            "ios:target-process-missing",
                            role="dialog",
                            text="verified target process is no longer running",
                            attributes={
                                "type": "device_service_guard",
                                "probe": "go-ios-process-liveness",
                            },
                        )
            except Exception as exc:
                errors.append(f"blocker: {type(exc).__name__}: {exc}")
        elif "blocker" in requested and self._blocker_probe_mode == "active_app_guard":
            try:
                response = self._settled_active_app_info()
                value = response.get("value")
                info = value if isinstance(value, dict) else response
                app_id = str(info.get("bundleId") or "") or None
                foreground_observed = True
                state["device"]["foreground_app"] = app_id
                state["device"]["blocker_probe"] = "active_app_guard"
                if app_id == self.bundle_id:
                    self._target_seen_foreground = True
                elif self._target_seen_foreground:
                    alert_node = ElementNode(
                        "ios:foreground-blocker",
                        role="dialog",
                        text="non-target foreground system surface",
                        attributes={
                            "type": "foreground_guard",
                            "probe": "active-app-guard",
                            "bundle_id": app_id or "",
                        },
                    )
            except Exception as exc:
                errors.append(f"blocker: {type(exc).__name__}: {exc}")
        elif "blocker" in requested:
            for attempt in range(2):
                try:
                    response = self._client.session_request(
                        "/alert/text", timeout_seconds=5.0
                    )
                    state["device"]["blocker_probe_attempts"] = attempt + 1
                    value = response.get("value")
                    if isinstance(value, str) and value.strip():
                        alert_node = ElementNode(
                            "ios:system-alert",
                            role="alert",
                            text=value.strip(),
                            attributes={
                                "type": "XCUIElementTypeAlert",
                                "probe": "alert-text",
                            },
                        )
                    break
                except WdaRequestTimeout as exc:
                    if attempt == 0:
                        # This is an idempotent observation. WDA can briefly stop
                        # serving the alert endpoint while a content view settles,
                        # so retry it once without weakening the fail-closed gate.
                        time.sleep(0.5)
                        continue
                    state["device"]["blocker_probe_attempts"] = attempt + 1
                    try:
                        fallback = self._client.session_request(
                            "/elements",
                            {
                                "using": "predicate string",
                                "value": (
                                    "type == 'XCUIElementTypeAlert' AND visible == 1"
                                ),
                            },
                            timeout_seconds=5.0,
                        )
                        raw_matches = fallback.get("value")
                        if not isinstance(raw_matches, list):
                            raise WdaRequestError(
                                "visible alert query response value must be a list"
                            )
                        alert_ids = self._element_ids(fallback)
                        if raw_matches and len(alert_ids) != len(raw_matches):
                            raise WdaRequestError(
                                "visible alert query returned an invalid element id"
                            )
                        state["device"]["blocker_probe_fallback"] = (
                            "visible_alert_query"
                        )
                        state["device"]["blocker_probe_fallback_matches"] = len(
                            alert_ids
                        )
                        if alert_ids:
                            alert_node = ElementNode(
                                f"ios:visible-alert:{alert_ids[0]}",
                                role="alert",
                                attributes={
                                    "type": "XCUIElementTypeAlert",
                                    "probe": "visible-alert-query",
                                    "match_count": len(alert_ids),
                                },
                            )
                    except Exception as fallback_exc:
                        errors.append(
                            f"blocker: {type(exc).__name__}: {exc}; "
                            "visible alert fallback failed: "
                            f"{type(fallback_exc).__name__}: {fallback_exc}"
                        )
                except WdaRequestError as exc:
                    state["device"]["blocker_probe_attempts"] = attempt + 1
                    message = str(exc).casefold()
                    if "no such alert" not in message and "no alert" not in message:
                        errors.append(f"blocker: {type(exc).__name__}: {exc}")
                    break
                except Exception as exc:
                    state["device"]["blocker_probe_attempts"] = attempt + 1
                    errors.append(f"blocker: {type(exc).__name__}: {exc}")
                    break
        if "foreground" in requested and not foreground_observed:
            try:
                response = self._settled_active_app_info()
                value = response.get("value")
                info = value if isinstance(value, dict) else response
                app_id = str(info.get("bundleId") or "") or None
                state["device"]["foreground_settle_polls"] = response["foreground_settle_polls"]
                state["device"]["foreground_app"] = app_id
                if app_id == self.bundle_id:
                    self._target_seen_foreground = True
            except Exception as exc:
                errors.append(f"foreground: {type(exc).__name__}: {exc}")
        if "viewport" in requested:
            try:
                width, height = self._get_window_size()
                state["device"].update(
                    {
                        "viewport": (width, height),
                        "orientation": "landscape" if width > height else "portrait",
                    }
                )
            except Exception as exc:
                errors.append(f"viewport: {type(exc).__name__}: {exc}")
        if "motion" in requested:
            try:
                motion = sample_frame_motion(
                    self._capture_screenshot,
                    time.sleep,
                    self._motion_config,
                )
                state["motion"] = motion.as_state()
            except Exception as exc:
                errors.append(f"motion: {type(exc).__name__}: {exc}")
        if "network" in requested:
            state["network"] = (
                self._network_activity.observe()
                if self._network_activity is not None
                else {"capture_activity": "unknown"}
            )
        if "frame" in requested:
            try:
                frame = self._capture_screenshot()
                from PIL import Image, ImageStat

                image = Image.open(BytesIO(frame)).convert("L")
                width, height = image.size
                top_luma = ImageStat.Stat(
                    image.crop((0, 0, width, round(height * 0.12)))
                ).mean[0]
                bottom_luma = ImageStat.Stat(
                    image.crop((0, round(height * 0.92), width, height))
                ).mean[0]
                content_stddev = ImageStat.Stat(
                    image.crop((0, round(height * 0.16), width, round(height * 0.90)))
                ).stddev[0]
                chrome_theme = (
                    "light"
                    if top_luma > 225 and bottom_luma > 225
                    else "dark"
                    if top_luma < 150 and bottom_luma < 150
                    else "mixed"
                )
                state["visual"] = {
                    "frame_fingerprint": frame_fingerprint(frame),
                    "top_band_luma": round(float(top_luma), 3),
                    "bottom_band_luma": round(float(bottom_luma), 3),
                    "bottom_band_theme": "dark" if bottom_luma < 150 else "light",
                    "chrome_theme": chrome_theme,
                    "content_detail": "loaded" if content_stddev > 25 else "placeholder",
                    "content_luma_stddev": round(float(content_stddev), 3),
                }
                state["visual"]["music_mini_player"] = bottom_music_player_state(frame)
            except Exception as exc:
                errors.append(f"frame: {type(exc).__name__}: {exc}")
        if "ui" in requested:
            try:
                self._client.session_request(
                    "/appium/settings",
                    {"settings": {"snapshotMaxDepth": 50}},
                    timeout_seconds=min(self._timeout, 5.0),
                )
                response = self._client.session_request("/source", timeout_seconds=self._timeout)
                source = response.get("value")
                if not isinstance(source, str):
                    raise WdaRequestError("WDA source response did not contain XML")
                elements = self._parse_source(source)
                if not elements:
                    errors.append("structured XCUI hierarchy was empty")
            except Exception as exc:
                errors.append(f"structured: {type(exc).__name__}: {exc}")
        if alert_node is not None:
            # /alert/text is the authoritative lightweight blocker signal.
            # Preserve the richer source identity when it exists; otherwise
            # inject one synthetic alert so the blocker cannot disappear merely
            # because /source omitted the system surface.
            source_alert_index = next(
                (index for index, node in enumerate(elements) if node.role == "alert"),
                None,
            )
            if source_alert_index is None:
                elements = (alert_node,) + elements
            else:
                source_alert = elements[source_alert_index]
                merged_alert = replace(
                    source_alert,
                    text=source_alert.text or alert_node.text,
                    attributes={
                        **source_alert.attributes,
                        "probe": "alert-text",
                        "probe_text": alert_node.text,
                    },
                )
                elements = (
                    *elements[:source_alert_index],
                    merged_alert,
                    *elements[source_alert_index + 1 :],
                )
        self._generation += 1
        return Observation(
            self.platform,
            time.time(),
            app_id,
            elements,
            state,
            tuple(errors),
            self._generation,
        )

    def query_elements(
        self,
        capability: str,
        parameters: Mapping[str, Any],
        reason: str,
    ) -> Observation:
        if capability != "observation.element.query":
            self._generation += 1
            return Observation(
                self.platform,
                time.time(),
                errors=(f"native_query: unsupported capability {capability!r}",),
                generation=self._generation,
            )
        using = str(parameters.get("using") or "predicate string").strip()
        value = str(parameters.get("value") or "").strip()
        if using not in {"predicate string", "xpath"} or not value:
            self._generation += 1
            return Observation(
                self.platform,
                time.time(),
                errors=("native_query: valid WDA query strategy and value are required",),
                generation=self._generation,
            )
        try:
            # Both native predicates and XPath need nested controls when a
            # visual-only session starts with a shallow snapshot tree.
            snapshot_depth = parameters.get("snapshot_max_depth", 50)
            if type(snapshot_depth) is not int or not 1 <= snapshot_depth <= 100:
                raise WdaRequestError("snapshot_max_depth must be an integer between 1 and 100")
            self._client.session_request(
                "/appium/settings",
                {"settings": {"snapshotMaxDepth": snapshot_depth}},
                timeout_seconds=min(self._timeout, 5.0),
            )
            response = self._client.session_request(
                "/elements",
                {"using": using, "value": value},
            )
            raw_matches = response.get("value")
            if not isinstance(raw_matches, list):
                raise WdaRequestError(
                    "native element query response value must be a list"
                )
            matches = raw_matches
            for index, match in enumerate(matches):
                if not isinstance(match, Mapping):
                    raise WdaRequestError(
                        f"native element query match {index} must be an object"
                    )
                element_id = match.get(
                    "element-6066-11e4-a52e-4f735466cecf"
                ) or match.get("ELEMENT")
                if not isinstance(element_id, str) or not element_id.strip():
                    raise WdaRequestError(
                        f"native element query match {index} has no valid element id"
                    )
            total_match_count = len(matches)
            raw_result_limit = parameters.get("result_limit")
            if raw_result_limit is not None:
                if isinstance(raw_result_limit, bool):
                    raise WdaRequestError("native element query result_limit must be an integer")
                try:
                    result_limit = int(raw_result_limit)
                except (TypeError, ValueError) as exc:
                    raise WdaRequestError(
                        "native element query result_limit must be an integer"
                    ) from exc
                if result_limit < 1 or result_limit > 5:
                    raise WdaRequestError(
                        "native element query result_limit must be between 1 and 5"
                    )
                if type(parameters.get("result_tail", False)) is not bool:
                    raise WdaRequestError("native element query result_tail must be boolean")
                matches = matches[-result_limit:] if parameters.get("result_tail") else matches[:result_limit]
            elif total_match_count > 5:
                raise WdaRequestError(
                    f"native element query returned {total_match_count} matches; limit is 5"
                )
            role = str(parameters.get("role") or "").strip().casefold()
            requested_attributes = tuple(
                str(name)
                for name in parameters.get(
                    "attribute_names",
                    ("type", "name", "label", "value", "visible", "enabled", "hittable"),
                )
            )
            defaults = dict(parameters.get("defaults") or {})
            elements: list[ElementNode] = []
            for index, match in enumerate(matches):
                element_id = match.get("element-6066-11e4-a52e-4f735466cecf") or match.get(
                    "ELEMENT"
                )
                attrs = dict(defaults)
                for attribute in requested_attributes:
                    attribute_response = self._client.session_request(
                        f"/element/{element_id}/attribute/{attribute}"
                    )
                    attrs[attribute] = attribute_response.get("value")
                element_type = str(attrs.get("type") or "")
                resolved_role = role or element_type.removeprefix(
                    "XCUIElementType"
                ).casefold()
                name = str(attrs.get("name") or "")
                label = str(attrs.get("label") or "")
                element_value = str(attrs.get("value") or "")
                visible = self._wda_bool(attrs.get("visible"), True)
                enabled = self._wda_bool(attrs.get("enabled"), True)
                hittable = self._wda_bool(attrs.get("hittable"), False)
                elements.append(
                    ElementNode(
                        f"ios-query:{element_id}:{index}",
                        role=resolved_role,
                        accessibility_id=name,
                        text=label or name,
                        label=label,
                        value=element_value,
                        visible=visible,
                        enabled=enabled,
                        clickable=resolved_role in {
                            element_type.removeprefix("XCUIElementType").casefold()
                            for element_type in _CLICKABLE_TYPES
                        },
                        attributes={
                            "type": element_type,
                            "value": element_value,
                            "hittable": hittable,
                            "native_query": True,
                        },
                    )
                )
            self._generation += 1
            return Observation(
                self.platform,
                time.time(),
                elements=tuple(elements),
                state={
                        "mobile_control": {
                            "observation_path": "native_element_query",
                            "match_count": len(elements),
                            "total_match_count": total_match_count,
                            "reason": reason,
                        }
                },
                generation=self._generation,
            )
        except Exception as exc:
            self._generation += 1
            return Observation(
                self.platform,
                time.time(),
                errors=(f"native_query: {type(exc).__name__}: {exc}",),
                generation=self._generation,
            )

    def execute_direct(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        bundle_id = self._valid_bundle_id(str(parameters.get("app_id") or self.bundle_id))
        if capability == "app.observe_foreground":
            try:
                response = self._settled_active_app_info()
                value = response.get("value")
                active_bundle = (
                    str(value.get("bundleId") or "")
                    if isinstance(value, dict)
                    else ""
                )
                status = (
                    CommandStatus.ACCEPTED
                    if active_bundle == bundle_id
                    else CommandStatus.REJECTED
                )
                return CommandResult(
                    status,
                    ActionMethod.DIRECT,
                    capability,
                    "target app is foreground"
                    if status is CommandStatus.ACCEPTED
                    else f"foreground app is {active_bundle or 'unknown'}",
                    {"active_bundle": active_bundle, "foreground_settle_polls": response["foreground_settle_polls"]},
                )
            except Exception as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    f"active app query failed: {type(exc).__name__}: {exc}",
                )
        if capability == "control.session.refresh":
            try:
                previous_session, session_id = self._client.refresh_session()
                return CommandResult(
                    CommandStatus.ACCEPTED,
                    ActionMethod.DIRECT,
                    capability,
                    "WDA control session refreshed without terminating the app",
                    {
                        "previous_session_id": previous_session,
                        "session_id": session_id,
                        "runtime_settings": tuple(self._client.session_settings_results),
                    },
                )
            except Exception as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    f"WDA session refresh failed: {type(exc).__name__}: {exc}",
                )
        if self._blocker_probe_mode == "device_service_guard" and capability in {
            "app.launch",
            "app.terminate",
        }:
            if capability == "app.launch" and self._cached_window_size is None:
                self._cached_window_size = self._query_window_size()
            command = "launch" if capability == "app.launch" else "kill"
            result = self._executor.run(
                ("ios", command, bundle_id, "--udid", self._udid),
                timeout_seconds=self._timeout,
            )
            if result.returncode != 0:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    result.stderr.strip() or result.stdout.strip() or f"ios {command} failed",
                )
            if capability == "app.launch":
                self._target_seen_foreground = True
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.DIRECT,
                capability,
                f"go-ios {command} accepted",
                {"process_name": self._process_name},
            )
        if capability == "app.launch":
            wda_result = self._wda_command(
                capability,
                ActionMethod.DIRECT,
                "/wda/apps/launch",
                {"bundleId": bundle_id},
            )
            if wda_result.status is not CommandStatus.REJECTED or not self._udid:
                return wda_result
            try:
                fallback = self._executor.run(
                    ("ios", "launch", bundle_id, "--udid", self._udid),
                    timeout_seconds=self._timeout,
                )
            except Exception as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    f"WDA launch rejected and go-ios fallback failed: {type(exc).__name__}: {exc}",
                    {"wda_error": wda_result.detail, "fallback": "go-ios"},
                )
            if fallback.returncode != 0:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    fallback.stderr.strip()
                    or fallback.stdout.strip()
                    or "WDA launch rejected and go-ios launch failed",
                    {"wda_error": wda_result.detail, "fallback": "go-ios"},
                )
            self._target_seen_foreground = True
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.DIRECT,
                capability,
                "WDA launch rejected; go-ios launch accepted",
                {
                    "wda_error": wda_result.detail,
                    "fallback": "go-ios",
                    "udid": self._udid,
                },
            )
        if capability == "app.terminate":
            return self._wda_command(
                capability,
                ActionMethod.DIRECT,
                "/wda/apps/terminate",
                {"bundleId": bundle_id},
            )
        media_action = {
            "media.ensure_playing": "play",
            "media.ensure_paused": "pause",
            "media.next": "next",
        }.get(capability)
        if media_action is not None:
            page, usage = _HID_MEDIA_CONTROLS[media_action]
            try:
                duration_seconds = float(parameters.get("duration_seconds", 0.005))
            except (TypeError, ValueError):
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    "HID duration must be numeric",
                )
            if duration_seconds <= 0 or duration_seconds > 1:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    "HID duration must be between zero and one second",
                )
            return self._wda_command(
                capability,
                ActionMethod.DIRECT,
                "/wda/performIoHidEvent",
                {
                    "page": page,
                    "usage": usage,
                    "durationSeconds": duration_seconds,
                },
            )
        return CommandResult(
            CommandStatus.UNSUPPORTED,
            ActionMethod.DIRECT,
            capability,
            f"unknown direct capability {capability!r}",
        )

    def execute_element(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        if capability not in {
            "element.activate.query",
            "element.activate.revealed_query",
            "element.replace_text.query",
            "element.activate.candidate",
            "element.activate.media_card",
        }:
            return CommandResult(
                CommandStatus.UNSUPPORTED,
                ActionMethod.ELEMENT,
                capability,
                f"unknown element capability {capability!r}",
            )
        if capability == "element.activate.revealed_query":
            return self._activate_revealed_query(parameters)
        if capability == "element.replace_text.query":
            return self._replace_query_text(parameters)
        if capability in {"element.activate.candidate", "element.activate.media_card"}:
            try:
                candidate_wait_seconds = float(parameters.get("candidate_wait_seconds", 0.0))
                candidate_poll_seconds = float(parameters.get("candidate_poll_seconds", 1.0))
                candidate_initial_scrolls = int(parameters.get("candidate_initial_scrolls", 0))
                candidate_max_scrolls = int(
                    parameters.get("candidate_max_scrolls", candidate_initial_scrolls)
                )
                candidate_scroll_not_before_seconds = float(
                    parameters.get("candidate_scroll_not_before_seconds", 0.0)
                )
                candidate_avoid_recent = int(parameters.get("candidate_avoid_recent", 0))
            except (TypeError, ValueError):
                return self._rejected("candidate wait parameters must be numeric")
            if (
                candidate_wait_seconds < 0
                or candidate_poll_seconds < 0
                or candidate_initial_scrolls < 0
                or candidate_max_scrolls < candidate_initial_scrolls
                or candidate_scroll_not_before_seconds < 0
                or candidate_avoid_recent < 0
            ):
                return self._rejected("candidate wait parameters cannot be negative")
            candidate_history_key = str(
                parameters.get("candidate_history_key") or ""
            ).strip()
            deadline = time.monotonic() + candidate_wait_seconds
            scroll_not_before = (
                time.monotonic() + candidate_scroll_not_before_seconds
            )
            source_polls = 0
            candidate_scrolls = 0
            try:
                snapshot_max_depth = int(
                    parameters.get("candidate_snapshot_max_depth", 0)
                )
                if snapshot_max_depth:
                    if snapshot_max_depth < 1 or snapshot_max_depth > 100:
                        raise ValueError(
                            "candidate_snapshot_max_depth must be between 1 and 100"
                        )
                    self._client.session_request(
                        "/appium/settings",
                        {"settings": {"snapshotMaxDepth": snapshot_max_depth}},
                        timeout_seconds=min(self._timeout, 5.0),
                    )
                while True:
                    response = self._client.session_request("/source", timeout_seconds=self._timeout)
                    source_polls += 1
                    source = response.get("value")
                    if not isinstance(source, str):
                        raise WdaRequestError("WDA source response did not contain XML")
                    nodes = self._parse_source(source)
                    selection_parameters = dict(parameters)
                    if candidate_history_key and candidate_avoid_recent:
                        selection_parameters["avoid_semantic_texts"] = tuple(
                            self._semantic_candidate_history.get(
                                candidate_history_key,
                                (),
                            )[-candidate_avoid_recent:]
                        )
                    selection = (
                        select_semantic_candidate(nodes, selection_parameters)
                        if capability == "element.activate.candidate"
                        else select_media_card(
                            nodes,
                            minimum_duration_seconds=int(
                                parameters.get("minimum_duration_seconds", 60)
                            ),
                            exclude_pattern=str(parameters.get("exclude_pattern") or ""),
                        )
                    )
                    should_scroll = (
                        (
                            candidate_scrolls < candidate_initial_scrolls
                            and (
                                selection.selected is not None
                                or time.monotonic() >= scroll_not_before
                            )
                        )
                        or (
                            candidate_scrolls >= candidate_initial_scrolls
                            and
                            selection.selected is None
                            and candidate_scrolls < candidate_max_scrolls
                        )
                    )
                    if should_scroll:
                        if selection.detail.startswith("blocking surface"):
                            break
                        scroll = self.execute_gesture(
                            "screen.swipe.relative",
                            {
                                "direction": "up",
                                "duration_ms": int(
                                    parameters.get("candidate_scroll_duration_ms", 550)
                                ),
                                "start_y_ratio": float(
                                    parameters.get("candidate_scroll_start_y_ratio", 0.78)
                                ),
                                "end_y_ratio": float(
                                    parameters.get("candidate_scroll_end_y_ratio", 0.30)
                                ),
                            },
                        )
                        if scroll.status is not CommandStatus.ACCEPTED:
                            return CommandResult(
                                scroll.status,
                                ActionMethod.ELEMENT,
                                capability,
                                f"candidate pre-scroll failed: {scroll.detail}",
                                {
                                    **dict(scroll.evidence),
                                    "source_polls": source_polls,
                                    "candidate_scrolls": candidate_scrolls,
                                },
                            )
                        candidate_scrolls += 1
                        remaining = max(0.0, deadline - time.monotonic())
                        time.sleep(min(candidate_poll_seconds, remaining))
                        continue
                    if selection.selected is not None or time.monotonic() >= deadline:
                        break
                    remaining = max(0.0, deadline - time.monotonic())
                    time.sleep(min(candidate_poll_seconds, remaining))
            except WdaRequestTimeout as exc:
                return CommandResult(
                    CommandStatus.TIMEOUT,
                    ActionMethod.ELEMENT,
                    capability,
                    str(exc),
                    {
                        "effect_started": False,
                        "phase": "candidate_source_query",
                        "source_polls": source_polls,
                        "candidate_scrolls": candidate_scrolls,
                    },
                )
            except (WdaRequestError, TypeError, ValueError, re.error, ET.ParseError) as exc:
                return CommandResult(CommandStatus.REJECTED, ActionMethod.ELEMENT, capability, str(exc))
            except Exception as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    f"semantic candidate query failed: {type(exc).__name__}: {exc}",
                )
            if selection.selected is None:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    selection.detail,
                    {
                        "source_polls": source_polls,
                        "candidate_scrolls": candidate_scrolls,
                    },
                )
            if capability == "element.activate.media_card" and selection.anchor is not None:
                anchor = selection.anchor
                container_type = str(selection.selected.attributes.get("type") or "")
                anchor_type = str(anchor.attributes.get("type") or "")
                if (
                    selection.selected is not anchor
                    and container_type
                    and anchor_type
                    and anchor.accessibility_id
                ):
                    query = {
                        "using": "xpath",
                        "value": (
                            f"//{container_type}[.//{anchor_type}"
                            f"[@name={self._xpath_literal(anchor.accessibility_id)}]]"
                        ),
                    }
                    activation_path = "semantic_media_card_container"
                elif anchor_type and anchor.accessibility_id:
                    query = {
                        "using": "predicate string",
                        "value": (
                            f"type == '{self._predicate_escape(anchor_type)}' AND "
                            f"name == '{self._predicate_escape(anchor.accessibility_id)}'"
                        ),
                    }
                    activation_path = "semantic_media_title"
                else:
                    query = None
                    activation_path = "live_media_card_hitpoint"
                result = (
                    self._activate_query(
                        query,
                        capability,
                        {
                            "activation_path": activation_path,
                            "anchor": {
                                "accessibility_id": anchor.accessibility_id,
                                "role": anchor.role,
                                "semantic_text": anchor.semantic_text,
                            },
                        },
                    )
                    if query is not None
                    else self._activate_element_hitpoint(selection.selected)
                )
            else:
                result = self._activate_element_hitpoint(selection.selected)
            selected_semantic_text = str(
                selection.selected.attributes.get("descendant_text")
                or selection.selected.semantic_text
            )
            if (
                result.status is CommandStatus.ACCEPTED
                and capability == "element.activate.candidate"
                and candidate_history_key
            ):
                history = self._semantic_candidate_history.setdefault(
                    candidate_history_key,
                    [],
                )
                history.append(selected_semantic_text)
                del history[:-20]
            return CommandResult(
                result.status,
                result.method,
                capability,
                result.detail,
                {
                    **dict(result.evidence),
                    "source_polls": source_polls,
                    "candidate_scrolls": candidate_scrolls,
                    "snapshot_max_depth": snapshot_max_depth,
                    "candidate_count": (
                        len(selection.candidates)
                        if hasattr(selection, "candidates")
                        else selection.candidate_count
                    ),
                    "selection_policy": (
                        str(parameters.get("selection_policy") or "first_visible")
                        if capability == "element.activate.candidate"
                        else "longest_duration_nearest_title"
                    ),
                    "duration_seconds": getattr(selection, "duration_seconds", None),
                    "selection_detail": selection.detail,
                    "selected": {
                        "accessibility_id": selection.selected.accessibility_id,
                        "role": selection.selected.role,
                        "semantic_text": selected_semantic_text,
                    },
                    "candidate_history_key": candidate_history_key,
                    "candidate_avoid_recent": candidate_avoid_recent,
                },
            )
        using = str(parameters.get("using") or "predicate string").strip()
        value = str(parameters.get("value") or "").strip()
        if using not in {"predicate string", "xpath"}:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                f"unsupported WDA semantic query strategy {using!r}",
            )
        if not value:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                "WDA semantic query value is required",
            )
        try:
            query_wait_seconds = float(parameters.get("query_wait_seconds", 0.0))
            query_poll_seconds = float(parameters.get("query_poll_seconds", 0.75))
        except (TypeError, ValueError):
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                "WDA semantic query wait parameters must be numeric",
            )
        if query_wait_seconds < 0 or query_wait_seconds > 30:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                "WDA semantic query wait must be between zero and 30 seconds",
            )
        if query_poll_seconds <= 0 or query_poll_seconds > 5:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                "WDA semantic query poll interval must be above zero and at most five seconds",
            )
        return self._activate_query(
            {"using": using, "value": value},
            capability,
            {"query": {"using": using, "value": value}},
            match_index=parameters.get("match_index"),
            query_wait_seconds=query_wait_seconds,
            query_poll_seconds=query_poll_seconds,
        )

    def _activate_revealed_query(self, parameters: Mapping[str, Any]) -> CommandResult:
        using = str(parameters.get("using") or "predicate string").strip()
        target_value = str(parameters.get("value") or "").strip()
        reveal_value = str(parameters.get("reveal_value") or "").strip()
        if using not in {"predicate string", "xpath"}:
            return self._rejected("unsupported WDA semantic query strategy")
        if not target_value or not reveal_value:
            return self._rejected("target and reveal query values are required")
        target_query = {"using": using, "value": target_value}
        reveal_query = {"using": using, "value": reveal_value}
        direct_target = self._activate_query(
            target_query,
            "element.activate.revealed_query",
            {"activation_path": "target_already_visible", "target_query": target_query},
        )
        if direct_target.status is CommandStatus.ACCEPTED:
            return direct_target
        if "resolved 0 elements" not in direct_target.detail:
            return direct_target
        reveal = self._activate_query(
            reveal_query,
            "element.activate.revealed_query",
            {"activation_path": "reveal_control", "reveal_query": reveal_query},
        )
        if reveal.status is not CommandStatus.ACCEPTED:
            return reveal
        try:
            wait_seconds = float(parameters.get("reveal_wait_seconds", 0.5))
        except (TypeError, ValueError):
            return self._rejected("reveal_wait_seconds must be numeric")
        if wait_seconds < 0 or wait_seconds > 5:
            return self._rejected("reveal_wait_seconds must be between zero and five")
        time.sleep(wait_seconds)
        return self._activate_query(
            target_query,
            "element.activate.revealed_query",
            {
                "activation_path": "revealed_target",
                "target_query": target_query,
                "reveal_query": reveal_query,
                "reveal_response": dict(reveal.evidence),
            },
        )

    def _replace_query_text(self, parameters: Mapping[str, Any]) -> CommandResult:
        using = str(parameters.get("using") or "predicate string").strip()
        value = str(parameters.get("value") or "").strip()
        text = parameters.get("text")
        if using not in {"predicate string", "xpath"}:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                f"unsupported WDA semantic query strategy {using!r}",
            )
        if not value:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                "WDA semantic query value is required",
            )
        if not isinstance(text, str):
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                "replacement text must be a string",
            )
        if len(text) > 4096:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                "replacement text exceeds 4096 characters",
            )

        query = {"using": using, "value": value}
        evidence: dict[str, Any] = {
            "query": query,
            "replacement_length": len(text),
        }
        try:
            response = self._client.session_request("/elements", query)
        except WdaRequestTimeout as exc:
            return CommandResult(
                CommandStatus.TIMEOUT,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                str(exc),
                evidence,
            )
        except Exception as exc:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                f"semantic query failed before text replacement: {type(exc).__name__}: {exc}",
                evidence,
            )
        element_ids = self._element_ids(response)
        if len(element_ids) != 1:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                f"WDA semantic query resolved {len(element_ids)} elements; expected exactly one",
                evidence,
            )
        element_id = element_ids[0]
        evidence["wda_element_id"] = element_id
        try:
            focus_response = self._client.session_request(
                f"/element/{element_id}/click",
                {},
            )
            clear_response = self._client.session_request(
                f"/element/{element_id}/clear",
                {},
            )
            value_response = self._client.session_request(
                f"/element/{element_id}/value",
                {"value": list(text), "text": text},
            )
        except WdaRequestTimeout as exc:
            return CommandResult(
                CommandStatus.UNKNOWN,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                f"text replacement outcome is uncertain: {exc}",
                evidence,
            )
        except Exception as exc:
            return CommandResult(
                CommandStatus.UNKNOWN,
                ActionMethod.ELEMENT,
                "element.replace_text.query",
                f"text replacement outcome is uncertain: {type(exc).__name__}: {exc}",
                evidence,
            )
        return CommandResult(
            CommandStatus.ACCEPTED,
            ActionMethod.ELEMENT,
            "element.replace_text.query",
            "WDA text replacement accepted",
            {
                **evidence,
                "focus_response": focus_response,
                "clear_response": clear_response,
                "value_response": value_response,
            },
        )

    def activate_element(self, element: ElementNode, parameters: Mapping[str, Any]) -> CommandResult:
        clauses: list[str] = []
        element_type = str(element.attributes.get("type") or "")
        if element_type:
            clauses.append(f"type == '{self._predicate_escape(element_type)}'")
        if element.accessibility_id:
            clauses.append(f"name == '{self._predicate_escape(element.accessibility_id)}'")
        if element.label:
            clauses.append(f"label == '{self._predicate_escape(element.label)}'")
        if element.value:
            clauses.append(f"value == '{self._predicate_escape(element.value)}'")
        if not clauses:
            identity = element.text
            if not identity:
                if parameters.get("interruption_rule") and element.bounds is not None:
                    return self._activate_element_hitpoint(element)
                return self._rejected("element has no semantic identity")
            escaped = self._predicate_escape(identity)
            clauses.append(f"(name == '{escaped}' OR label == '{escaped}')")
        # WebDriverAgent exposes the native strategy name without the
        # Appium-only ``-ios`` prefix.
        query = {"using": "predicate string", "value": " AND ".join(clauses)}
        result = self._activate_query(
            query,
            "element.activate",
            {"element_handle": element.handle},
        )
        # A rejected lookup means no click was sent, so the current live bounds
        # remain a safe adapter-internal fallback for small overlay controls.
        # Accepted, timed-out, or unknown native clicks are never duplicated.
        if (
            parameters.get("interruption_rule")
            and result.status is CommandStatus.REJECTED
            and element.bounds is not None
        ):
            fallback = self._activate_element_hitpoint(element)
            return CommandResult(
                fallback.status,
                fallback.method,
                fallback.command_id,
                fallback.detail,
                {
                    **dict(fallback.evidence),
                    "native_query_fallback": result.detail,
                },
            )
        return result

    def _activate_element_hitpoint(self, element: ElementNode) -> CommandResult:
        assert element.bounds is not None
        x1, y1, x2, y2 = element.bounds
        if x2 <= x1 or y2 <= y1:
            return self._rejected("element has invalid live bounds")
        point = {"x": round((x1 + x2) / 2), "y": round((y1 + y2) / 2)}
        try:
            response = self._client.session_request("/wda/tap", point)
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.ELEMENT,
                "element.activate",
                "WDA element hit-point tap accepted",
                {
                    "element_handle": element.handle,
                    "bounds": element.bounds,
                    "point": (point["x"], point["y"]),
                    "response": response,
                },
            )
        except WdaRequestTimeout as exc:
            return CommandResult(
                CommandStatus.TIMEOUT,
                ActionMethod.ELEMENT,
                "element.activate",
                str(exc),
                {"element_handle": element.handle, "bounds": element.bounds},
            )
        except Exception as exc:
            return CommandResult(
                CommandStatus.UNKNOWN,
                ActionMethod.ELEMENT,
                "element.activate",
                f"element hit-point outcome is uncertain: {type(exc).__name__}: {exc}",
                {"element_handle": element.handle, "bounds": element.bounds},
            )

    def execute_gesture(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        if capability == "system.recents.clear":
            return self._clear_recent_apps(parameters)
        if capability not in {
            "screen.tap.relative",
            "screen.swipe.relative",
            "screen.swipe.relative.native",
        }:
            return CommandResult(
                CommandStatus.UNSUPPORTED,
                ActionMethod.GESTURE,
                capability,
                f"unknown gesture capability {capability!r}",
            )
        if capability == "screen.tap.relative":
            try:
                x_ratio = float(parameters.get("x_ratio", 0.5))
                y_ratio = float(parameters.get("y_ratio", 0.5))
            except (TypeError, ValueError):
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.GESTURE,
                    capability,
                    "tap ratios must be numbers",
                )
            if not (0 <= x_ratio <= 1 and 0 <= y_ratio <= 1):
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.GESTURE,
                    capability,
                    "tap ratios must be between zero and one",
                )
            try:
                session_refresh: dict[str, Any] | None = None
                if self._wda_bool(parameters.get("refresh_session_before"), False):
                    previous_session, session_id = self._client.refresh_session()
                    session_refresh = {
                        "previous_session_id": previous_session,
                        "session_id": session_id,
                        "runtime_settings": tuple(
                            self._client.session_settings_results
                        ),
                    }
                width, height = self._get_window_size()
                payload = {
                    "x": round(width * x_ratio),
                    "y": round(height * y_ratio),
                }
                response = self._client.session_request("/wda/tap", payload)
                return CommandResult(
                    CommandStatus.ACCEPTED,
                    ActionMethod.GESTURE,
                    capability,
                    "WDA relative tap accepted",
                    {
                        "ratios": (x_ratio, y_ratio),
                        "screen_size": (width, height),
                        "point": (payload["x"], payload["y"]),
                        "response": response,
                        **(
                            {"session_refresh": session_refresh}
                            if session_refresh is not None
                            else {}
                        ),
                    },
                )
            except WdaRequestTimeout as exc:
                return CommandResult(
                    CommandStatus.TIMEOUT,
                    ActionMethod.GESTURE,
                    capability,
                    str(exc),
                )
            except WdaRequestError as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.GESTURE,
                    capability,
                    str(exc),
                )
            except Exception as exc:
                return CommandResult(
                    CommandStatus.UNKNOWN,
                    ActionMethod.GESTURE,
                    capability,
                    f"{type(exc).__name__}: {exc}",
                )

        direction = str(parameters.get("direction") or "up").casefold()
        paths = {
            "up": (0.5, 0.75, 0.5, 0.25),
            "down": (0.5, 0.25, 0.5, 0.75),
            "left": (0.8, 0.5, 0.2, 0.5),
            "right": (0.2, 0.5, 0.8, 0.5),
        }
        if direction not in paths:
            return self._rejected("unsupported direction", method=ActionMethod.GESTURE)
        try:
            guard_names = parameters.get("required_visible_names")
            guard_evidence: dict[str, Any] = {}
            if guard_names is not None:
                if (
                    not isinstance(guard_names, (list, tuple))
                    or not 1 <= len(guard_names) <= 3
                    or any(not isinstance(name, str) or not name.strip() for name in guard_names)
                ):
                    return self._rejected("invalid swipe surface guard", method=ActionMethod.GESTURE)
                active = self._client.session_request("/wda/activeAppInfo").get("value")
                if not isinstance(active, dict) or active.get("bundleId") != self.bundle_id:
                    return self._rejected("swipe target app is not foreground", method=ActionMethod.GESTURE)
                self._client.session_request(
                    "/appium/settings", {"settings": {"snapshotMaxDepth": 50}},
                    timeout_seconds=min(self._timeout, 5.0),
                )
                source = self._client.session_request("/source").get("value")
                if not isinstance(source, str):
                    return self._rejected("swipe surface guard source is unavailable", method=ActionMethod.GESTURE)
                nodes = self._parse_source(source)
                dependencies = parameters.get("visible_marker_dependencies", {})
                if not isinstance(dependencies, dict) or len(dependencies) > 3:
                    return self._rejected("invalid swipe marker dependencies", method=ActionMethod.GESTURE)
                required_names = list(guard_names)
                for marker, dependents in dependencies.items():
                    if (
                        not isinstance(marker, str) or not marker.strip()
                        or not isinstance(dependents, (list, tuple))
                        or not 1 <= len(dependents) <= 3
                        or any(not isinstance(name, str) or not name.strip() for name in dependents)
                    ):
                        return self._rejected("invalid swipe marker dependencies", method=ActionMethod.GESTURE)
                    if any(node.visible and marker in (node.accessibility_id, node.text) for node in nodes):
                        required_names.extend((marker, *dependents))
                for name in required_names:
                    matches = [
                        node for node in nodes
                        if node.visible and name in (node.accessibility_id, node.text)
                    ]
                    # XCTest may duplicate the same marker at the same positive
                    # bounds. This presence guard chooses no hit target; distinct
                    # visible locations and unresolved duplicates stay ambiguous.
                    locations = {
                        (node.role, node.bounds)
                        if node.bounds and node.bounds[2] > node.bounds[0]
                        and node.bounds[3] > node.bounds[1]
                        else ("unresolved", node.handle)
                        for node in matches
                    }
                    if len(locations) != 1:
                        return self._rejected(
                            f"swipe surface guard requires one visible {name!r}; found {len(matches)}",
                            method=ActionMethod.GESTURE,
                        )
                guard_evidence["required_visible_names"] = tuple(required_names)
            width, height = self._get_window_size()
            x1r, y1r, x2r, y2r = paths[direction]
            if direction in {"up", "down"}:
                x1r = float(parameters.get("x_ratio", x1r))
                x2r = x1r
                y1r = float(parameters.get("start_y_ratio", y1r))
                y2r = float(parameters.get("end_y_ratio", y2r))
            elif direction in {"left", "right"}:
                y1r = float(parameters.get("y_ratio", y1r))
                y2r = y1r
                x1r = float(parameters.get("start_x_ratio", x1r))
                x2r = float(parameters.get("end_x_ratio", x2r))
            ratios = (x1r, y1r, x2r, y2r)
            if not all(0 <= ratio <= 1 for ratio in ratios):
                return self._rejected(
                    "swipe ratios must be between zero and one",
                    method=ActionMethod.GESTURE,
                )
            duration_ms = max(50, int(parameters.get("duration_ms", 450)))
            start_x = round(width * x1r)
            start_y = round(height * y1r)
            end_x = round(width * x2r) + int(parameters.get("end_x_delta_px", 0))
            end_y = round(height * y2r)
            if not (0 <= end_x < width and 0 <= end_y < height):
                return self._rejected(
                    "derived swipe endpoint is outside the current viewport",
                    method=ActionMethod.GESTURE,
                )
            if capability == "screen.swipe.relative.native":
                native_hold_ms = max(
                    10,
                    min(500, int(parameters.get("native_hold_ms", 50))),
                )
                response = self._client.session_request(
                    "/wda/dragfromtoforduration",
                    {
                        "fromX": start_x,
                        "fromY": start_y,
                        "toX": end_x,
                        "toY": end_y,
                        "duration": native_hold_ms / 1000.0,
                    },
                )
                return CommandResult(
                    CommandStatus.ACCEPTED,
                    ActionMethod.GESTURE,
                    capability,
                    "WDA native relative swipe accepted",
                    {
                        **guard_evidence,
                        "direction": direction,
                        "duration_ms": duration_ms,
                        "native_hold_ms": native_hold_ms,
                        "path": (start_x, start_y, end_x, end_y),
                        "screen_size": (width, height),
                        "response": response,
                    },
                )
            payload = {
                "actions": [
                    {
                        "type": "pointer",
                        "id": "finger1",
                        "parameters": {"pointerType": "touch"},
                        "actions": [
                            {
                                "type": "pointerMove",
                                "duration": 0,
                                "x": start_x,
                                "y": start_y,
                            },
                            {"type": "pointerDown", "button": 0},
                            {"type": "pause", "duration": 50},
                            {
                                "type": "pointerMove",
                                "duration": duration_ms,
                                "x": end_x,
                                "y": end_y,
                            },
                            {"type": "pointerUp", "button": 0},
                        ],
                    }
                ]
            }
            response = self._client.session_request("/actions", payload)
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.GESTURE,
                capability,
                "WDA relative swipe accepted",
                {
                    **guard_evidence,
                    "direction": direction,
                    "duration_ms": duration_ms,
                    "path": (start_x, start_y, end_x, end_y),
                    "screen_size": (width, height),
                    "response": response,
                },
            )
        except WdaRequestTimeout as exc:
            return CommandResult(CommandStatus.TIMEOUT, ActionMethod.GESTURE, capability, str(exc))
        except Exception as exc:
            return CommandResult(
                CommandStatus.UNKNOWN,
                ActionMethod.GESTURE,
                capability,
                f"{type(exc).__name__}: {exc}",
            )

    def _clear_recent_apps(self, parameters: Mapping[str, Any]) -> CommandResult:
        """Port the AssistiveTouch App Switcher route proven on this test phone."""

        capability = "system.recents.clear"
        method = "app_switcher_swipe_up"
        try:
            max_swipes = int(parameters.get("max_swipes", 20))
        except (TypeError, ValueError):
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.GESTURE,
                capability,
                "max_swipes must be numeric",
                {"method": method, "empty_verified": False, "remaining_cards": -1},
            )
        if not 1 <= max_swipes <= 100:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.GESTURE,
                capability,
                "max_swipes must be between 1 and 100",
                {"method": method, "empty_verified": False, "remaining_cards": -1},
            )
        route: list[str] = []
        swipes_attempted = 0
        final_source = ""
        final_visible_nodes = 0
        active_bundle = ""
        uncertain_swipe_reconciled = ""
        home_screen_visible = False
        entry_verification = ""
        entry_source_bytes = 0
        entry_visible_nodes = 0
        entry_visual_evidence: Mapping[str, Any] = {}
        final_home_visual_evidence: Mapping[str, Any] = {}
        try:
            width, height = self._get_window_size()
            # These are the current AssistiveTouch menu locations on the
            # 375x667 test viewport, expressed as ratios for the live viewport.
            for x_ratio, y_ratio, label in (
                (344 / 375, 176 / 667, "assistivetouch"),
                (270 / 375, 170 / 667, "device"),
                (238 / 375, 295 / 667, "more"),
                (100 / 375, 118 / 667, "app_switcher"),
            ):
                self._client.session_request(
                    "/wda/tap",
                    {
                        "x": round(width * x_ratio),
                        "y": round(height * y_ratio),
                    },
                )
                route.append(label)
                time.sleep(0.2)

            # Do not start blind upward swipes unless the route actually
            # reached the native App Switcher. A wrong AssistiveTouch hit can
            # otherwise swipe an ordinary app or SpringBoard page repeatedly.
            time.sleep(0.4)
            switcher_response = self._client.session_request(
                "/elements",
                {
                    "using": "predicate string",
                    "value": (
                        "type == 'XCUIElementTypeOther' AND "
                        "name == 'AppSwitcherContentView' AND visible == 1"
                    ),
                },
                timeout_seconds=min(self._timeout, 5.0),
            )
            switcher_value = switcher_response.get("value")
            switcher_visible = (
                isinstance(switcher_value, list) and len(switcher_value) > 0
            )
            home_response = self._client.session_request(
                "/elements",
                {
                    "using": "predicate string",
                    "value": (
                        "type == 'XCUIElementTypeOther' AND "
                        "name == 'Home screen icons' AND visible == 1"
                    ),
                },
                timeout_seconds=min(self._timeout, 5.0),
            )
            home_value = home_response.get("value")
            home_screen_visible = (
                isinstance(home_value, list) and len(home_value) > 0
            )
            active = self._client.session_request("/wda/activeAppInfo")
            active_value = active.get("value")
            active_bundle = (
                str(active_value.get("bundleId") or "")
                if isinstance(active_value, dict)
                else ""
            )
            if switcher_visible:
                entry_verification = "native_app_switcher_content_view"
            elif active_bundle == "com.apple.springboard" and not home_screen_visible:
                # iOS 18.7 can render the native App Switcher while WDA exposes
                # only one minimal SpringBoard application node. Accept that
                # exact system state after the bounded AssistiveTouch route;
                # an ordinary app, the normal home screen, or a populated
                # system accessibility tree still fails closed.
                entry_source_response = self._client.session_request(
                    "/source", timeout_seconds=self._timeout
                )
                entry_source_value = entry_source_response.get("value")
                entry_source = (
                    entry_source_value
                    if isinstance(entry_source_value, str)
                    else ""
                )
                entry_source_bytes = len(entry_source.encode("utf-8"))
                entry_visible_nodes = entry_source.count('visible="true"')
                entry_visual_evidence = _springboard_home_visual_evidence(
                    self._capture_screenshot()
                )
                if 100 <= entry_source_bytes <= 1000 and entry_visible_nodes <= 1:
                    if entry_visual_evidence.get("is_home"):
                        home_screen_visible = True
                        final_source = entry_source
                        final_visible_nodes = entry_visible_nodes
                        final_home_visual_evidence = entry_visual_evidence
                        entry_verification = "visual_springboard_home_already_empty"
                    else:
                        switcher_visible = True
                        entry_verification = "minimal_springboard_overlay_tree"
            if not switcher_visible:
                if not (
                    home_screen_visible and active_bundle == "com.apple.springboard"
                ):
                    raise WdaRequestError(
                        "AssistiveTouch route did not enter the native App Switcher"
                    )
                final_source_response = self._client.session_request(
                    "/source", timeout_seconds=self._timeout
                )
                final_source_value = final_source_response.get("value")
                final_source = (
                    final_source_value
                    if isinstance(final_source_value, str)
                    else ""
                )
                final_visible_nodes = final_source.count('visible="true"')

            for index in range(max_swipes if switcher_visible else 0):
                swipes_attempted += 1
                uncertain_swipe_error = ""
                try:
                    self._ios_pointer_actions(
                        width,
                        height,
                        (
                            {
                                "type": "pointerMove",
                                "duration": 0,
                                "x": round(width * (188 / 375)),
                                "y": round(height * (470 / 667)),
                            },
                            {"type": "pointerDown", "button": 0},
                            {"type": "pause", "duration": 40},
                            {
                                "type": "pointerMove",
                                "duration": 260,
                                "x": round(width * (188 / 375)),
                                "y": round(height * (60 / 667)),
                            },
                            {"type": "pointerUp", "button": 0},
                        ),
                    )
                except Exception as exc:
                    # The App Switcher can invalidate the WDA session after it
                    # has already accepted the swipe. Never replay that
                    # non-idempotent gesture; reconcile through fresh read-only
                    # SpringBoard evidence instead.
                    uncertain_swipe_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.35)
                home_response = self._client.session_request(
                    "/elements",
                    {
                        "using": "predicate string",
                        "value": (
                            "type == 'XCUIElementTypeOther' AND "
                            "name == 'Home screen icons' AND visible == 1"
                        ),
                    },
                    timeout_seconds=min(self._timeout, 5.0),
                )
                home_value = home_response.get("value")
                home_screen_visible = (
                    isinstance(home_value, list) and len(home_value) > 0
                )
                if not home_screen_visible:
                    if uncertain_swipe_error:
                        raise WdaRequestError(
                            "App Switcher swipe transport became uncertain and fresh "
                            "home-screen evidence did not reconcile it: "
                            f"{uncertain_swipe_error}"
                        )
                    active = self._client.session_request("/wda/activeAppInfo")
                    active_value = active.get("value")
                    active_bundle = (
                        str(active_value.get("bundleId") or "")
                        if isinstance(active_value, dict)
                        else ""
                    )
                    source_response = self._client.session_request(
                        "/source", timeout_seconds=self._timeout
                    )
                    source_value = source_response.get("value")
                    current_source = (
                        source_value if isinstance(source_value, str) else ""
                    )
                    current_source_bytes = len(current_source.encode("utf-8"))
                    current_visible_nodes = current_source.count('visible="true"')
                    final_home_visual_evidence = _springboard_home_visual_evidence(
                        self._capture_screenshot()
                    )
                    minimal_springboard = (
                        active_bundle == "com.apple.springboard"
                        and 100 <= current_source_bytes <= 1000
                        and current_visible_nodes <= 1
                    )
                    if minimal_springboard and final_home_visual_evidence.get("is_home"):
                        home_screen_visible = True
                        final_source = current_source
                        final_visible_nodes = current_visible_nodes
                        uncertain_swipe_reconciled = uncertain_swipe_error
                        break
                    if minimal_springboard:
                        # The same minimal tree represents the still-visible
                        # switcher on iOS 18.7. The visual home check above
                        # distinguishes the final card dismissal.
                        continue
                    # A swipe that leaves both the App Switcher and the home
                    # screen is not a card dismissal. Stop immediately instead
                    # of injecting the remaining bounded swipes into an app.
                    switcher_response = self._client.session_request(
                        "/elements",
                        {
                            "using": "predicate string",
                            "value": (
                                "type == 'XCUIElementTypeOther' AND "
                                "name == 'AppSwitcherContentView' AND visible == 1"
                            ),
                        },
                        timeout_seconds=min(self._timeout, 5.0),
                    )
                    switcher_value = switcher_response.get("value")
                    if not (
                        isinstance(switcher_value, list)
                        and len(switcher_value) > 0
                    ):
                        raise WdaRequestError(
                            "App Switcher disappeared before an empty home screen was verified"
                        )
                    continue
                source_response = self._client.session_request(
                    "/source", timeout_seconds=self._timeout
                )
                source_value = source_response.get("value")
                final_source = source_value if isinstance(source_value, str) else ""
                final_visible_nodes = final_source.count('visible="true"')
                active = self._client.session_request("/wda/activeAppInfo")
                active_value = active.get("value")
                active_bundle = (
                    str(active_value.get("bundleId") or "")
                    if isinstance(active_value, dict)
                    else ""
                )
                if (
                    active_bundle == "com.apple.springboard"
                    and home_screen_visible
                    and len(final_source.encode("utf-8")) > 1000
                    and final_visible_nodes >= 2
                ):
                    uncertain_swipe_reconciled = uncertain_swipe_error
                    break

            active = self._client.session_request("/wda/activeAppInfo")
            active_value = active.get("value")
            if isinstance(active_value, dict):
                active_bundle = str(active_value.get("bundleId") or "")
            source_bytes = len(final_source.encode("utf-8"))
            normal_home_tree_verified = (
                active_bundle == "com.apple.springboard"
                and home_screen_visible
                and source_bytes > 1000
                and final_visible_nodes >= 2
            )
            visual_home_verified = (
                active_bundle == "com.apple.springboard"
                and home_screen_visible
                and 100 <= source_bytes <= 1000
                and final_visible_nodes <= 1
                and bool(final_home_visual_evidence.get("is_home"))
            )
            empty_verified = normal_home_tree_verified or visual_home_verified
            alert_text = ""
            known_alert_dismissed = ""
            if empty_verified:
                # A failed go-ios DeviceKit helper installation can surface only
                # after App Switcher returns to SpringBoard. Acknowledge exactly
                # that non-permission failure notice before capture; every other
                # alert remains a fail-closed blocker.
                time.sleep(1.0)
                try:
                    alert_response = self._client.session_request(
                        "/alert/text", timeout_seconds=5.0
                    )
                    alert_value = alert_response.get("value")
                    alert_text = (
                        alert_value.strip() if isinstance(alert_value, str) else ""
                    )
                except WdaRequestError as exc:
                    message = str(exc).casefold()
                    if "no such alert" in message or "no alert" in message:
                        alert_text = ""
                    else:
                        raise
                if alert_text:
                    if alert_text not in _KNOWN_POST_ISOLATION_ALERTS:
                        empty_verified = False
                    else:
                        self._client.session_request("/alert/accept", {})
                        time.sleep(0.3)
                        known_alert_dismissed = alert_text
            evidence = {
                "method": method,
                "entry_method": "assistivetouch_system_app_switcher",
                "route": route,
                "screen_size": (width, height),
                "swipes_attempted": swipes_attempted,
                "dismissed_cards": swipes_attempted,
                "remaining_cards": 0 if empty_verified else -1,
                "empty_verified": empty_verified,
                "active_bundle": active_bundle,
                "home_screen_visible": home_screen_visible,
                "entry_verification": entry_verification,
                "entry_source_bytes": entry_source_bytes,
                "entry_visible_nodes": entry_visible_nodes,
                "entry_visual_evidence": entry_visual_evidence,
                "final_home_visual_evidence": final_home_visual_evidence,
                "home_verification": (
                    "normal_springboard_tree"
                    if normal_home_tree_verified
                    else "visual_springboard_dock"
                    if visual_home_verified
                    else ""
                ),
                "final_source_bytes": source_bytes,
                "final_visible_nodes": final_visible_nodes,
                "known_post_isolation_alert_dismissed": known_alert_dismissed,
                "uncertain_swipe_reconciled": uncertain_swipe_reconciled,
            }
            if not empty_verified:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.GESTURE,
                    capability,
                    (
                        f"unexpected post-isolation alert blocks collection: {alert_text}"
                        if alert_text
                        else "App Switcher did not return to the normal SpringBoard window tree"
                    ),
                    evidence,
                )
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.GESTURE,
                capability,
                f"AssistiveTouch App Switcher cleared after {swipes_attempted} upward swipe(s)",
                evidence,
            )
        except WdaRequestTimeout as exc:
            status = CommandStatus.TIMEOUT
            detail = str(exc)
        except WdaRequestError as exc:
            status = CommandStatus.REJECTED
            detail = str(exc)
        except Exception as exc:
            status = CommandStatus.UNKNOWN
            detail = f"{type(exc).__name__}: {exc}"
        return CommandResult(
            status,
            ActionMethod.GESTURE,
            capability,
            detail,
            {
                "method": method,
                "entry_method": "assistivetouch_system_app_switcher",
                "route": route,
                "swipes_attempted": swipes_attempted,
                "remaining_cards": -1,
                "empty_verified": False,
                "active_bundle": active_bundle,
            },
        )

    def _ios_pointer_actions(
        self,
        width: int,
        height: int,
        actions: tuple[Mapping[str, Any], ...],
    ) -> None:
        if width <= 0 or height <= 0:
            raise WdaRequestError("invalid iOS viewport for pointer actions")
        self._client.session_request(
            "/actions",
            {
                "actions": [
                    {
                        "type": "pointer",
                        "id": "finger1",
                        "parameters": {"pointerType": "touch"},
                        "actions": list(actions),
                    }
                ]
            },
        )

    def execute_visual(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        return CommandResult(
            CommandStatus.UNSUPPORTED,
            ActionMethod.VISUAL,
            capability,
            "iOS adapter has no runtime visual-agent capability",
        )

    def _wda_command(
        self,
        capability: str,
        method: ActionMethod,
        path: str,
        payload: Mapping[str, Any],
    ) -> CommandResult:
        try:
            response = self._client.session_request(path, payload)
            return CommandResult(
                CommandStatus.ACCEPTED,
                method,
                capability,
                "WDA command accepted",
                {"response": response},
            )
        except WdaRequestTimeout as exc:
            return CommandResult(CommandStatus.TIMEOUT, method, capability, str(exc))
        except WdaRequestError as exc:
            return CommandResult(CommandStatus.REJECTED, method, capability, str(exc))
        except Exception as exc:
            return CommandResult(
                CommandStatus.UNKNOWN,
                method,
                capability,
                f"{type(exc).__name__}: {exc}",
            )

    def _activate_query(
        self,
        query: Mapping[str, Any],
        capability: str,
        evidence: Mapping[str, Any],
        *,
        match_index: Any = None,
        query_wait_seconds: float = 0.0,
        query_poll_seconds: float = 0.75,
    ) -> CommandResult:
        deadline = time.monotonic() + query_wait_seconds
        query_polls = 0
        while True:
            try:
                if query_polls == 0:
                    # Visual-only sessions start shallow; native lookup must
                    # include nested controls before deciding they are absent.
                    self._client.session_request(
                        "/appium/settings",
                        {"settings": {"snapshotMaxDepth": 50}},
                        timeout_seconds=min(self._timeout, 5.0),
                    )
                response = self._client.session_request("/elements", query)
            except WdaRequestTimeout as exc:
                return CommandResult(CommandStatus.TIMEOUT, ActionMethod.ELEMENT, capability, str(exc))
            except WdaRequestError as exc:
                # Lookup failed before any click was sent, so retrying a bounded
                # recovery path is safe.
                return CommandResult(CommandStatus.REJECTED, ActionMethod.ELEMENT, capability, str(exc))
            except Exception as exc:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    f"semantic query failed before activation: {type(exc).__name__}: {exc}",
                )
            query_polls += 1
            element_ids = self._element_ids(response)
            if element_ids or time.monotonic() >= deadline:
                break
            time.sleep(min(query_poll_seconds, max(0.0, deadline - time.monotonic())))
        if match_index is None and len(element_ids) != 1:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                f"WDA semantic query resolved {len(element_ids)} elements; expected exactly one",
                {**dict(evidence), "query_polls": query_polls},
            )
        if match_index is not None:
            try:
                selected_index = int(match_index)
            except (TypeError, ValueError):
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    "WDA semantic query match_index must be an integer",
                    dict(evidence),
                )
            if selected_index < 0 or selected_index >= len(element_ids):
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    f"WDA semantic query match_index {selected_index} is outside {len(element_ids)} matches",
                    dict(evidence),
                )
        else:
            selected_index = 0
        element_id = element_ids[selected_index]
        try:
            clicked = self._client.session_request(f"/element/{element_id}/click", {})
        except WdaRequestTimeout as exc:
            return CommandResult(CommandStatus.TIMEOUT, ActionMethod.ELEMENT, capability, str(exc))
        except Exception as exc:
            # A click request may have reached the device even when its receipt
            # is unavailable. Preserve uncertainty so non-idempotent actions
            # are not blindly repeated.
            return CommandResult(
                CommandStatus.UNKNOWN,
                ActionMethod.ELEMENT,
                capability,
                f"element click outcome is uncertain: {type(exc).__name__}: {exc}",
                {**dict(evidence), "wda_element_id": element_id},
            )
        return CommandResult(
            CommandStatus.ACCEPTED,
            ActionMethod.ELEMENT,
            capability,
            "WDA element click accepted",
            {
                **dict(evidence),
                "query_polls": query_polls,
                "wda_element_id": element_id,
                "match_count": len(element_ids),
                "selected_index": selected_index,
                "response": clicked,
            },
        )

    @staticmethod
    def _element_ids(response: Mapping[str, Any]) -> list[str]:
        value = response.get("value")
        matches = value if isinstance(value, list) else []
        element_ids = [
            match.get("element-6066-11e4-a52e-4f735466cecf") or match.get("ELEMENT")
            for match in matches
            if isinstance(match, Mapping)
        ]
        return [str(element_id) for element_id in element_ids if element_id]

    @staticmethod
    def _rejected(detail: str, method: ActionMethod = ActionMethod.ELEMENT) -> CommandResult:
        capability = "element.activate" if method is ActionMethod.ELEMENT else "screen.swipe.relative"
        return CommandResult(CommandStatus.REJECTED, method, capability, detail)

    @staticmethod
    def _valid_bundle_id(value: str) -> str:
        if not _BUNDLE_ID.fullmatch(value):
            raise ValueError(f"invalid iOS bundle id {value!r}")
        return value

    @staticmethod
    def _predicate_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _xpath_literal(value: str) -> str:
        if "'" not in value:
            return f"'{value}'"
        if '"' not in value:
            return f'"{value}"'
        parts = value.split("'")
        pieces: list[str] = []
        for index, part in enumerate(parts):
            if part:
                pieces.append(f"'{part}'")
            if index < len(parts) - 1:
                pieces.append('"\'"')
        return f"concat({', '.join(pieces)})"

    @staticmethod
    def _wda_bool(value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "1"}:
                return True
            if normalized in {"false", "0"}:
                return False
        return default

    @staticmethod
    def _parse_source(source: str) -> tuple[ElementNode, ...]:
        root = ET.fromstring(source)
        nodes: list[ElementNode] = []
        for index, element in enumerate(root.iter()):
            attrs = dict(element.attrib)
            element_type = attrs.get("type") or element.tag
            if not element_type.startswith("XCUIElementType"):
                continue
            name = attrs.get("name", "")
            label = attrs.get("label", "")
            value = attrs.get("value", "")
            descendant_text = " | ".join(
                child_value.strip()
                for child in element.iter()
                for child_value in (
                    child.attrib.get("name", ""),
                    child.attrib.get("label", ""),
                    child.attrib.get("value", ""),
                )
                if child_value.strip()
            )
            bounds = None
            try:
                x = int(float(attrs["x"]))
                y = int(float(attrs["y"]))
                width = int(float(attrs["width"]))
                height = int(float(attrs["height"]))
                bounds = (x, y, x + width, y + height)
            except (KeyError, TypeError, ValueError):
                pass
            nodes.append(
                ElementNode(
                    f"ios:{index}",
                    role=element_type.removeprefix("XCUIElementType").casefold(),
                    accessibility_id=name,
                    text=label or name,
                    label=label,
                    value=value,
                    visible=attrs.get("visible", "true") == "true",
                    enabled=attrs.get("enabled", "true") == "true",
                    clickable=element_type in _CLICKABLE_TYPES,
                    attributes={
                        "type": element_type,
                        "value": value,
                        "selected": attrs.get("selected") == "true",
                        "accessible": attrs.get("accessible") == "true",
                        "hittable": attrs.get("hittable") == "true",
                        "descendant_text": descendant_text,
                    },
                    bounds=bounds,
                )
            )
        return tuple(nodes)

    def _get_window_size(self) -> tuple[int, int]:
        if self._blocker_probe_mode == "device_service_guard":
            if self._cached_window_size is None:
                raise WdaRequestError("AX-free viewport was not cached before app launch")
            return self._cached_window_size
        return self._query_window_size()

    def _query_window_size(self) -> tuple[int, int]:
        response = self._client.session_request("/window/rect")
        value = response.get("value")
        if not isinstance(value, dict):
            raise WdaRequestError("WDA window rect response is missing value")
        width = int(value.get("width") or 0)
        height = int(value.get("height") or 0)
        if width <= 0 or height <= 0:
            raise WdaRequestError(f"invalid WDA window size: {value}")
        return width, height

    def _capture_screenshot(self) -> bytes:
        if self._blocker_probe_mode == "device_service_guard":
            return self._capture_device_screenshot()
        response = self._client.session_request("/screenshot", timeout_seconds=self._timeout)
        value = response.get("value")
        if not isinstance(value, str) or not value:
            raise WdaRequestError("WDA screenshot response is missing base64 data")
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as exc:
            raise WdaRequestError("WDA screenshot response is invalid base64") from exc

    def capture_screenshot(self) -> bytes:
        """Return a passive PNG snapshot for run evidence."""
        return self._capture_screenshot()

    def background_checkpoint(self) -> dict[str, Any]:
        """Read the current native boundary without activating any application."""
        if not self._udid:
            raise ValueError("iOS background snapshot requires an explicit UDID")
        def query(args: tuple[str, ...]) -> Any:
            result = self._executor.run(args, timeout_seconds=min(self._timeout, 10.0))
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "go-ios snapshot query failed")
            return json.loads(result.stdout)
        devices = query(("ios", "list", "--details"))
        processes = query(("ios", "ps", "--apps", "--udid", self._udid))
        status = self._client.request("/status", timeout_seconds=5.0)
        foreground = self._client.session_request("/wda/activeAppInfo", timeout_seconds=8.0).get("value")
        self._client.session_request("/appium/settings", {"settings": {"snapshotMaxDepth": 50}}, timeout_seconds=5.0)
        source = self._client.session_request("/source", timeout_seconds=15.0).get("value")
        return {"epoch": time.time(), "udid": self._udid, "devices": devices,
                "processes": processes, "wda_status": status, "foreground": foreground,
                "source": source, "media_evidence_scope": "current_operator_observation"}

    def _target_process_running(self) -> bool:
        if self._process_probe is not None:
            return bool(self._process_probe())
        result = self._executor.run(
            ("ios", "ps", "--apps", "--udid", self._udid),
            timeout_seconds=min(self._timeout, 10.0),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "go-ios process query failed")
        payload = json.loads(result.stdout)
        if not isinstance(payload, list):
            raise RuntimeError("go-ios process query did not return a list")
        return any(
            isinstance(row, dict)
            and row.get("IsApplication") is True
            and str(row.get("Name") or "") == self._process_name
            for row in payload
        )

    def _capture_device_screenshot(self) -> bytes:
        if self._device_screenshot is not None:
            return self._device_screenshot()
        handle = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        path = Path(handle.name)
        handle.close()
        try:
            result = self._executor.run(
                ("ios", "screenshot", "--udid", self._udid, "--output", str(path)),
                timeout_seconds=min(self._timeout, 15.0),
            )
            if result.returncode != 0 or not path.is_file():
                raise RuntimeError(result.stderr.strip() or "go-ios screenshot failed")
            data = path.read_bytes()
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                raise RuntimeError("go-ios screenshot did not produce a PNG")
            return data
        finally:
            path.unlink(missing_ok=True)
