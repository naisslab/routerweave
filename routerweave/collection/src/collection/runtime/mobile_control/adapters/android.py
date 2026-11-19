"""Android capability adapter backed only by ADB primitives."""

from __future__ import annotations

import re
import subprocess
import time
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

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
from ..platform import CommandResult
from ..semantic_candidate import select_semantic_candidate
from ..status import ActionMethod, CommandStatus, ObservationLevel, Platform
from ..visual_template import match_visual_template
from .process import ProcessExecutor, ProcessResult, SubprocessExecutor
from .android_view import focused_activity_views
from .android_native import build_native_helper


_APP_ID = re.compile(r"^[A-Za-z0-9_.]+$")
_ACTIVITY = re.compile(r"^[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+$")
_BOUNDS = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")
_SYSTEM_DIALOG_PACKAGES = {
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.systemui",
}


def _control(name: str, method: ActionMethod, description: str) -> CapabilityDescriptor:
    return CapabilityDescriptor(name, CapabilityKind.CONTROL, method, description)


def _observe(name: str, description: str) -> CapabilityDescriptor:
    return CapabilityDescriptor(name, CapabilityKind.OBSERVATION, None, description)


ANDROID_CAPABILITIES = CapabilityCatalog(
    (
        _control("app.launch", ActionMethod.DIRECT, "Launch an app by package or explicit activity"),
        _control("app.terminate", ActionMethod.DIRECT, "Force-stop the target app"),
        _control(
            "app.cache.clear",
            ActionMethod.DIRECT,
            "Clear allowlisted external media-cache paths and verify they are empty",
        ),
        _control("app.open_url", ActionMethod.DIRECT, "Open a URI through Android intent resolution"),
        _control("media.ensure_playing", ActionMethod.DIRECT, "Set media playback through an ADB injection backend"),
        _control("media.ensure_paused", ActionMethod.DIRECT, "Pause media playback through an ADB injection backend"),
        _control("media.next", ActionMethod.DIRECT, "Advance media through an ADB injection backend"),
        _control("navigation.back", ActionMethod.DIRECT, "Inject Android BACK"),
        _control("device.orientation.set", ActionMethod.DIRECT, "Lock the display to portrait or landscape"),
        _control("element.activate", ActionMethod.ELEMENT, "Activate the current bounds of a semantic UI node"),
        _control(
            "element.activate.query",
            ActionMethod.ELEMENT,
            "Resolve one exact semantic node and activate it in one adapter transaction",
        ),
        _control(
            "element.activate.hierarchy_query",
            ActionMethod.ELEMENT,
            "Resolve one exact semantic node from an adapter-owned hierarchy file and activate it",
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
        _control(
            "element.activate.visual_template.repeat",
            ActionMethod.ELEMENT,
            "Activate a recurring local visual component until it remains absent",
        ),
        _control(
            "element.activate.visual_template.any",
            ActionMethod.ELEMENT,
            "Resolve one known visual state and activate only an allowlisted match",
        ),
        _control(
            "element.activate.visual_template.sequence",
            ActionMethod.ELEMENT,
            "Advance through bounded known visual states until a terminal state appears",
        ),
        _control(
            "element.activate.visual_color_component",
            ActionMethod.ELEMENT,
            "Activate one bounded current component derived from a local color mask",
        ),
        _control("screen.tap.relative", ActionMethod.GESTURE, "Tap a screen-relative point"),
        _control("screen.swipe.relative", ActionMethod.GESTURE, "Swipe using screen-relative direction ratios"),
        _control(
            "screen.swipe.relative.if_visual_ready",
            ActionMethod.GESTURE,
            "Swipe from a HUD control only when a bounded local readiness probe is active",
        ),
        _control(
            "system.recents.clear",
            ActionMethod.GESTURE,
            "Open Android recents, dismiss every task card for the current orientation, and verify it is empty",
        ),
        _observe("observation.fast", "Read foreground app and media session state"),
        _observe("observation.audio", "Read target-app AudioTrack playback state"),
        _observe("observation.blocker", "Read the current hierarchy for blocking UI"),
        _observe("observation.frame", "Fingerprint one local frame without a visual Agent"),
        _observe("observation.motion", "Measure local frame motion without a visual Agent"),
        _observe("observation.structured", "Read the Android UIAutomator hierarchy"),
        _observe("observation.viewport", "Read the active logical viewport and rotation lock"),
        _observe("observation.element.query", "Read a resource marker from the focused Activity view tree"),
        _observe(
            "observation.element.hierarchy_query",
            "Read current text for allowlisted resources through an adapter-owned UI hierarchy file",
        ),
        _observe(
            "observation.visual.template",
            "Resolve a semantic element by bounded local template matching",
        ),
        _observe(
            "observation.visual.template.any",
            "Resolve any known semantic visual state from one local frame",
        ),
        _observe(
            "observation.visual.region_ready",
            "Read whether a bounded current HUD region is visually active",
        ),
        _observe(
            "observation.visual.color_components",
            "Resolve bounded current components from a local color mask",
        ),
    )
)


class AndroidAdbAdapter:
    def __init__(
        self,
        serial: str,
        app_id: str,
        *,
        adb_path: str = "adb",
        executor: ProcessExecutor | None = None,
        command_timeout_seconds: float = 15.0,
        motion_config: FrameMotionConfig | None = None,
        ui_hierarchy_backend: str = "uiautomator",
        ui_idle_fallback_backend: str = "",
        motion_player_resource_id: str = "",
        ui_snapshot_timeout_seconds: int = 8,
        ui_include_not_important_views: bool = True,
    ) -> None:
        self.serial = serial
        self.app_id = self._valid_app_id(app_id)
        self.adb_path = adb_path
        self._executor = executor or SubprocessExecutor()
        self._timeout = command_timeout_seconds
        self._generation = 0
        self._app_uid: str | None = None
        self._motion_config = motion_config or FrameMotionConfig()
        if motion_player_resource_id and not re.fullmatch(
            re.escape(self.app_id) + r":id/[A-Za-z0-9_]+", motion_player_resource_id
        ):
            raise ValueError("motion player resource must be target-app scoped")
        self._motion_player_resource_id = motion_player_resource_id
        if ui_hierarchy_backend not in {"uiautomator", "current_accessibility"}:
            raise ValueError("Unknown Android UI hierarchy backend")
        self._ui_hierarchy_backend = ui_hierarchy_backend
        if ui_idle_fallback_backend not in {"", "current_accessibility"}:
            raise ValueError("Unknown Android idle hierarchy fallback")
        if ui_idle_fallback_backend and ui_hierarchy_backend != "uiautomator":
            raise ValueError("Idle hierarchy fallback requires the uiautomator primary reader")
        self._ui_idle_fallback_backend = ui_idle_fallback_backend
        if type(ui_snapshot_timeout_seconds) is not int or not 8 <= ui_snapshot_timeout_seconds <= 16:
            raise ValueError("native snapshot deadline must be an integer from 8 to 16 seconds")
        self._ui_snapshot_timeout_seconds = ui_snapshot_timeout_seconds
        if type(ui_include_not_important_views) is not bool:
            raise ValueError("native important-view selection must be boolean")
        self._ui_include_not_important_views = ui_include_not_important_views
        self._native_helper_path: str | None = None

    @property
    def platform(self) -> Platform:
        return Platform.ANDROID

    @property
    def capabilities(self) -> CapabilityCatalog:
        return ANDROID_CAPABILITIES

    def probe_capabilities(self) -> CapabilityReport:
        started = time.monotonic()
        try:
            state = self._adb(("get-state",), timeout=5.0)
            ready = state.returncode == 0 and "device" in state.stdout
            detail = state.stdout.strip() or state.stderr.strip() or f"exit {state.returncode}"
        except Exception as exc:
            ready = False
            detail = f"{type(exc).__name__}: {exc}"
        transport_duration = time.monotonic() - started
        if not ready:
            return CapabilityReport(
                f"adb:{self.serial}",
                tuple(
                    CapabilityProbe(
                        descriptor.name,
                        CapabilityHealth.UNAVAILABLE,
                        f"ADB transport unavailable: {detail}",
                        transport_duration,
                    )
                    for descriptor in self.capabilities.descriptors
                ),
            )

        structured_started = time.monotonic()
        try:
            observation = self.observe(ObservationLevel.STRUCTURED, "capability-probe")
            structured_errors = tuple(
                error for error in observation.errors if error.startswith("structured:")
            )
            if not observation.elements:
                structured_health = CapabilityHealth.UNAVAILABLE
            elif structured_errors:
                structured_health = CapabilityHealth.DEGRADED
            else:
                structured_health = CapabilityHealth.AVAILABLE
            fast_health = (
                CapabilityHealth.AVAILABLE
                if observation.app_id is not None
                else CapabilityHealth.UNAVAILABLE
            )
            structured_detail = (
                f"{len(observation.elements)} UI nodes"
                if observation.elements
                else "; ".join(observation.errors) or "UI hierarchy was empty"
            )
        except Exception as exc:
            structured_health = CapabilityHealth.UNAVAILABLE
            fast_health = CapabilityHealth.UNAVAILABLE
            structured_detail = f"{type(exc).__name__}: {exc}"
        structured_duration = time.monotonic() - structured_started

        probes: list[CapabilityProbe] = []
        for descriptor in self.capabilities.descriptors:
            if descriptor.name == "observation.structured":
                probes.append(
                    CapabilityProbe(
                        descriptor.name,
                        structured_health,
                        structured_detail,
                        structured_duration,
                    )
                )
            elif descriptor.name == "observation.blocker":
                probes.append(
                    CapabilityProbe(
                        descriptor.name,
                        fast_health,
                        "blocker scan uses the foreground system-dialog package",
                        transport_duration,
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
                            "ADB observation transport ready"
                            if descriptor.kind is CapabilityKind.OBSERVATION
                            else "ADB transport ready; mutating action intentionally not invoked"
                        ),
                        transport_duration,
                        {"transport": detail},
                    )
                )
        return CapabilityReport(f"adb:{self.serial}", tuple(probes))

    def observe(
        self,
        level: ObservationLevel,
        reason: str,
        signals: frozenset[str] = frozenset(),
    ) -> Observation:
        errors: list[str] = []
        foreground: str | None = None
        foreground_activity: str | None = None
        media: dict[str, Any] = {}
        audio_state: dict[str, Any] = {}
        hierarchy_state: dict[str, Any] = {}
        elements: tuple[ElementNode, ...] = ()
        requested = signals or frozenset(
            ("foreground", "media", "ui")
            if level in (ObservationLevel.STRUCTURED, ObservationLevel.VISUAL)
            else ("foreground", "media")
        )
        # Read slow UI evidence first, then obtain fresh foreground/media state.
        if "ui" in requested:
            try:
                elements, hierarchy_state = self._read_element_hierarchy({})
            except Exception as exc:
                errors.append(f"structured: {type(exc).__name__}: {exc}")
        foreground_source: str | None = None
        if "foreground" in requested or "blocker" in requested:
            try:
                window = self._shell(("dumpsys", "window"), timeout=8.0)
                if window.returncode == 0:
                    foreground, foreground_activity = self._parse_foreground_component(
                        window.stdout
                    )
                    foreground_source = "dumpsys window" if foreground else None
                else:
                    errors.append(f"foreground: {window.stderr.strip() or window.returncode}")
                if foreground is None:
                    activity = self._shell(("dumpsys", "activity", "activities"), timeout=8.0)
                    if activity.returncode == 0:
                        foreground, foreground_activity = self._parse_foreground_component(
                            activity.stdout
                        )
                        foreground_source = "dumpsys activity activities" if foreground else None
                    else:
                        errors.append(
                            f"foreground fallback: {activity.stderr.strip() or activity.returncode}"
                        )
                if foreground is None:
                    errors.append("foreground: no resumed package found")
            except Exception as exc:
                errors.append(f"foreground: {type(exc).__name__}: {exc}")
        if "blocker" in requested and foreground is None:
            errors.append("blocker: foreground package is unavailable")
        if "media" in requested:
            try:
                session = self._shell(("dumpsys", "media_session"), timeout=10.0)
                if session.returncode == 0:
                    media = self._parse_media(session.stdout, self.app_id)
                else:
                    errors.append(f"media: {session.stderr.strip() or session.returncode}")
            except Exception as exc:
                errors.append(f"media: {type(exc).__name__}: {exc}")
        if "audio" in requested:
            try:
                uid = self._get_app_uid()
                audio = self._shell(("dumpsys", "audio"), timeout=10.0)
                if audio.returncode != 0:
                    raise RuntimeError(audio.stderr.strip() or audio.returncode)
                audio_state = self._parse_audio(audio.stdout, uid)
            except Exception as exc:
                errors.append(f"audio: {type(exc).__name__}: {exc}")
        if "motion" in requested:
            try:
                bounds = None
                if self._motion_player_resource_id:
                    nodes, _ = self._read_element_hierarchy({})
                    players = [node for node in nodes if node.visible and node.enabled
                               and node.resource_id == self._motion_player_resource_id]
                    if len(players) != 1 or players[0].bounds is None:
                        raise ValueError("native motion player is missing or ambiguous")
                    bounds = players[0].bounds
                motion = sample_frame_motion(
                    self._capture_screenshot,
                    time.sleep,
                    self._motion_config,
                    crop_bounds=bounds,
                )
                state_motion = motion.as_state()
            except Exception as exc:
                state_motion = {}
                errors.append(f"motion: {type(exc).__name__}: {exc}")
        else:
            state_motion = {}
        if "frame" in requested:
            try:
                state_visual = {
                    "frame_fingerprint": frame_fingerprint(self._capture_screenshot())
                }
            except Exception as exc:
                state_visual = {}
                errors.append(f"frame: {type(exc).__name__}: {exc}")
        else:
            state_visual = {}
        if "blocker" in requested and "ui" not in requested and foreground in _SYSTEM_DIALOG_PACKAGES:
            elements = (
                ElementNode(
                    "android:system-dialog",
                    role="dialog",
                    text="system dialog foreground",
                    attributes={"package": foreground, "probe": "foreground-package"},
                ),
            )
        self._generation += 1
        state: dict[str, Any] = {
            "device": {
                "foreground_app": foreground,
                "foreground_activity": foreground_activity,
                "foreground_activity_class": self._activity_class(foreground_activity),
                "foreground_source": foreground_source,
            }
        }
        if "viewport" in requested:
            try:
                width, height = self._read_logical_viewport()
                rotation = self._shell(("wm", "user-rotation"), timeout=5.0)
                fixed = self._shell(("wm", "fixed-to-user-rotation"), timeout=5.0)
                state["device"].update({
                    "viewport": {"width": width, "height": height},
                    "orientation": "landscape" if width > height else "portrait",
                    "orientation_locked": (
                        rotation.returncode == 0
                        and rotation.stdout.strip().startswith("lock")
                        and fixed.returncode == 0
                        and fixed.stdout.strip() == "enabled"
                    ),
                })
            except Exception as exc:
                errors.append(f"viewport: {type(exc).__name__}: {exc}")
        if media:
            state["media"] = media
        if hierarchy_state:
            state["ui"] = hierarchy_state
        if audio_state:
            state["audio"] = audio_state
        if state_motion:
            state["motion"] = state_motion
        if state_visual:
            state["visual"] = state_visual
        return Observation(
            self.platform,
            time.time(),
            foreground,
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
        """Read native resource evidence without waiting for accessibility idle."""
        self._generation += 1
        if capability == "observation.element.query":
            resource_id = str(parameters.get("resource_id") or "")
            class_name = str(parameters.get("class_name") or "")
            valid_identity = (bool(resource_id) != bool(class_name)) and (
                re.fullmatch(re.escape(self.app_id) + r":id/[A-Za-z0-9_]+", resource_id) if resource_id
                else re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", class_name))
            if not valid_identity:
                return Observation(self.platform, time.time(), errors=("native_query: invalid target resource",))
            try:
                result = self._shell(("dumpsys", "activity", self.app_id), timeout=6.0)
                if result.returncode != 0:
                    raise ValueError(result.stderr.strip() or "Activity dump failed")
                nodes = focused_activity_views(result.stdout, self.app_id, include_class_nodes=bool(class_name))
                matches = tuple(node for node in nodes if (
                    node.resource_id == resource_id if resource_id else node.attributes.get("class") == class_name))
                return Observation(
                    self.platform, time.time(), self.app_id, matches,
                    {"mobile_control": {"match_count": len(matches), "source": "focused_activity_view"}},
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform, time.time(), errors=(f"native_query: {type(exc).__name__}: {exc}",),
                    generation=self._generation,
                )
        if capability == "observation.element.hierarchy_query":
            raw_resource_ids = parameters.get("resource_ids", ())
            resource_ids = tuple(
                str(value).strip()
                for value in (
                    raw_resource_ids
                    if isinstance(raw_resource_ids, (list, tuple))
                    else (raw_resource_ids,)
                )
                if str(value).strip()
            )
            resource_pattern = re.compile(
                re.escape(self.app_id) + r":id/[A-Za-z0-9_]+"
            )
            if not resource_ids or any(
                resource_pattern.fullmatch(resource_id) is None
                for resource_id in resource_ids
            ):
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("hierarchy_query: invalid target resources",),
                    generation=self._generation,
                )
            try:
                nodes, hierarchy_evidence = self._read_element_hierarchy_file(parameters)
                wanted = frozenset(resource_ids)
                matches = tuple(
                    node for node in nodes if node.resource_id in wanted
                )
                return Observation(
                    self.platform,
                    time.time(),
                    self.app_id,
                    matches,
                    {
                        "mobile_control": {
                            "match_count": len(matches),
                            "source": "uiautomator_device_file",
                            **hierarchy_evidence,
                        }
                    },
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=(
                        f"hierarchy_query: {type(exc).__name__}: {exc}",
                    ),
                    generation=self._generation,
                )
        if capability == "observation.visual.color_components":
            resource_id = str(parameters.get("resource_id") or "").strip()
            if not re.fullmatch(r"visual:[A-Za-z0-9_.-]+", resource_id):
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("visual_color_components: invalid semantic resource id",),
                    generation=self._generation,
                )
            try:
                components = self._visual_color_components(
                    self._capture_screenshot(), parameters
                )
                matches = tuple(
                    ElementNode(
                        handle=f"{resource_id}:{self._generation}:{index}",
                        role="visual_component",
                        resource_id=resource_id,
                        visible=True,
                        enabled=True,
                        clickable=bool(parameters.get("clickable", True)),
                        attributes={
                            "source": "local_visual_color_components",
                            "fill_ratio": component["fill_ratio"],
                        },
                        bounds=component["bounds"],
                    )
                    for index, component in enumerate(components)
                )
                return Observation(
                    self.platform,
                    time.time(),
                    self.app_id,
                    matches,
                    {
                        "mobile_control": {
                            "match_count": len(matches),
                            "source": "local_visual_color_components",
                        }
                    },
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=(
                        f"visual_color_components: {type(exc).__name__}: {exc}",
                    ),
                    generation=self._generation,
                )
        if capability == "observation.visual.region_ready":
            resource_id = str(parameters.get("resource_id") or "").strip()
            if not re.fullmatch(r"visual:[A-Za-z0-9_.-]+", resource_id):
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("visual_region_ready: invalid semantic resource id",),
                    generation=self._generation,
                )
            try:
                readiness = self._visual_region_readiness(
                    self._capture_screenshot(), parameters
                )
                matches = (
                    (
                        ElementNode(
                            handle=f"{resource_id}:{self._generation}",
                            role="visual_state",
                            resource_id=resource_id,
                            visible=True,
                            enabled=True,
                            clickable=False,
                            attributes={
                                "source": "local_visual_region",
                                "ready_fraction": readiness["ready_fraction"],
                            },
                            bounds=readiness["bounds"],
                        ),
                    )
                    if readiness["ready"]
                    else ()
                )
                return Observation(
                    self.platform,
                    time.time(),
                    self.app_id,
                    matches,
                    {
                        "mobile_control": {
                            "match_count": len(matches),
                            "source": "local_visual_region",
                            **readiness,
                        }
                    },
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=(
                        f"visual_region_ready: {type(exc).__name__}: {exc}",
                    ),
                    generation=self._generation,
                )
        if capability == "observation.visual.template":
            resource_id = str(parameters.get("resource_id") or "").strip()
            if not re.fullmatch(r"visual:[A-Za-z0-9_.-]+", resource_id):
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("visual_template: invalid semantic resource id",),
                    generation=self._generation,
                )
            try:
                match = match_visual_template(self._capture_screenshot(), parameters)
                matches = (
                    (
                        ElementNode(
                            handle=f"{resource_id}:{self._generation}",
                            role="visual_component",
                            resource_id=resource_id,
                            visible=True,
                            enabled=True,
                            clickable=bool(parameters.get("clickable", True)),
                            attributes={
                                "source": "local_visual_template",
                                "match_score": match.score,
                            },
                            bounds=match.bounds,
                        ),
                    )
                    if match is not None
                    else ()
                )
                return Observation(
                    self.platform,
                    time.time(),
                    self.app_id,
                    matches,
                    {
                        "mobile_control": {
                            "match_count": len(matches),
                            "source": "local_visual_template",
                            "match_score": match.score if match is not None else None,
                        }
                    },
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=(f"visual_template: {type(exc).__name__}: {exc}",),
                    generation=self._generation,
                )
        if capability == "observation.visual.template.any":
            resource_id = str(parameters.get("resource_id") or "").strip()
            templates = parameters.get("templates")
            if not re.fullmatch(r"visual:[A-Za-z0-9_.-]+", resource_id):
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("visual_template_any: invalid semantic resource id",),
                    generation=self._generation,
                )
            if not isinstance(templates, (list, tuple)) or not templates:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=("visual_template_any: templates are required",),
                    generation=self._generation,
                )
            try:
                frame = self._capture_screenshot()
                found = []
                for index, template_parameters in enumerate(templates):
                    if not isinstance(template_parameters, Mapping):
                        raise ValueError("template entry must be a mapping")
                    match = match_visual_template(frame, template_parameters)
                    if match is not None:
                        found.append(
                            (str(template_parameters.get("name") or index), match)
                        )
                if found:
                    found = [max(found, key=lambda item: item[1].score)]
                matches = tuple(
                    ElementNode(
                        handle=f"{resource_id}:{self._generation}:{index}",
                        role="visual_component",
                        resource_id=resource_id,
                        visible=True,
                        enabled=True,
                        clickable=False,
                        attributes={
                            "source": "local_visual_template_any",
                            "match_name": name,
                            "match_score": match.score,
                        },
                        bounds=match.bounds,
                    )
                    for index, (name, match) in enumerate(found)
                )
                return Observation(
                    self.platform,
                    time.time(),
                    self.app_id,
                    matches,
                    {
                        "mobile_control": {
                            "match_count": len(matches),
                            "source": "local_visual_template_any",
                            "match_names": tuple(name for name, _ in found),
                        }
                    },
                    generation=self._generation,
                )
            except Exception as exc:
                return Observation(
                    self.platform,
                    time.time(),
                    errors=(f"visual_template_any: {type(exc).__name__}: {exc}",),
                    generation=self._generation,
                )
        return Observation(
            self.platform,
            time.time(),
            errors=(f"native_query: unsupported capability {capability!r}",),
            generation=self._generation,
        )

    def running_app_processes(self, app_ids: Sequence[str]) -> dict[str, list[str]]:
        """Read all process names, including package-scoped child processes."""
        packages = [self._valid_app_id(app_id) for app_id in app_ids]
        result = self._shell(("ps", "-A", "-o", "NAME"), timeout=10.0)
        names = result.stdout.splitlines()
        if result.returncode != 0 or len(names) < 2 or names[0].strip() != "NAME":
            raise RuntimeError("Cannot independently read Android process names")
        return {package: [name.strip() for name in names[1:]
                          if name.strip() == package or name.strip().startswith(package + ":")]
                for package in packages}

    def execute_direct(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        app_id = self._valid_app_id(str(parameters.get("app_id") or self.app_id))
        if capability == "app.launch":
            activity = str(parameters.get("activity") or "").strip()
            if activity:
                if not _ACTIVITY.fullmatch(activity):
                    return self._rejected(ActionMethod.DIRECT, capability, "invalid activity")
                return self._shell_command(
                    capability,
                    ("am", "start", "-n", activity),
                    ActionMethod.DIRECT,
                )
            return self._adb_command(
                capability,
                ("shell", "monkey", "-p", app_id, "-c", "android.intent.category.LAUNCHER", "1"),
                ActionMethod.DIRECT,
            )
        if capability == "app.terminate":
            return self._shell_command(capability, ("am", "force-stop", app_id), ActionMethod.DIRECT)
        if capability == "app.cache.clear":
            return self._clear_app_cache(app_id, parameters)
        if capability == "app.open_url":
            url = str(parameters.get("url") or "").strip()
            if not url:
                return self._rejected(ActionMethod.DIRECT, capability, "url is required")
            return self._shell_command(
                capability,
                ("am", "start", "-a", "android.intent.action.VIEW", "-d", url),
                ActionMethod.DIRECT,
            )
        if capability == "media.ensure_playing":
            return self._media_command(capability, "play", "126", parameters)
        if capability == "media.ensure_paused":
            return self._media_command(capability, "pause", "127", parameters)
        if capability == "media.next":
            return self._media_command(capability, "next", "87", parameters)
        if capability == "navigation.back":
            return self._shell_command(capability, ("input", "keyevent", "4"), ActionMethod.DIRECT)
        if capability == "device.orientation.set":
            orientation = str(parameters.get("orientation") or "").casefold()
            if orientation not in {"portrait", "landscape"}:
                return self._rejected(ActionMethod.DIRECT, capability, "unsupported orientation")
            size = self._shell(("wm", "size"), timeout=5.0)
            match = re.search(r"Physical size:\s*(\d+)x(\d+)", size.stdout)
            if size.returncode != 0 or not match:
                return self._rejected(ActionMethod.DIRECT, capability, "natural display size unavailable")
            natural_portrait = int(match.group(1)) < int(match.group(2))
            rotation = "0" if natural_portrait == (orientation == "portrait") else "1"
            previous = {
                "user_rotation": self._shell(("wm", "user-rotation"), timeout=5.0).stdout.strip(),
                "fixed_to_user_rotation": self._shell(("wm", "fixed-to-user-rotation"), timeout=5.0).stdout.strip(),
            }
            for arguments in (
                ("wm", "user-rotation", "lock", rotation),
                ("wm", "fixed-to-user-rotation", "enabled"),
            ):
                result = self._shell_command(
                    capability, arguments, ActionMethod.DIRECT,
                    {"previous_rotation_policy": previous, "requested_orientation": orientation},
                )
                if result.status is not CommandStatus.ACCEPTED:
                    return result
            return result
        return CommandResult(
            CommandStatus.UNSUPPORTED,
            ActionMethod.DIRECT,
            capability,
            f"unknown direct capability {capability!r}",
        )

    def _clear_app_cache(
        self,
        app_id: str,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        capability = "app.cache.clear"
        installed = self._shell(("pm", "path", app_id), timeout=10.0)
        if installed.returncode != 0 or not installed.stdout.strip().startswith("package:"):
            return self._rejected(
                ActionMethod.DIRECT,
                capability,
                f"target package is not installed: {installed.stderr.strip() or installed.stdout.strip()}",
            )
        raw_paths = parameters.get("relative_paths")
        if not isinstance(raw_paths, (list, tuple)) or not raw_paths:
            return self._rejected(
                ActionMethod.DIRECT,
                capability,
                "relative_paths must contain at least one allowlisted cache directory",
            )
        root = f"/sdcard/Android/data/{app_id}"
        targets: list[str] = []
        for raw in raw_paths:
            relative = PurePosixPath(str(raw))
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                return self._rejected(
                    ActionMethod.DIRECT,
                    capability,
                    f"unsafe cache path {raw!r}",
                )
            targets.append(f"{root}/{relative.as_posix()}")

        stopped = self._shell(("am", "force-stop", app_id), timeout=10.0)
        running = self._shell(("pidof", app_id), timeout=5.0)
        if stopped.returncode != 0 or running.stdout.strip():
            return self._rejected(
                ActionMethod.DIRECT,
                capability,
                "target app could not be independently verified as stopped",
            )

        before = {target: self._external_path_size_bytes(target) for target in targets}
        deletions: list[dict[str, Any]] = []
        for target in targets:
            deleted = self._shell(
                ("find", target, "-mindepth", "1", "-depth", "-delete"),
                timeout=30.0,
            )
            deletions.append(
                {
                    "path": target,
                    "returncode": deleted.returncode,
                    "stdout": deleted.stdout.strip()[-1000:],
                    "stderr": deleted.stderr.strip()[-1000:],
                }
            )
            if deleted.returncode != 0:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.DIRECT,
                    capability,
                    f"failed to clear allowlisted cache path {target}",
                    {
                        "method": "external_media_cache_paths",
                        "package": app_id,
                        "targets": targets,
                        "before_path_bytes": before,
                        "deletions": deletions,
                        "postcondition_verified": False,
                    },
                )

        after = {target: self._external_path_size_bytes(target) for target in targets}
        remaining = {}
        for target in targets:
            probe = self._shell(
                ("find", target, "-mindepth", "1", "-print", "-quit"),
                timeout=10.0,
            )
            remaining[target] = probe.stdout.strip()
        verified = all(not value for value in remaining.values())
        evidence = {
            "method": "external_media_cache_paths",
            "package": app_id,
            "targets": targets,
            "before_path_bytes": before,
            "after_path_bytes": after,
            "before_total_cache_bytes": sum(before.values()),
            "after_total_cache_bytes": sum(after.values()),
            "remaining_entries": remaining,
            "deletions": deletions,
            "app_stopped_verified": True,
            "postcondition_verified": verified,
        }
        return CommandResult(
            CommandStatus.ACCEPTED if verified else CommandStatus.REJECTED,
            ActionMethod.DIRECT,
            capability,
            (
                f"verified {len(targets)} allowlisted media-cache path(s) empty"
                if verified
                else "one or more allowlisted media-cache paths remain non-empty"
            ),
            evidence,
        )

    def _external_path_size_bytes(self, path: str) -> int:
        result = self._shell(("du", "-sk", path), timeout=20.0)
        if result.returncode != 0:
            return 0
        match = re.match(r"\s*(\d+)", result.stdout)
        return int(match.group(1)) * 1024 if match else 0

    def _media_command(
        self,
        capability: str,
        action: str,
        keycode: str,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        injection = str(parameters.get("injection") or "keyevent").strip().casefold()
        if injection in {"session", "media_session", "media-session"}:
            return self._shell_command(
                capability,
                ("cmd", "media_session", "dispatch", action),
                ActionMethod.DIRECT,
            )
        if injection == "keyevent":
            return self._shell_command(
                capability,
                ("input", "keyevent", keycode),
                ActionMethod.DIRECT,
            )
        return self._rejected(
            ActionMethod.DIRECT,
            capability,
            f"unsupported media injection backend {injection!r}",
        )

    def execute_element(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        if capability == "element.activate.visual_color_component":
            try:
                components = self._visual_color_components(
                    self._capture_screenshot(), parameters
                )
            except Exception as exc:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"visual color query failed: {type(exc).__name__}: {exc}",
                )
            if not components:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    "no bounded visual color component matched",
                )
            selection = str(parameters.get("selection") or "leftmost").casefold()
            if selection == "leftmost":
                selected = min(components, key=lambda item: item["bounds"][0])
            elif selection == "rightmost":
                selected = max(components, key=lambda item: item["bounds"][2])
            else:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"unsupported visual color selection {selection!r}",
                )
            node = ElementNode(
                handle=f"visual-color:{selection}",
                role="visual_component",
                resource_id=str(parameters.get("resource_id") or ""),
                clickable=True,
                bounds=selected["bounds"],
            )
            result = self.activate_element(node, parameters)
            return CommandResult(
                result.status,
                ActionMethod.ELEMENT,
                capability,
                result.detail,
                {
                    **dict(result.evidence),
                    "candidate_count": len(components),
                    "selection": selection,
                    "selected_bounds": selected["bounds"],
                },
            )
        if capability == "element.activate.visual_template.repeat":
            return self._activate_repeated_visual_template(parameters)
        if capability == "element.activate.visual_template.any":
            return self._activate_visual_template_any(parameters)
        if capability == "element.activate.visual_template.sequence":
            return self._activate_visual_template_sequence(parameters)
        if capability not in {
            "element.activate.query",
            "element.activate.hierarchy_query",
            "element.activate.candidate",
            "element.activate.media_card",
        }:
            return CommandResult(
                CommandStatus.UNSUPPORTED,
                ActionMethod.ELEMENT,
                capability,
                f"unknown element capability {capability!r}",
            )
        try:
            nodes, hierarchy_evidence = (
                self._read_element_hierarchy_file(parameters)
                if capability == "element.activate.hierarchy_query"
                else self._read_element_hierarchy(parameters)
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(CommandStatus.TIMEOUT, ActionMethod.ELEMENT, capability, str(exc))
        except Exception as exc:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.ELEMENT,
                capability,
                f"semantic query failed before activation: {type(exc).__name__}: {exc}",
            )
        if capability == "element.activate.candidate":
            try:
                selection = select_semantic_candidate(nodes, parameters)
            except (TypeError, ValueError, re.error) as exc:
                return self._rejected(ActionMethod.ELEMENT, capability, str(exc))
            if selection.selected is None:
                return self._rejected(ActionMethod.ELEMENT, capability, selection.detail)
            result = self.activate_element(selection.selected, parameters)
            return CommandResult(
                result.status,
                result.method,
                capability,
                result.detail,
                {
                    **dict(result.evidence),
                    **hierarchy_evidence,
                    "candidate_count": len(selection.candidates),
                    "selection_policy": str(
                        parameters.get("selection_policy") or "first_visible"
                    ),
                    "selection_seed": parameters.get("selection_seed"),
                    "selection_detail": selection.detail,
                    "selected_index": selection.candidates.index(selection.selected),
                    "eligible_candidates": [
                        {
                            "resource_id": candidate.resource_id,
                            "role": candidate.role,
                            "semantic_text": str(
                                candidate.attributes.get("descendant_text")
                                or candidate.semantic_text
                            ),
                            "bounds": candidate.bounds,
                        }
                        for candidate in selection.candidates
                    ],
                    "selected": {
                        "resource_id": selection.selected.resource_id,
                        "role": selection.selected.role,
                        "semantic_text": str(
                            selection.selected.attributes.get("descendant_text")
                            or selection.selected.semantic_text
                        ),
                        "bounds": selection.selected.bounds,
                    },
                },
            )
        if capability == "element.activate.media_card":
            try:
                selection = select_media_card(
                    nodes,
                    minimum_duration_seconds=int(
                        parameters.get("minimum_duration_seconds", 60)
                    ),
                    exclude_pattern=str(parameters.get("exclude_pattern") or ""),
                )
            except (TypeError, ValueError) as exc:
                return self._rejected(ActionMethod.ELEMENT, capability, str(exc))
            if selection.selected is None:
                return self._rejected(ActionMethod.ELEMENT, capability, selection.detail)
            result = self.activate_element(selection.selected, parameters)
            return CommandResult(
                result.status,
                result.method,
                capability,
                result.detail,
                {
                    **dict(result.evidence),
                    **hierarchy_evidence,
                    "candidate_count": selection.candidate_count,
                    "duration_seconds": selection.duration_seconds,
                    "selection_detail": selection.detail,
                    "anchor": (
                        {
                            "resource_id": selection.anchor.resource_id,
                            "role": selection.anchor.role,
                            "semantic_text": selection.anchor.semantic_text,
                        }
                        if selection.anchor is not None
                        else None
                    ),
                    "selected": {
                        "resource_id": selection.selected.resource_id,
                        "role": selection.selected.role,
                        "semantic_text": selection.selected.semantic_text,
                    },
                },
            )
        resource_id = str(parameters.get("resource_id") or "").strip()
        exact_text = str(parameters.get("exact_text") or "").strip()
        accessibility_id = str(parameters.get("accessibility_id") or "").strip()
        if not resource_id and not exact_text:
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "resource_id or exact_text is required",
            )
        def query_matches(current_nodes: Sequence[ElementNode]) -> list[ElementNode]:
            return [node for node in current_nodes if node.visible and node.enabled
                    and (not resource_id or node.resource_id == resource_id)
                    and (not exact_text or node.semantic_text == exact_text)
                    and (not accessibility_id or node.accessibility_id == accessibility_id)]

        matches = query_matches(nodes)
        reveal_resource = str(parameters.get("reveal_resource_id") or "").strip()
        reveal_evidence: dict[str, Any] = {}
        if not matches and reveal_resource:
            # Reveal controls once, then wait read-only for the exact state-labelled
            # control. Never toggle a visible control in the opposite state.
            prefix = f"{self.app_id}:id/"
            if not resource_id.startswith(prefix) or not reveal_resource.startswith(prefix):
                return self._rejected(ActionMethod.ELEMENT, capability, "reveal queries must be target-app scoped")
            if any(node.visible and node.resource_id == resource_id for node in nodes):
                return self._rejected(ActionMethod.ELEMENT, capability, "visible control has a different state label")
            surfaces = [node for node in nodes if node.visible and node.enabled
                        and node.resource_id == reveal_resource]
            if len(surfaces) != 1:
                return self._rejected(ActionMethod.ELEMENT, capability, "reveal surface is missing or ambiguous")
            revealed = self.activate_element(surfaces[0], parameters)
            if revealed.status is not CommandStatus.ACCEPTED:
                return revealed
            reveal_evidence = {"reveal": dict(revealed.evidence), "effect_started": True}
            deadline = time.monotonic() + 4.0
            try:
                while time.monotonic() < deadline:
                    nodes, hierarchy_evidence = self._read_element_hierarchy(parameters)
                    matches = query_matches(nodes)
                    if matches or any(node.visible and node.resource_id == resource_id for node in nodes):
                        break
                    time.sleep(0.1)
            except Exception as exc:
                return CommandResult(CommandStatus.UNKNOWN, ActionMethod.ELEMENT, capability,
                                     f"control observation after reveal failed: {type(exc).__name__}: {exc}",
                                     reveal_evidence)
        if len(matches) != 1:
            return CommandResult(CommandStatus.UNKNOWN if reveal_evidence else CommandStatus.REJECTED,
                                 ActionMethod.ELEMENT, capability,
                                 f"semantic query resolved {len(matches)} elements; expected exactly one",
                                 reveal_evidence)
        result = self.activate_element(matches[0], parameters)
        return CommandResult(
            result.status,
            result.method,
            capability,
            result.detail,
            {
                **dict(result.evidence),
                **hierarchy_evidence,
                **reveal_evidence,
                "query": {"resource_id": resource_id, "exact_text": exact_text,
                          "accessibility_id": accessibility_id},
            },
        )

    def _activate_repeated_visual_template(
        self,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        capability = "element.activate.visual_template.repeat"
        resource_id = str(parameters.get("resource_id") or "").strip()
        if not re.fullmatch(r"visual:[A-Za-z0-9_.-]+", resource_id):
            return self._rejected(ActionMethod.ELEMENT, capability, "invalid semantic resource id")
        maximum = max(1, min(10, int(parameters.get("max_activations", 6))))
        confirmations = max(1, min(5, int(parameters.get("absence_confirmations", 3))))
        interval = max(0.1, min(2.0, float(parameters.get("settle_seconds", 0.8))))
        template_entries = parameters.get("templates")
        if template_entries is not None and (
            not isinstance(template_entries, (list, tuple)) or not template_entries
        ):
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "templates must be a non-empty sequence",
            )
        activated = 0
        absent = 0
        scores: list[float] = []
        matched_names: list[str] = []
        while absent < confirmations:
            try:
                frame = self._capture_screenshot()
                if template_entries is None:
                    candidates = ((resource_id, match_visual_template(frame, parameters)),)
                else:
                    candidates = tuple(
                        (
                            str(entry.get("name") or index),
                            match_visual_template(frame, entry),
                        )
                        for index, entry in enumerate(template_entries)
                        if isinstance(entry, Mapping)
                    )
                    if len(candidates) != len(template_entries):
                        raise ValueError("template entry must be a mapping")
                name, match = max(
                    (
                        (candidate_name, candidate_match)
                        for candidate_name, candidate_match in candidates
                        if candidate_match is not None
                    ),
                    key=lambda item: item[1].score,
                    default=("", None),
                )
            except Exception as exc:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"visual template query failed: {type(exc).__name__}: {exc}",
                )
            if match is None:
                absent += 1
                time.sleep(interval)
                continue
            if activated >= maximum:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    f"visual component remained after {activated} bounded activations",
                    {
                        "activated": activated,
                        "scores": tuple(scores),
                        "matched_names": tuple(matched_names),
                    },
                )
            absent = 0
            scores.append(match.score)
            matched_names.append(name)
            node = ElementNode(
                handle=f"{resource_id}:repeat:{activated + 1}",
                role="visual_component",
                resource_id=resource_id,
                clickable=True,
                bounds=match.bounds,
            )
            result = self.activate_element(node, parameters)
            if result.status is not CommandStatus.ACCEPTED:
                return CommandResult(
                    result.status,
                    ActionMethod.ELEMENT,
                    capability,
                    result.detail,
                    {"activated": activated, "scores": tuple(scores)},
                )
            activated += 1
            time.sleep(interval)
        return CommandResult(
            CommandStatus.ACCEPTED,
            ActionMethod.ELEMENT,
            capability,
            "recurring visual component remained absent",
            {
                "activated": activated,
                "absence_confirmations": absent,
                "scores": tuple(scores),
                "matched_names": tuple(matched_names),
            },
        )

    def _activate_visual_template_any(
        self,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        capability = "element.activate.visual_template.any"
        templates = parameters.get("templates")
        if not isinstance(templates, (list, tuple)) or not templates:
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "templates are required",
            )
        activate_names = {
            str(value) for value in parameters.get("activate_names", ())
        }
        timeout = max(0.0, min(60.0, float(parameters.get("timeout_seconds", 45.0))))
        interval = max(0.1, min(2.0, float(parameters.get("poll_interval_seconds", 0.4))))
        deadline = time.monotonic() + timeout
        polls = 0
        while True:
            polls += 1
            try:
                frame = self._capture_screenshot()
                for index, template_parameters in enumerate(templates):
                    if not isinstance(template_parameters, Mapping):
                        raise ValueError("template entry must be a mapping")
                    match = match_visual_template(frame, template_parameters)
                    if match is None:
                        continue
                    name = str(template_parameters.get("name") or index)
                    evidence = {
                        "matched_name": name,
                        "match_score": match.score,
                        "polls": polls,
                    }
                    if name not in activate_names:
                        return CommandResult(
                            CommandStatus.ACCEPTED,
                            ActionMethod.ELEMENT,
                            capability,
                            "known visual state required no activation",
                            {**evidence, "activated": False},
                        )
                    node = ElementNode(
                        handle=f"visual:any:{name}:{polls}",
                        role="visual_component",
                        resource_id=f"visual:{name}",
                        clickable=True,
                        bounds=match.bounds,
                    )
                    result = self.activate_element(node, parameters)
                    return CommandResult(
                        result.status,
                        ActionMethod.ELEMENT,
                        capability,
                        result.detail,
                        {**dict(result.evidence), **evidence, "activated": True},
                    )
            except Exception as exc:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"visual state query failed: {type(exc).__name__}: {exc}",
                )
            if time.monotonic() >= deadline:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"no known visual state appeared after {polls} polls",
                )
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))

    def _activate_visual_template_sequence(
        self,
        parameters: Mapping[str, Any],
    ) -> CommandResult:
        capability = "element.activate.visual_template.sequence"
        templates = parameters.get("templates")
        if not isinstance(templates, (list, tuple)) or not templates:
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "templates are required",
            )
        if any(not isinstance(entry, Mapping) for entry in templates):
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "template entry must be a mapping",
            )
        activate_names = {
            str(value) for value in parameters.get("activate_names", ())
        }
        terminal_names = {
            str(value) for value in parameters.get("terminal_names", ())
        }
        terminal_all_names = {
            str(value) for value in parameters.get("terminal_all_names", ())
        }
        if not terminal_names and not terminal_all_names:
            return self._rejected(
                ActionMethod.ELEMENT,
                capability,
                "terminal_names or terminal_all_names are required",
            )
        maximum = max(1, min(30, int(parameters.get("max_activations", 16))))
        timeout = max(1.0, min(300.0, float(parameters.get("timeout_seconds", 180.0))))
        partial_terminal_grace = max(
            0.0,
            min(300.0, float(parameters.get("partial_terminal_grace_seconds", 0.0))),
        )
        reset_timeout_on_activation = bool(
            parameters.get("reset_timeout_on_activation", False)
        )
        interval = max(0.1, min(2.0, float(parameters.get("poll_interval_seconds", 0.4))))
        settle = max(0.1, min(3.0, float(parameters.get("settle_seconds", 0.8))))
        deadline = time.monotonic() + timeout
        polls = 0
        activated_names: list[str] = []
        scores: list[float] = []
        partial_terminal_grace_used = False
        partial_terminal_names: tuple[str, ...] = ()
        timeout_resets = 0
        while True:
            polls += 1
            try:
                frame = self._capture_screenshot()
                candidates = []
                for index, template_parameters in enumerate(templates):
                    match = match_visual_template(frame, template_parameters)
                    if match is None:
                        continue
                    candidates.append(
                        (str(template_parameters.get("name") or index), match)
                    )
                matched_names = {name for name, _ in candidates}
                if terminal_all_names and terminal_all_names.issubset(matched_names):
                    terminal_matches = [
                        match for name, match in candidates if name in terminal_all_names
                    ]
                    return CommandResult(
                        CommandStatus.ACCEPTED,
                        ActionMethod.ELEMENT,
                        capability,
                        "all terminal visual states appeared",
                        {
                            "terminal_names": tuple(sorted(terminal_all_names)),
                            "terminal_score": min(match.score for match in terminal_matches),
                            "polls": polls,
                            "activated": len(activated_names),
                            "activated_names": tuple(activated_names),
                            "scores": tuple(scores),
                            "partial_terminal_grace_used": partial_terminal_grace_used,
                            "partial_terminal_names": partial_terminal_names,
                            "timeout_resets": timeout_resets,
                        },
                    )
                candidates = [
                    candidate
                    for candidate in candidates
                    if candidate[0] not in terminal_all_names
                ]
                name, match = max(
                    candidates,
                    key=lambda item: item[1].score,
                    default=("", None),
                )
            except Exception as exc:
                return self._rejected(
                    ActionMethod.ELEMENT,
                    capability,
                    f"visual state sequence failed: {type(exc).__name__}: {exc}",
                )
            if match is not None:
                if name in terminal_names:
                    return CommandResult(
                        CommandStatus.ACCEPTED,
                        ActionMethod.ELEMENT,
                        capability,
                        "terminal visual state appeared",
                        {
                            "terminal_name": name,
                            "terminal_score": match.score,
                            "polls": polls,
                            "activated": len(activated_names),
                            "activated_names": tuple(activated_names),
                            "scores": tuple(scores),
                        },
                    )
                if name not in activate_names:
                    return self._rejected(
                        ActionMethod.ELEMENT,
                        capability,
                        f"known visual state {name!r} is not allowlisted for activation",
                    )
                if len(activated_names) >= maximum:
                    return self._rejected(
                        ActionMethod.ELEMENT,
                        capability,
                        f"visual state sequence exceeded {maximum} bounded activations",
                    )
                node = ElementNode(
                    handle=f"visual:sequence:{name}:{polls}",
                    role="visual_component",
                    resource_id=f"visual:{name}",
                    clickable=True,
                    bounds=match.bounds,
                )
                result = self.activate_element(node, parameters)
                if result.status is not CommandStatus.ACCEPTED:
                    return CommandResult(
                        result.status,
                        ActionMethod.ELEMENT,
                        capability,
                        result.detail,
                        {
                            "polls": polls,
                            "activated": len(activated_names),
                            "activated_names": tuple(activated_names),
                        },
                    )
                activated_names.append(name)
                scores.append(match.score)
                if reset_timeout_on_activation:
                    deadline = time.monotonic() + timeout
                    partial_terminal_grace_used = False
                    partial_terminal_names = ()
                    timeout_resets += 1
                time.sleep(settle)
                continue
            if time.monotonic() >= deadline:
                current_partial_names = tuple(
                    sorted(matched_names.intersection(terminal_all_names))
                )
                if (
                    current_partial_names
                    and partial_terminal_grace > 0.0
                    and not partial_terminal_grace_used
                ):
                    partial_terminal_grace_used = True
                    partial_terminal_names = current_partial_names
                    deadline = time.monotonic() + partial_terminal_grace
                    continue
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.ELEMENT,
                    capability,
                    f"terminal visual state did not appear after {polls} polls",
                    {
                        "polls": polls,
                        "activated": len(activated_names),
                        "activated_names": tuple(activated_names),
                        "scores": tuple(scores),
                        "partial_terminal_grace_used": partial_terminal_grace_used,
                        "partial_terminal_names": partial_terminal_names,
                        "timeout_resets": timeout_resets,
                    },
                )
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))

    def _read_element_hierarchy(
        self,
        parameters: Mapping[str, Any],
    ) -> tuple[tuple[ElementNode, ...], dict[str, Any]]:
        if self._ui_hierarchy_backend == "current_accessibility":
            return self._read_current_accessibility()
        attempts = max(1, min(4, int(parameters.get("hierarchy_read_attempts", 2))))
        compressed = bool(parameters.get("hierarchy_compressed", False))
        compressed_fallback = bool(parameters.get("hierarchy_compressed_fallback", True))
        settle_seconds = max(
            0.0,
            min(5.0, float(parameters.get("hierarchy_settle_seconds", 0.0))),
        )
        retry_delay_seconds = max(
            0.0,
            min(3.0, float(parameters.get("hierarchy_retry_delay_seconds", 0.5))),
        )
        read_timeout_seconds = max(
            1.0,
            min(
                self._timeout,
                float(parameters.get("hierarchy_read_timeout_seconds", self._timeout)),
            ),
        )
        if settle_seconds:
            time.sleep(settle_seconds)

        failures: list[str] = []
        for attempt in range(1, attempts + 1):
            read_compressed = compressed or (attempt > 1 and compressed_fallback)
            dump_args = ["exec-out", "uiautomator", "dump"]
            if read_compressed:
                dump_args.append("--compressed")
            dump_args.append("/dev/tty")
            try:
                hierarchy = self._adb(tuple(dump_args), timeout=read_timeout_seconds)
                if hierarchy.returncode != 0:
                    detail = hierarchy.stderr.strip() or f"exit {hierarchy.returncode}"
                    raise RuntimeError(detail)
                if "</hierarchy>" not in hierarchy.stdout:
                    detail = hierarchy.stderr.strip() or hierarchy.stdout.strip()
                    raise ValueError(
                        "uiautomator returned no hierarchy: " + (detail[:400] or "empty output")
                    )
                nodes = self._parse_hierarchy(hierarchy.stdout)
                if not nodes:
                    raise ValueError("structured UI hierarchy was empty")
                return nodes, {
                    "hierarchy_read_attempt": attempt,
                    "hierarchy_read_attempts": attempts,
                    "hierarchy_compressed": read_compressed,
                    "hierarchy_node_count": len(nodes),
                    "hierarchy_read_failures": tuple(failures),
                }
            except subprocess.TimeoutExpired:
                failures.append(f"attempt {attempt}: timeout after {read_timeout_seconds:.1f}s")
            except Exception as exc:
                failures.append(f"attempt {attempt}: {type(exc).__name__}: {exc}")
            if attempt < attempts and retry_delay_seconds:
                time.sleep(retry_delay_seconds)
        # Continuously updating video can keep UIAutomator from becoming idle.
        # An opt-in alternate read still returns a fresh complete hierarchy;
        # malformed output, timeouts and other errors never select this path.
        if self._ui_idle_fallback_backend and all(
            failure == f"attempt {index}: ValueError: uiautomator returned no hierarchy: "
            "ERROR: could not get idle state."
            for index, failure in enumerate(failures, 1)
        ):
            nodes, evidence = self._read_current_accessibility()
            return nodes, {**evidence, "hierarchy_fallback_from": "uiautomator_idle",
                           "hierarchy_primary_read_failures": tuple(failures)}
        raise ValueError(
            "stable UI hierarchy unavailable after "
            f"{attempts} attempt(s): {'; '.join(failures)}"
        )

    def _read_current_accessibility(self) -> tuple[tuple[ElementNode, ...], dict[str, Any]]:
        failures = []
        for attempt in range(1, 3):
            result = self._run_native_helper("snapshot")
            if result.returncode or len(result.stdout) > 8_000_000:
                detail = (result.stderr if len(result.stderr) <= 2400 else
                          result.stderr[:1200] + "\n... native trace shortened ...\n" + result.stderr[-1200:])
                # The old connection has exited. A changing tree or temporary
                # missing root can settle just like a watchdog-expired read.
                # Discard output and allow one fresh complete observation;
                # malformed trees and unrelated failures are not retried.
                deadline_expired = (result.returncode == 2 and any(
                    line.startswith(f"Android native operation exceeded {self._ui_snapshot_timeout_seconds} seconds")
                    for line in result.stderr.splitlines()))
                transient_tree = (result.returncode == 1 and any(
                    line.strip() in (
                        "java.util.ConcurrentModificationException: incomplete current hierarchy",
                        "java.lang.IllegalStateException: current root unavailable",
                    ) for line in result.stderr.splitlines()))
                failures.append(f"attempt {attempt}: {detail}")
                if attempt == 1 and (deadline_expired or transient_tree):
                    if transient_tree:
                        time.sleep(2.0)
                    continue
                raise RuntimeError("Current Android UI snapshot failed: " + "; ".join(failures))
            nodes = self._parse_hierarchy(result.stdout)
            if not nodes:
                raise ValueError("Current Android UI snapshot was empty")
            return nodes, {"hierarchy_source": "current_accessibility", "hierarchy_node_count": len(nodes),
                           "hierarchy_read_attempt": attempt, "hierarchy_read_failures": tuple(failures)}
        raise AssertionError("bounded current UI observation exhausted")

    def _run_native_helper(self, *arguments: str) -> ProcessResult:
        if self._native_helper_path is None:
            from hashlib import sha256
            helper = build_native_helper(self.adb_path)
            digest = sha256(helper.read_bytes()).hexdigest()
            device_path = f"/data/local/tmp/mobile-control-ui-{digest[:20]}.zip"
            pushed = self._adb(("push", str(helper), device_path), timeout=10.0)
            verified = self._shell(("sha256sum", device_path), timeout=5.0)
            if pushed.returncode or verified.returncode or verified.stdout.split()[:1] != [digest]:
                raise RuntimeError("Android UI snapshot helper upload not verified")
            self._native_helper_path = device_path
        # The device watchdog starts inside app_process. The host allowance also
        # includes ADB transport and VM startup, which can exceed two seconds.
        snapshot = arguments == ("snapshot",)
        host_timeout = 20.0 if snapshot else 10.0
        if snapshot and (self._ui_snapshot_timeout_seconds != 8 or not self._ui_include_not_important_views):
            arguments = (*arguments, str(self._ui_snapshot_timeout_seconds))
            if not self._ui_include_not_important_views:
                arguments = (*arguments, "important")
        return self._shell((f"CLASSPATH={self._native_helper_path}", "app_process", "/system/bin",
                            "org.testbed.mobile.AndroidNativeBridge", *arguments), timeout=host_timeout)

    def recent_app_tasks(self) -> list[dict[str, Any]]:
        import json
        result = self._run_native_helper("list-recent-tasks")
        if result.returncode:
            raise RuntimeError("Recent task observation failed: " + result.stderr[-1200:])
        tasks = json.loads(result.stdout)["tasks"]
        if not isinstance(tasks, list) or len(tasks) > 1000:
            raise ValueError("Invalid recent task observation")
        for task in tasks:
            self._valid_app_id(task["app_id"])
            if type(task["task_id"]) is not int or task["task_id"] < 0:
                raise ValueError("Invalid recent task ID")
        return tasks

    def dismiss_recent_app_tasks(self, app_ids: Sequence[str]) -> dict[str, Any]:
        packages = {self._valid_app_id(app_id) for app_id in app_ids}
        before = self.recent_app_tasks()
        removed = []
        for task in before:
            if task["app_id"] not in packages:
                continue
            if task.get("is_home") or task.get("activity_type") not in (0, 1):
                raise ValueError("Refusing to remove a system recent task")
            command = self._run_native_helper("remove-task", str(task["task_id"]), task["app_id"])
            if command.returncode:
                raise RuntimeError("Recent task removal failed: " + command.stderr[-1200:])
            removed.append(task["task_id"])
        after = self.recent_app_tasks()
        if any(task["app_id"] in packages for task in after):
            raise RuntimeError("Target recent task remains after removal")
        preserved = {(task["task_id"], task["app_id"]) for task in before if task["app_id"] not in packages}
        if not preserved.issubset({(task["task_id"], task["app_id"]) for task in after}):
            raise RuntimeError("Other recent tasks changed during target removal")
        return {"recent_tasks_before": before, "removed_task_ids": removed, "recent_tasks_after": after}

    def _read_element_hierarchy_file(
        self,
        parameters: Mapping[str, Any],
    ) -> tuple[tuple[ElementNode, ...], dict[str, Any]]:
        """Read one current hierarchy through an adapter-owned device temp file."""

        device_path = "/sdcard/mobile_control_hierarchy.xml"
        attempts = max(1, min(4, int(parameters.get("hierarchy_read_attempts", 3))))
        retry_delay_seconds = max(
            0.0,
            min(3.0, float(parameters.get("hierarchy_retry_delay_seconds", 0.75))),
        )
        read_timeout_seconds = max(
            1.0,
            min(
                self._timeout,
                float(parameters.get("hierarchy_read_timeout_seconds", self._timeout)),
            ),
        )
        compressed = bool(parameters.get("hierarchy_compressed", True))
        failures: list[str] = []
        for attempt in range(1, attempts + 1):
            self._shell(("rm", "-f", device_path), timeout=5.0)
            read_compressed = compressed and attempt == 1
            try:
                dump_args = ["uiautomator", "dump"]
                if read_compressed:
                    dump_args.append("--compressed")
                dump_args.append(device_path)
                dumped = self._shell(tuple(dump_args), timeout=read_timeout_seconds)
                if dumped.returncode != 0:
                    raise RuntimeError(
                        dumped.stderr.strip()
                        or dumped.stdout.strip()
                        or "uiautomator dump failed"
                    )
                hierarchy = self._adb(
                    ("exec-out", "cat", device_path),
                    timeout=read_timeout_seconds,
                )
                if hierarchy.returncode != 0:
                    raise RuntimeError(
                        hierarchy.stderr.strip() or "uiautomator hierarchy read failed"
                    )
                if "</hierarchy>" not in hierarchy.stdout:
                    raise ValueError("uiautomator device-file hierarchy is incomplete")
                nodes = self._parse_hierarchy(hierarchy.stdout)
                if not nodes:
                    raise ValueError("structured UI hierarchy was empty")
                return nodes, {
                    "hierarchy_read_attempt": attempt,
                    "hierarchy_read_attempts": attempts,
                    "hierarchy_compressed": read_compressed,
                    "hierarchy_node_count": len(nodes),
                    "hierarchy_read_failures": tuple(failures),
                }
            except subprocess.TimeoutExpired:
                failures.append(
                    f"attempt {attempt}: timeout after {read_timeout_seconds:.1f}s"
                )
            except Exception as exc:
                failures.append(f"attempt {attempt}: {type(exc).__name__}: {exc}")
            finally:
                self._shell(("rm", "-f", device_path), timeout=5.0)
            if attempt < attempts and retry_delay_seconds:
                time.sleep(retry_delay_seconds)
        raise ValueError(
            "stable device-file UI hierarchy unavailable after "
            f"{attempts} attempt(s): {'; '.join(failures)}"
        )

    def activate_element(self, element: ElementNode, parameters: Mapping[str, Any]) -> CommandResult:
        if not element.bounds:
            return self._rejected(ActionMethod.ELEMENT, "element.activate", "element has no bounds")
        left, top, right, bottom = element.bounds
        if right <= left or bottom <= top:
            return self._rejected(ActionMethod.ELEMENT, "element.activate", "element bounds are invalid")
        x, y = (left + right) // 2, (top + bottom) // 2
        return self._shell_command(
            "element.activate",
            ("input", "tap", str(x), str(y)),
            ActionMethod.ELEMENT,
            {"element_handle": element.handle, "resource_id": element.resource_id},
        )

    def replace_element_text(self, element: ElementNode, text: str) -> CommandResult:
        """Set Unicode through the existing native bridge; no clipboard/IME changes."""
        import base64
        import json
        if not element.resource_id or not isinstance(text, str) or not 1 <= len(text) <= 4096:
            return self._rejected(ActionMethod.ELEMENT, "element.replace_text", "invalid editor or text")
        payload = base64.b64encode(json.dumps({"app_id": self.app_id,
            "resource_id": element.resource_id, "text": text}, ensure_ascii=False).encode()).decode()
        result = self._run_native_helper("set-text", payload)
        return CommandResult(CommandStatus.ACCEPTED if result.returncode == 0 else CommandStatus.UNKNOWN,
            ActionMethod.ELEMENT, "element.replace_text", "native text replacement attempted",
            {"replacement_length": len(text)})

    def execute_gesture(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        if capability == "system.recents.clear":
            return self._clear_recent_apps(parameters)
        if capability == "screen.swipe.relative.if_visual_ready":
            try:
                readiness = self._visual_region_readiness(
                    self._capture_screenshot(), parameters
                )
            except Exception as exc:
                return self._rejected(
                    ActionMethod.GESTURE,
                    capability,
                    f"visual readiness probe failed: {type(exc).__name__}: {exc}",
                )
            if not readiness["ready"]:
                return CommandResult(
                    CommandStatus.ACCEPTED,
                    ActionMethod.GESTURE,
                    capability,
                    "visual control is unavailable; gesture skipped",
                    {**readiness, "executed": False, "skip_reason": "unavailable"},
                )
            result = self.execute_gesture("screen.swipe.relative", parameters)
            return CommandResult(
                result.status,
                result.method,
                capability,
                result.detail,
                {**dict(result.evidence), **readiness, "executed": True},
            )
        if capability not in {"screen.tap.relative", "screen.swipe.relative"}:
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
                return self._rejected(
                    ActionMethod.GESTURE,
                    capability,
                    "tap ratios must be numbers",
                )
            if not (0 <= x_ratio <= 1 and 0 <= y_ratio <= 1):
                return self._rejected(
                    ActionMethod.GESTURE,
                    capability,
                    "tap ratios must be between zero and one",
                )
            try:
                width, height = self._get_screen_size()
            except Exception as exc:
                return self._rejected(
                    ActionMethod.GESTURE,
                    capability,
                    f"screen size unavailable: {type(exc).__name__}: {exc}",
                )
            return self._shell_command(
                capability,
                (
                    "input",
                    "tap",
                    str(round(width * x_ratio)),
                    str(round(height * y_ratio)),
                ),
                ActionMethod.GESTURE,
                {
                    "ratios": (x_ratio, y_ratio),
                    "screen_size": (width, height),
                },
            )

        if "required_visible_texts" in parameters:
            required = parameters["required_visible_texts"]
            if (
                not isinstance(required, (list, tuple))
                or not 1 <= len(required) <= 16
                or any(not isinstance(text, str) or not text.strip() for text in required)
            ):
                return self._rejected(
                    ActionMethod.GESTURE, capability, "invalid required visible texts"
                )
            try:
                foreground = self._shell(("dumpsys", "window"), timeout=5.0)
                if foreground.returncode != 0 or self._parse_foreground(foreground.stdout) != self.app_id:
                    raise RuntimeError("target app is not foreground")
                elements, _ = self._read_element_hierarchy(parameters)
                visible = {
                    value.strip()
                    for node in elements
                    if node.visible and node.attributes.get("package") == self.app_id
                    for value in (node.text, node.label, node.accessibility_id)
                    if value.strip()
                }
                if not set(required).issubset(visible):
                    raise RuntimeError("required target-app texts are not all visible")
            except Exception as exc:
                return self._rejected(
                    ActionMethod.GESTURE, capability,
                    f"guarded swipe rejected: {type(exc).__name__}: {exc}",
                )

        direction = str(parameters.get("direction") or "up").casefold()
        paths = {
            "up": (0.5, 0.75, 0.5, 0.25),
            "down": (0.5, 0.25, 0.5, 0.75),
            "left": (0.8, 0.5, 0.2, 0.5),
            "right": (0.2, 0.5, 0.8, 0.5),
        }
        custom_path_keys = (
            "start_x_ratio",
            "start_y_ratio",
            "end_x_ratio",
            "end_y_ratio",
        )
        custom_requested = any(
            key in parameters for key in ("start_x_ratio", "end_x_ratio")
        )
        if custom_requested and not all(key in parameters for key in custom_path_keys):
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                "custom swipe requires all four start/end ratios",
            )
        if direction not in paths and not custom_requested:
            return self._rejected(ActionMethod.GESTURE, capability, "unsupported direction")
        try:
            width, height = self._get_screen_size()
        except Exception as exc:
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                f"screen size unavailable: {type(exc).__name__}: {exc}",
            )
        x1r, y1r, x2r, y2r = paths.get(direction, paths["up"])
        try:
            if custom_requested:
                direction = "custom"
                x1r = float(parameters["start_x_ratio"])
                y1r = float(parameters["start_y_ratio"])
                x2r = float(parameters["end_x_ratio"])
                y2r = float(parameters["end_y_ratio"])
                end_x_delta_px = 0
            elif direction in {"up", "down"} and any(
                key in parameters
                for key in ("x_ratio", "start_y_ratio", "end_y_ratio", "end_x_delta_px")
            ):
                x1r = float(parameters.get("x_ratio", x1r))
                x2r = x1r
                y1r = float(parameters.get("start_y_ratio", y1r))
                y2r = float(parameters.get("end_y_ratio", y2r))
                end_x_delta_px = int(parameters.get("end_x_delta_px", 0))
            else:
                end_x_delta_px = 0
            duration = max(50, int(parameters.get("duration_ms", 450)))
        except (TypeError, ValueError):
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                "swipe path and duration parameters must be numeric",
            )
        if not all(0 <= ratio <= 1 for ratio in (x1r, y1r, x2r, y2r)):
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                "swipe path ratios must be between zero and one",
            )
        x1 = round(width * x1r)
        x2 = min(width - 1, max(0, round(width * x2r) + end_x_delta_px))
        args = (
            "input",
            "swipe",
            str(x1),
            str(round(height * y1r)),
            str(x2),
            str(round(height * y2r)),
            str(duration),
        )
        return self._shell_command(
            capability,
            args,
            ActionMethod.GESTURE,
            {
                "direction": direction,
                "screen_size": (width, height),
                "path": (x1, round(height * y1r), x2, round(height * y2r)),
                "duration_ms": duration,
            },
        )

    @staticmethod
    def _visual_region_readiness(
        frame_png: bytes,
        parameters: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            import cv2
            import numpy as np
            from PIL import Image
        except ImportError as exc:  # pragma: no cover - host packaging failure
            raise RuntimeError(
                "OpenCV, NumPy, and Pillow are required for visual readiness probes"
            ) from exc

        frame = Image.open(BytesIO(frame_png)).convert("RGB")
        width, height = frame.size
        reference_size = parameters.get("reference_size", (width, height))
        if not isinstance(reference_size, (list, tuple)) or len(reference_size) != 2:
            raise ValueError("reference_size must contain width and height")
        reference_width, reference_height = map(int, reference_size)
        if reference_width <= 0 or reference_height <= 0:
            raise ValueError("reference_size values must be positive")
        center_x_ratio = float(parameters.get("ready_x_ratio"))
        center_y_ratio = float(parameters.get("ready_y_ratio"))
        if not 0 <= center_x_ratio <= 1 or not 0 <= center_y_ratio <= 1:
            raise ValueError("visual readiness center ratios must be between zero and one")
        radius_reference_px = int(parameters.get("ready_radius_reference_px", 32))
        if not 4 <= radius_reference_px <= 200:
            raise ValueError("visual readiness radius is outside the bounded range")
        radius = max(
            4,
            round(
                radius_reference_px
                * min(width / reference_width, height / reference_height)
            ),
        )
        center_x = round(width * center_x_ratio)
        center_y = round(height * center_y_ratio)
        left = max(0, center_x - radius)
        top = max(0, center_y - radius)
        right = min(width, center_x + radius + 1)
        bottom = min(height, center_y + radius + 1)
        if right - left < 8 or bottom - top < 8:
            raise ValueError("visual readiness region is too small")

        region = np.asarray(frame.crop((left, top, right, bottom)))
        hsv = cv2.cvtColor(region, cv2.COLOR_RGB2HSV)
        yy, xx = np.ogrid[: region.shape[0], : region.shape[1]]
        local_center_x = center_x - left
        local_center_y = center_y - top
        circle = (
            (xx - local_center_x) ** 2 + (yy - local_center_y) ** 2
            <= radius**2
        )
        minimum_saturation = int(parameters.get("ready_min_saturation", 60))
        minimum_value = int(parameters.get("ready_min_value", 100))
        minimum_fraction = float(parameters.get("ready_min_fraction", 0.55))
        if not 0 <= minimum_saturation <= 255 or not 0 <= minimum_value <= 255:
            raise ValueError("visual readiness HSV thresholds must be bytes")
        if not 0 <= minimum_fraction <= 1:
            raise ValueError("visual readiness fraction must be between zero and one")
        active = (
            (hsv[:, :, 1] >= minimum_saturation)
            & (hsv[:, :, 2] >= minimum_value)
            & circle
        )
        ready_fraction = float(active.sum() / max(1, circle.sum()))
        return {
            "ready": ready_fraction >= minimum_fraction,
            "ready_fraction": round(ready_fraction, 6),
            "minimum_ready_fraction": minimum_fraction,
            "bounds": (left, top, right, bottom),
            "frame_size": (width, height),
        }

    @staticmethod
    def _visual_color_components(
        frame_png: bytes,
        parameters: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        try:
            import cv2
            import numpy as np
            from PIL import Image
        except ImportError as exc:  # pragma: no cover - host packaging failure
            raise RuntimeError(
                "OpenCV, NumPy, and Pillow are required for visual color components"
            ) from exc

        frame = Image.open(BytesIO(frame_png)).convert("RGB")
        width, height = frame.size
        ratios = parameters.get("search_region", (0.0, 0.0, 1.0, 1.0))
        if not isinstance(ratios, (list, tuple)) or len(ratios) != 4:
            raise ValueError("search_region must contain four relative bounds")
        left_ratio, top_ratio, right_ratio, bottom_ratio = map(float, ratios)
        if not (0 <= left_ratio < right_ratio <= 1 and 0 <= top_ratio < bottom_ratio <= 1):
            raise ValueError("search_region must be inside the current viewport")
        search_bounds = (
            round(width * left_ratio),
            round(height * top_ratio),
            round(width * right_ratio),
            round(height * bottom_ratio),
        )
        lower = parameters.get("hsv_lower")
        upper = parameters.get("hsv_upper")
        if (
            not isinstance(lower, (list, tuple))
            or not isinstance(upper, (list, tuple))
            or len(lower) != 3
            or len(upper) != 3
        ):
            raise ValueError("hsv_lower and hsv_upper must contain three values")
        lower_values = tuple(int(value) for value in lower)
        upper_values = tuple(int(value) for value in upper)
        if any(value < 0 or value > 255 for value in (*lower_values, *upper_values)):
            raise ValueError("HSV bounds must be bytes")
        search = np.asarray(frame.crop(search_bounds))
        hsv = cv2.cvtColor(search, cv2.COLOR_RGB2HSV)
        mask = cv2.inRange(
            hsv,
            np.array(lower_values, dtype=np.uint8),
            np.array(upper_values, dtype=np.uint8),
        )
        count, _, stats, _ = cv2.connectedComponentsWithStats(mask)
        min_width = width * float(parameters.get("min_width_ratio", 0.0))
        max_width = width * float(parameters.get("max_width_ratio", 1.0))
        min_height = height * float(parameters.get("min_height_ratio", 0.0))
        max_height = height * float(parameters.get("max_height_ratio", 1.0))
        min_fill = float(parameters.get("minimum_fill_ratio", 0.0))
        if not 0 <= min_fill <= 1:
            raise ValueError("minimum_fill_ratio must be between zero and one")
        components: list[dict[str, Any]] = []
        for x, y, component_width, component_height, area in stats[1:count]:
            if not (
                min_width <= component_width <= max_width
                and min_height <= component_height <= max_height
            ):
                continue
            fill_ratio = float(area / max(1, component_width * component_height))
            if fill_ratio < min_fill:
                continue
            components.append(
                {
                    "bounds": (
                        search_bounds[0] + int(x),
                        search_bounds[1] + int(y),
                        search_bounds[0] + int(x + component_width),
                        search_bounds[1] + int(y + component_height),
                    ),
                    "pixel_count": int(area),
                    "fill_ratio": round(fill_ratio, 6),
                }
            )
        components.sort(key=lambda item: (item["bounds"][0], item["bounds"][1]))
        minimum_count = max(1, min(10, int(parameters.get("minimum_count", 1))))
        maximum_count = max(
            minimum_count,
            min(20, int(parameters.get("maximum_count", 20))),
        )
        if not minimum_count <= len(components) <= maximum_count:
            return ()
        return tuple(components)

    def _clear_recent_apps(self, parameters: Mapping[str, Any]) -> CommandResult:
        capability = "system.recents.clear"
        method = "app_switcher_swipe_up"
        preserve_labels = tuple(
            dict.fromkeys(
                str(label).strip()
                for label in parameters.get("preserve_app_labels", ())
                if str(label).strip()
            )
        )
        preserve_keys = {label.casefold() for label in preserve_labels}
        try:
            max_swipes = int(parameters.get("max_swipes", 40))
            settle_seconds = float(parameters.get("settle_seconds", 0.45))
        except (TypeError, ValueError):
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                "max_swipes and settle_seconds must be numeric",
            )
        if not 1 <= max_swipes <= 100 or not 0 <= settle_seconds <= 3:
            return self._rejected(
                ActionMethod.GESTURE,
                capability,
                "recent-app cleanup limits are invalid",
            )
        try:
            width, height = self._get_screen_size()
            initial_probe_error = ""
            system_empty_verified = False
            recents_entry_method = "already_visible"
            try:
                cards, recents_visible = self._recent_app_cards()
            except Exception as exc:
                # This first read only avoids toggling an already-open switcher.
                # A busy media app may not expose an accessibility hierarchy at
                # all, so enter Recents and apply the strict read there instead.
                cards, recents_visible = (), False
                initial_probe_error = f"{type(exc).__name__}: {exc}"
            if not recents_visible:
                opened = self._shell(("input", "keyevent", "187"))
                if opened.returncode != 0:
                    raise RuntimeError(opened.stderr.strip() or "cannot open Android recents")
                recents_entry_method = "keyevent_app_switch"
                time.sleep(settle_seconds)
                cards, recents_visible = self._recent_app_cards()
            if not recents_visible:
                non_home_tasks = self._non_home_recent_task_count()
                if non_home_tasks == 0:
                    cards = ()
                    system_empty_verified = True
                else:
                    recents_component = self._start_system_recents_component()
                    recents_entry_method = f"resolved_component:{recents_component}"
                    time.sleep(settle_seconds)
                    cards, recents_visible = self._recent_app_cards()
                    if not recents_visible:
                        raise RuntimeError(
                            "Android recents surface was not visible after APP_SWITCH "
                            f"or resolved component {recents_component}"
                        )

            cards_before = len(cards)
            dismissed_cards = 0
            actions: list[dict[str, Any]] = []
            while cards and dismissed_cards < max_swipes:
                if preserve_keys and any(not card[1] for card in cards):
                    raise RuntimeError(
                        "recent-app card identity is unavailable; preservation cannot be verified"
                    )
                removable = tuple(
                    card for card in cards if card[1].casefold() not in preserve_keys
                )
                if not removable:
                    break
                card = min(
                    removable,
                    key=lambda item: (
                        abs(((item[0][0] + item[0][2]) / 2) - (width / 2)),
                        -((item[0][2] - item[0][0]) * (item[0][3] - item[0][1])),
                    ),
                )
                bounds, card_label = card
                card = bounds
                left, top, right, bottom = card
                if width > height:
                    # MIUI uses a horizontal task carousel in landscape. An
                    # upward swipe only scrolls the card and leaves it in the
                    # task list, so dismiss toward the nearest side instead.
                    start_x = max(1, min(width - 1, round((left + right) / 2)))
                    start_y = max(1, min(height - 1, round((top + bottom) / 2)))
                    end_x = round(width * (0.94 if start_x >= width / 2 else 0.06))
                    end_y = start_y
                    direction = "right" if end_x > start_x else "left"
                else:
                    start_x = max(1, min(width - 1, round((left + right) / 2)))
                    start_y = max(1, min(height - 1, round(top + (bottom - top) * 0.72)))
                    end_x = start_x
                    end_y = max(1, round(height * 0.08))
                    direction = "up"
                    if start_y <= end_y:
                        raise RuntimeError(f"recent-app card has invalid swipe bounds: {card}")
                swipe = self._shell(
                    (
                        "input",
                        "swipe",
                        str(start_x),
                        str(start_y),
                        str(end_x),
                        str(end_y),
                        "320",
                    )
                )
                if swipe.returncode != 0:
                    raise RuntimeError(swipe.stderr.strip() or "recent-card swipe failed")
                dismissed_cards += 1
                actions.append(
                    {
                        "index": dismissed_cards,
                        "direction": direction,
                        "start_ratio": (start_x / width, start_y / height),
                        "end_ratio": (end_x / width, end_y / height),
                        "visible_cards_before": len(cards),
                        "dismissed_label": card_label,
                    }
                )
                time.sleep(settle_seconds)
                cards, recents_visible = self._recent_app_cards()
                if not recents_visible:
                    non_home_tasks = self._non_home_recent_task_count()
                    if non_home_tasks == 0:
                        cards = ()
                        system_empty_verified = True
                        break
                    # Some launchers leave recents after the last dismissal.
                    # Reopen it once and require the semantic task list to be empty.
                    reopened = self._shell(("input", "keyevent", "187"))
                    if reopened.returncode != 0:
                        raise RuntimeError(
                            reopened.stderr.strip() or "cannot reopen Android recents"
                        )
                    time.sleep(settle_seconds)
                    cards, recents_visible = self._recent_app_cards()
                    if not recents_visible:
                        non_home_tasks = self._non_home_recent_task_count()
                        if non_home_tasks == 0:
                            cards = ()
                            system_empty_verified = True
                            break
                        raise RuntimeError("cannot verify Android recents after swiping")

            remaining_cards = len(cards)
            remaining_labels = tuple(card[1] for card in cards)
            unexpected_labels = tuple(
                label for label in remaining_labels if label.casefold() not in preserve_keys
            )
            preservation_verified = bool(preserve_keys) and not unexpected_labels
            evidence = {
                "method": method,
                "screen_size": (width, height),
                "cards_before": cards_before,
                "dismissed_cards": dismissed_cards,
                "swipes_attempted": dismissed_cards,
                "remaining_cards": remaining_cards,
                "empty_verified": (recents_visible or system_empty_verified) and remaining_cards == 0,
                "system_empty_verified": system_empty_verified,
                "preserve_app_labels": preserve_labels,
                "remaining_labels": remaining_labels,
                "preservation_verified": recents_visible and preservation_verified,
                "initial_probe_error": initial_probe_error,
                "recents_entry_method": recents_entry_method,
                "actions": actions,
            }
            if unexpected_labels:
                return CommandResult(
                    CommandStatus.REJECTED,
                    ActionMethod.GESTURE,
                    capability,
                    "Android recents still contains non-preserved card(s): "
                    + ", ".join(unexpected_labels),
                    evidence,
                )
            return CommandResult(
                CommandStatus.ACCEPTED,
                ActionMethod.GESTURE,
                capability,
                (
                    f"dismissed {dismissed_cards} Android recent-app card(s) and preserved "
                    f"{remaining_cards} allowlisted card(s)"
                    if preserve_keys
                    else f"dismissed {dismissed_cards} Android recent-app card(s) with orientation-aware swipes"
                ),
                evidence,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                CommandStatus.TIMEOUT,
                ActionMethod.GESTURE,
                capability,
                str(exc),
                {"method": method, "empty_verified": False, "remaining_cards": -1},
            )
        except Exception as exc:
            return CommandResult(
                CommandStatus.REJECTED,
                ActionMethod.GESTURE,
                capability,
                f"{type(exc).__name__}: {exc}",
                {"method": method, "empty_verified": False, "remaining_cards": -1},
            )

    def _recent_app_cards(
        self,
    ) -> tuple[tuple[tuple[tuple[int, int, int, int], str], ...], bool]:
        nodes, _ = self._read_element_hierarchy(
            {
                "hierarchy_read_attempts": 3,
                "hierarchy_compressed": True,
                "hierarchy_retry_delay_seconds": 0.5,
                "hierarchy_read_timeout_seconds": min(6.0, self._timeout),
            }
        )
        recents_visible = any(
            node.resource_id.endswith(":id/recents_container")
            or node.resource_id.endswith(":id/recents_view")
            or node.resource_id.endswith(":id/clearAnimView")
            for node in nodes
        )
        recents_visible = recents_visible or any(
            str(node.attributes.get("package") or "") == "com.miui.home"
            and node.text.strip() == "近期没有任何内容"
            for node in nodes
        )
        cards: list[tuple[tuple[int, int, int, int], str]] = []
        for thumbnail in nodes:
            if (
                not thumbnail.resource_id.endswith(":id/task_view_thumbnail")
                or thumbnail.bounds is None
                or thumbnail.bounds[2] <= thumbnail.bounds[0]
                or thumbnail.bounds[3] <= thumbnail.bounds[1]
            ):
                continue
            left, top, right, bottom = thumbnail.bounds
            titles = [
                node
                for node in nodes
                if node.resource_id.endswith(":id/title")
                and node.bounds is not None
                and node.text.strip()
                and left <= (node.bounds[0] + node.bounds[2]) / 2 <= right
                and top <= (node.bounds[1] + node.bounds[3]) / 2 <= bottom
            ]
            titles.sort(key=lambda node: (node.bounds[1], node.bounds[0], node.handle))
            label = titles[0].text.strip() if titles else ""
            if not label:
                containers = [
                    node
                    for node in nodes
                    if node.clickable
                    and node.bounds == thumbnail.bounds
                    and node.accessibility_id.strip()
                ]
                if containers:
                    label = containers[0].accessibility_id.split(",", 1)[0].strip()
            cards.append((thumbnail.bounds, label))
        if recents_visible and not cards:
            # Current MIUI builds can omit task_view_thumbnail and expose each
            # task only as one large clickable container enclosing an :id/title.
            # Derive the card from that live relationship rather than storing a
            # launcher coordinate or trusting the localized content description.
            seen_bounds: set[tuple[int, int, int, int]] = set()
            for title in nodes:
                if (
                    not title.resource_id.endswith(":id/title")
                    or title.bounds is None
                    or not title.text.strip()
                ):
                    continue
                title_left, title_top, title_right, title_bottom = title.bounds
                title_height = max(1, title_bottom - title_top)
                containers = []
                for node in nodes:
                    if not node.clickable or node.bounds is None:
                        continue
                    left, top, right, bottom = node.bounds
                    if (
                        left <= title_left
                        and top <= title_top
                        and right >= title_right
                        and bottom >= title_bottom
                        and bottom - top >= title_height * 3
                    ):
                        containers.append(node)
                if not containers:
                    continue
                containers.sort(key=lambda node: (
                    (node.bounds[2] - node.bounds[0]) * (node.bounds[3] - node.bounds[1]),
                    node.handle,
                ))
                bounds = containers[0].bounds
                if bounds in seen_bounds:
                    continue
                seen_bounds.add(bounds)
                cards.append((bounds, title.text.strip()))
        return tuple(cards), recents_visible

    def _non_home_recent_task_count(self) -> int | None:
        result = self._shell(("dumpsys", "activity", "recents"), timeout=10.0)
        if result.returncode != 0 or "ACTIVITY MANAGER RECENT TASKS" not in result.stdout:
            return None
        task_lines = tuple(
            line
            for line in result.stdout.splitlines()
            if re.search(r"^\s*\*\s+Recent\s+#\d+:", line)
        )
        return sum("type=home" not in line for line in task_lines)

    def _start_system_recents_component(self) -> str:
        result = self._shell(("dumpsys", "activity", "recents"), timeout=10.0)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "cannot resolve Android recents component")
        match = re.search(
            r"(?m)^mRecentsComponent=ComponentInfo\{([A-Za-z0-9._$]+/[A-Za-z0-9._$]+)\}\s*$",
            result.stdout,
        )
        if match is None:
            raise RuntimeError("Android system did not report a valid recents component")
        component = match.group(1)
        opened = self._shell(("am", "start", "-n", component), timeout=10.0)
        if opened.returncode != 0:
            raise RuntimeError(opened.stderr.strip() or "cannot start Android recents component")
        return component

    def execute_visual(self, capability: str, parameters: Mapping[str, Any]) -> CommandResult:
        return CommandResult(
            CommandStatus.UNSUPPORTED,
            ActionMethod.VISUAL,
            capability,
            "Android adapter has no runtime visual-agent capability",
        )

    def environment_checkpoint(self) -> dict:
        """Read-only native evidence before resuming an uncleared environment."""
        evidence = {"serial": self.serial, "epoch": time.time()}
        for name, args in (
            ("uptime", ("cat", "/proc/uptime")),
            ("boot_id", ("cat", "/proc/sys/kernel/random/boot_id")),
            ("media_sessions", ("dumpsys", "media_session")),
            ("audio_flinger", ("dumpsys", "media.audio_flinger")),
        ):
            result = self._shell(args)
            if result.returncode or not result.stdout.strip():
                raise RuntimeError(f"Cannot verify environment: {name}")
            evidence[name] = result.stdout
        return evidence

    def background_checkpoint(self) -> dict:
        evidence = self.environment_checkpoint()
        for name, args in (("processes", ("ps", "-A")),
                           ("foreground", ("dumpsys", "activity", "activities"))):
            result = self._shell(args)
            if result.returncode or not result.stdout.strip():
                raise RuntimeError(f"Cannot observe retained background: {name}")
            evidence[name] = result.stdout
        return evidence

    def _adb(self, args: Sequence[str], *, timeout: float | None = None) -> ProcessResult:
        return self._executor.run(
            (self.adb_path, "-s", self.serial, *args),
            timeout or self._timeout,
        )

    def _shell(self, args: Sequence[str], *, timeout: float | None = None) -> ProcessResult:
        return self._adb(("shell", *args), timeout=timeout)

    def _capture_screenshot(self) -> bytes:
        result = self._executor.run_bytes(
            (self.adb_path, "-s", self.serial, "exec-out", "screencap", "-p"),
            self._timeout,
        )
        if result.returncode != 0 or not result.stdout:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(detail or f"ADB screencap failed with exit {result.returncode}")
        return result.stdout

    def capture_screenshot(self) -> bytes:
        """Return a passive PNG snapshot for run evidence."""
        return self._capture_screenshot()

    def _adb_command(
        self,
        capability: str,
        args: Sequence[str],
        method: ActionMethod,
        extra_evidence: Mapping[str, Any] | None = None,
    ) -> CommandResult:
        try:
            result = self._adb(args)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(CommandStatus.TIMEOUT, method, capability, str(exc))
        except FileNotFoundError as exc:
            return CommandResult(CommandStatus.UNSUPPORTED, method, capability, str(exc))
        except Exception as exc:
            return CommandResult(CommandStatus.UNKNOWN, method, capability, f"{type(exc).__name__}: {exc}")
        evidence = {
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[-1000:],
            "stderr": result.stderr.strip()[-1000:],
            **dict(extra_evidence or {}),
        }
        return CommandResult(
            CommandStatus.ACCEPTED if result.returncode == 0 else CommandStatus.REJECTED,
            method,
            capability,
            "ADB command returned zero" if result.returncode == 0 else "ADB command failed",
            evidence,
        )

    def _shell_command(
        self,
        capability: str,
        args: Sequence[str],
        method: ActionMethod,
        extra_evidence: Mapping[str, Any] | None = None,
    ) -> CommandResult:
        return self._adb_command(capability, ("shell", *args), method, extra_evidence)

    @staticmethod
    def _rejected(method: ActionMethod, capability: str, detail: str) -> CommandResult:
        return CommandResult(CommandStatus.REJECTED, method, capability, detail)

    @staticmethod
    def _valid_app_id(value: str) -> str:
        if not _APP_ID.fullmatch(value):
            raise ValueError(f"invalid Android package name {value!r}")
        return value

    @staticmethod
    def _parse_foreground(text: str) -> str | None:
        package, _ = AndroidAdbAdapter._parse_foreground_component(text)
        return package

    @staticmethod
    def _parse_foreground_component(text: str) -> tuple[str | None, str | None]:
        patterns = (
            r"mCurrentFocus=.*?\bu\d+\s+([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)",
            r"mFocusedApp=.*?\bu\d+\s+([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)",
            r"topResumedActivity=.*?\bu\d+\s+([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)",
        )
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                component = match.group(1)
                return component.split("/", 1)[0], component
        return None, None

    @staticmethod
    def _activity_class(component: str | None) -> str | None:
        if not component or "/" not in component:
            return None
        package, activity = component.split("/", 1)
        return package + activity if activity.startswith(".") else activity

    @staticmethod
    def _parse_media(text: str, app_id: str) -> dict[str, Any]:
        package_pattern = re.compile(r"(?im)^\s*(?:package|packageName)=([^\s]+)")
        package_matches = list(package_pattern.finditer(text))
        codes: list[int] = []
        for index, package_match in enumerate(package_matches):
            if package_match.group(1).casefold() != app_id.casefold():
                continue
            end = package_matches[index + 1].start() if index + 1 < len(package_matches) else len(text)
            block = text[package_match.end() : end]
            state_match = re.search(
                r"state=PlaybackState\s*\{state=(?:[A-Z_]+\()?([0-9]+)",
                block,
                re.IGNORECASE,
            )
            if state_match:
                codes.append(int(state_match.group(1)))
        if not codes:
            return {}
        code = codes[0]
        if code == 3:
            playback = "playing"
        elif code == 2:
            playback = "paused"
        elif code in {6, 8}:
            playback = "buffering"
        elif code in {4, 5, 9, 10, 11}:
            playback = "transitioning"
        else:
            playback = "stopped"
        package_match = next(
            (
                match
                for match in package_matches
                if match.group(1).casefold() == app_id.casefold()
            ),
            None,
        )
        metadata = ""
        if package_match is not None:
            index = package_matches.index(package_match)
            end = package_matches[index + 1].start() if index + 1 < len(package_matches) else len(text)
            block = text[package_match.end() : end]
            metadata_match = re.search(r"(?im)^\s*metadata:\s*(.+)$", block)
            metadata = metadata_match.group(1).strip() if metadata_match else ""
        result: dict[str, Any] = {
            "package": app_id,
            "playback": playback,
            "android_state_code": code,
        }
        if metadata:
            result["metadata"] = metadata
            description_match = re.search(r"(?:^|,\s*)description=(.+)$", metadata)
            if description_match:
                result["identity"] = description_match.group(1).strip()
        return result

    @staticmethod
    def _parse_audio(text: str, uid: str) -> dict[str, Any]:
        pattern = re.compile(
            rf"AudioPlaybackConfiguration[^\r\n]*\bu/pid:{re.escape(uid)}/\d+[^\r\n]*\bstate:([A-Za-z_]+)",
            re.IGNORECASE,
        )
        states = tuple(match.casefold() for match in pattern.findall(text))
        active_tracks = sum(state == "started" for state in states)
        return {
            "uid": int(uid),
            "playback": "playing" if active_tracks else "inactive",
            "active_tracks": active_tracks,
            "track_states": states,
            "track_evidence_present": bool(states),
        }

    @staticmethod
    def _parse_hierarchy(text: str) -> tuple[ElementNode, ...]:
        start = text.find("<?xml")
        end = text.rfind("</hierarchy>")
        if start < 0 or end < 0:
            raise ValueError("uiautomator output did not contain a hierarchy")
        root = ET.fromstring(text[start : end + len("</hierarchy>")])
        nodes: list[ElementNode] = []
        for index, element in enumerate(root.iter("node")):
            attrs = dict(element.attrib)
            bounds_match = _BOUNDS.fullmatch(attrs.get("bounds", ""))
            bounds = tuple(int(value) for value in bounds_match.groups()) if bounds_match else None
            class_name = attrs.get("class", "")
            descendant_text = " | ".join(
                value.strip()
                for child in element.iter("node")
                for value in (child.attrib.get("text", ""), child.attrib.get("content-desc", ""))
                if value.strip()
            )
            nodes.append(
                ElementNode(
                    f"android:{index}",
                    role=class_name.rsplit(".", 1)[-1].casefold(),
                    resource_id=attrs.get("resource-id", ""),
                    accessibility_id=attrs.get("content-desc", ""),
                    text=attrs.get("text", ""),
                    visible=attrs.get("displayed", "true") == "true",
                    enabled=attrs.get("enabled", "true") == "true",
                    clickable=attrs.get("clickable", "false") == "true",
                    attributes={
                        "class": class_name,
                        "package": attrs.get("package", ""),
                        "selected": attrs.get("selected") == "true",
                        "checked": attrs.get("checked") == "true",
                        "descendant_text": descendant_text,
                    },
                    bounds=bounds,
                )
            )
        return tuple(nodes)

    def _get_app_uid(self) -> str:
        if self._app_uid:
            return self._app_uid
        result = self._shell(
            ("cmd", "package", "list", "packages", "-U", self.app_id),
            timeout=5.0,
        )
        match = re.search(r"\buid:(\d+)\b", result.stdout)
        if result.returncode != 0 or not match:
            raise RuntimeError(result.stderr.strip() or f"UID not found for {self.app_id}")
        self._app_uid = match.group(1)
        return self._app_uid

    def _read_logical_viewport(self) -> tuple[int, int]:
        viewport = self._shell(("dumpsys", "input"), timeout=5.0)
        viewport_match = re.search(
            r"Viewport\s+INTERNAL:.*?logicalFrame=\[0,\s*0,\s*(\d+),\s*(\d+)\].*?isActive=\[1\]",
            viewport.stdout,
        )
        if viewport.returncode == 0 and viewport_match:
            return int(viewport_match.group(1)), int(viewport_match.group(2))
        raise RuntimeError(viewport.stderr.strip() or "active logical viewport unavailable")

    def _get_screen_size(self) -> tuple[int, int]:
        try:
            return self._read_logical_viewport()
        except RuntimeError:
            pass
        result = self._shell(("wm", "size"), timeout=5.0)
        matches = re.findall(r"(Physical|Override) size:\s*(\d+)x(\d+)", result.stdout)
        if result.returncode != 0 or not matches:
            raise RuntimeError(result.stderr.strip() or "wm size could not be parsed")
        _, width, height = next(
            (match for match in reversed(matches) if match[0] == "Override"),
            matches[-1],
        )
        return int(width), int(height)
