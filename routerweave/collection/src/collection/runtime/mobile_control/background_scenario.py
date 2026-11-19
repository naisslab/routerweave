"""Verified device-level background scenario collection.

Background scenarios are not app tasks. They use the shared router stream and
artifact validator but prove device state directly through the platform
controller instead of inventing a target app identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable, Protocol

from .capture import RouterStreamCapture
from .capture.pcap import valid_pcap_header
from .collection import CollectionEventLog, CollectionResult, RouterCaptureConfig
from .device_ip import detect_ios_wifi_ip, validate_router_visible_ip
from .session_isolation import SessionIsolationResult, clear_recent_app_cards
from .status import Platform
from .task_runtime import network_windows_from_mobile_events
from .validation import validate_mobile_collection, write_mobile_collection_validation
from .wda import WdaDeviceController
from collection.runtime.registry.tasks import CollectionTaskRun, require_collection_task


BACKGROUND_SCENARIOS = frozenset({"home_screen_idle", "idle_screen_off"})
SPRINGBOARD_BUNDLE_ID = "com.apple.springboard"


class ScenarioController(Protocol):
    def press_home(self) -> None: ...
    def lock(self) -> None: ...
    def unlock(self) -> None: ...
    def is_locked(self) -> bool: ...
    def active_bundle_id(self) -> str: ...


@dataclass(frozen=True, slots=True)
class BackgroundScenarioRequest:
    scenario: str
    monitor_seconds: float
    platform: str = "ios"
    app_name: str = ""
    udid: str = ""
    request_kind: str = "background_scenario"
    isolate_other_apps: bool = True
    poll_interval_seconds: float = 2.0

    def normalized(self) -> "BackgroundScenarioRequest":
        scenario = self.scenario.strip()
        if self.platform != Platform.IOS.value:
            raise ValueError("background scenario collection currently supports iOS only")
        if scenario not in BACKGROUND_SCENARIOS:
            raise ValueError(
                "scenario must be one of: " + ", ".join(sorted(BACKGROUND_SCENARIOS))
            )
        if self.monitor_seconds <= 0:
            raise ValueError("monitor_seconds must be positive")
        if not self.udid.strip():
            raise ValueError("udid is required for iOS background scenario collection")
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        return replace(self, scenario=scenario, app_name=scenario, udid=self.udid.strip())


def collect_background_scenario(
    request: BackgroundScenarioRequest,
    *,
    router: RouterCaptureConfig,
    out_dir: str | Path,
    wda_url: str = "http://127.0.0.1:8100",
    collection_task_id: str = "",
    capture_factory: Callable[..., RouterStreamCapture] = RouterStreamCapture,
    controller_factory: Callable[[str, Any], ScenarioController] | None = None,
    session_preparer: Callable[..., SessionIsolationResult] = clear_recent_app_cards,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> CollectionResult:
    request = request.normalized()
    registered_task = (
        require_collection_task(
            collection_task_id,
            kind="background",
            platform=request.platform,
        )
        if collection_task_id
        else None
    )
    phone_ip = router.phone_ip.strip() or detect_ios_wifi_ip(wda_url) or ""
    router = replace(router, phone_ip=validate_router_visible_ip(phone_ip))
    router.validate()
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    task_tracking = CollectionTaskRun(destination, collection_task_id)
    task_tracking.start(
        kind="background",
        platform=request.platform,
        title=f"{request.platform} · {request.scenario}",
    )
    task_dir = destination / "mobile_control"
    task_dir.mkdir(parents=True, exist_ok=True)
    collection_log = CollectionEventLog(destination / "collection_events.jsonl")
    task_log = CollectionEventLog(task_dir / "events.jsonl")
    state_path = task_dir / "state_samples.jsonl"
    capture_path = destination / "capture.pcap"
    capture = capture_factory(
        user=router.user,
        host=router.host,
        interface=router.interface,
        phone_ip=router.phone_ip,
        local_pcap=capture_path,
        log=collection_log,
        identity_file=router.identity_file,
    )
    if controller_factory is None:
        controller_factory = lambda url, log: WdaDeviceController(url, log=log)

    controller: ScenarioController | None = None
    isolation_result: SessionIsolationResult | None = None
    capture_started = False
    outcome = "failed"
    error = ""
    checks = 0
    monitor_started = 0.0
    monitor_ended = 0.0
    collection_log.write(
        "collection_started",
        platform=request.platform,
        app_name=request.app_name,
        request_kind=request.request_kind,
        phone_ip=router.phone_ip,
        attribution_mode="none",
        collection_task_id=collection_task_id or None,
    )
    _write_json(task_dir / "request.effective.json", asdict(request))
    _write_json(
        task_dir / "compiled_task.json",
        {
            "playbook_id": "background-scenario",
            "scenario": request.scenario,
            "monitor_seconds": request.monitor_seconds,
            "verification": "wda_locked_state_and_active_bundle",
        },
    )
    try:
        if request.isolate_other_apps:
            isolation_result = session_preparer(
                platform=Platform.IOS,
                target_app_id=SPRINGBOARD_BUNDLE_ID,
                serial="",
                wda_url=wda_url,
            )
            _write_json(destination / "session_isolation.json", asdict(isolation_result))
            collection_log.write("session_isolation_finished", result=isolation_result)
            if not isolation_result.success:
                raise RuntimeError(
                    "session isolation failed: " + "; ".join(isolation_result.errors)
                )
        controller = controller_factory(wda_url, collection_log)
        _prepare_state(controller, request.scenario, sleeper)
        prepared = _observe_state(controller, request.scenario)
        _append_state(state_path, "prepared", prepared)
        if not prepared["matches"]:
            raise RuntimeError("background scenario initial state was not verified")

        capture.start()
        capture_started = True
        task_log.write("playbook_started", playbook_id="background-scenario")
        task_log.write(
            "sustain_started",
            step_id="monitor-active-state",
            duration_seconds=request.monitor_seconds,
        )
        monitor_started = monotonic()
        deadline = monitor_started + request.monitor_seconds
        while True:
            state = _observe_state(controller, request.scenario)
            checks += 1
            _append_state(state_path, "monitor", state)
            if not state["matches"]:
                raise RuntimeError(
                    f"background scenario state changed during monitoring: {state}"
                )
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            sleeper(min(request.poll_interval_seconds, remaining))
        monitor_ended = monotonic()
        outcome = "success"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        collection_log.write("collection_error", error=error)
        monitor_ended = monotonic()
    finally:
        if capture_started:
            try:
                capture.stop()
            except Exception as exc:
                stop_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; capture stop: {stop_error}" if error else stop_error
                outcome = "failed"
                collection_log.write("collection_stop_error", error=stop_error)
        if controller is not None and request.scenario == "idle_screen_off":
            try:
                controller.unlock()
                sleeper(0.5)
                restored = _observe_state(controller, "home_screen_idle")
                _append_state(state_path, "restored", restored)
            except Exception as exc:
                collection_log.write("device_restore_error", error=repr(exc))

    sustain_result = {
        "outcome": outcome,
        "checks": checks,
        "recoveries": 0,
        "duration_seconds": max(0.0, monitor_ended - monitor_started),
        "activities": [],
        "error": error,
    }
    if monitor_started:
        task_log.write(
            "sustain_finished",
            step_id="monitor-active-state",
            result=sustain_result,
        )
    task_result = {
        "playbook_id": "background-scenario",
        "outcome": outcome,
        "steps": [
            {
                "step_id": "monitor-active-state",
                "outcome": outcome,
                "sustain": sustain_result,
            }
        ],
        "error": error,
    }
    task_log.write("playbook_finished", result=task_result)
    _write_json(task_dir / "result.json", task_result)
    windows = network_windows_from_mobile_events(task_dir / "events.jsonl")
    _write_json(destination / "network_capture_windows.json", windows)

    capture_bytes = capture_path.stat().st_size if capture_path.is_file() else 0
    preliminary = CollectionResult(
        request.platform,
        request.app_name,
        str(destination.resolve()),
        outcome == "success" and valid_pcap_header(capture_path) and bool(windows),
        outcome,
        capture_bytes,
        valid_pcap_header(capture_path),
        len(windows),
        False,
        False,
        error,
        "none",
        False,
    )
    manifest = {
        "schema_version": 1,
        "collection_task_id": collection_task_id or None,
        "attribution_mode": "none",
        "traffic_scope": "device",
        "request": asdict(request),
        "router": asdict(router),
        "result": asdict(preliminary),
        "platform_evidence": {
            "platform": request.platform,
            "evidence_type": "disabled",
            "ready": False,
            "formal_ready": False,
            "errors": [],
        },
        "session_isolation": (
            asdict(isolation_result)
            if isolation_result is not None
            else {"success": not request.isolate_other_apps, "disabled": True}
        ),
        "artifacts": {
            "capture_pcap": str(capture_path),
            "task_events": str(task_dir / "events.jsonl"),
            "task_result": str(task_dir / "result.json"),
            "state_samples": str(state_path),
            "network_windows": str(destination / "network_capture_windows.json"),
            "validation": str(destination / "collection_validation.json"),
        },
    }
    _write_json(destination / "collection_manifest.json", manifest)
    validation = validate_mobile_collection(destination)
    write_mobile_collection_validation(
        validation, destination / "collection_validation.json"
    )
    result = replace(
        preliminary,
        valid=preliminary.valid and validation.core_valid,
        collection_ready=preliminary.valid and validation.collection_ready,
    )
    manifest["result"] = asdict(result)
    _write_json(destination / "collection_manifest.json", manifest)
    collection_log.write("collection_finished", result=result)
    task_metadata = registered_task.get("metadata", {}) if registered_task else {}
    minimum_monitor_seconds = float(task_metadata.get("minimum_monitor_seconds") or 0)
    counts_toward_task = bool(
        result.collection_ready and request.monitor_seconds >= minimum_monitor_seconds
    )
    task_message = result.error
    if result.collection_ready and not counts_toward_task:
        task_message = (
            f"validated smoke; payload cleanup automatic; duration_seconds={request.monitor_seconds:g} "
            f"is below task minimum {minimum_monitor_seconds:g}"
        )
    task_tracking.finish(
        "complete" if result.collection_ready else "failed",
        completed_units=1 if counts_toward_task else 0,
        message=task_message,
        details={
            "collection_ready": result.collection_ready,
            "scenario": request.scenario,
            "duration_seconds": request.monitor_seconds,
            "minimum_monitor_seconds": minimum_monitor_seconds,
            "counts_toward_task": counts_toward_task,
        },
        validation_finished=True,
    )
    return result


def _prepare_state(
    controller: ScenarioController,
    scenario: str,
    sleeper: Callable[[float], None],
) -> None:
    controller.press_home()
    _wait_for_state(controller, "home_screen_idle", sleeper)
    if scenario == "idle_screen_off":
        controller.lock()
        _wait_for_state(controller, scenario, sleeper)


def _wait_for_state(
    controller: ScenarioController,
    scenario: str,
    sleeper: Callable[[float], None],
    attempts: int = 10,
) -> None:
    for attempt in range(attempts):
        if _observe_state(controller, scenario)["matches"]:
            return
        if attempt + 1 < attempts:
            sleeper(0.5)
    raise RuntimeError(f"could not verify background scenario state {scenario}")


def _observe_state(controller: ScenarioController, scenario: str) -> dict[str, Any]:
    locked = controller.is_locked()
    active_bundle = "" if locked else controller.active_bundle_id()
    matches = (
        locked
        if scenario == "idle_screen_off"
        else not locked and active_bundle == SPRINGBOARD_BUNDLE_ID
    )
    return {
        "scenario": scenario,
        "locked": locked,
        "active_bundle_id": active_bundle,
        "matches": matches,
    }


def _append_state(path: Path, phase: str, state: dict[str, Any]) -> None:
    row = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        **state,
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
