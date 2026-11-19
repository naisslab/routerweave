"""One cross-platform collection lifecycle for semantic mobile tasks."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import threading
from typing import Any, Callable

from .capture import (
    AndroidSocketEvidence,
    IosProcessEvidence,
    PlatformEvidence,
    PlatformEvidenceResult,
    RouterStreamCapture,
)
from .catalog import MobileAppCatalog
from .cache_cleanup import AppCacheCleanupResult, clear_target_app_cache
from .capture.pcap import valid_pcap_header
from .result import RunResult
from .session_isolation import (SessionIsolationResult, clear_recent_app_cards,
                                reset_android_experiment_apps, close_android_target_tasks)
from .status import Platform
from .device_ip import resolve_phone_ip, validate_router_visible_ip
from .task_runtime import (
    MobileTaskRequest,
    compile_mobile_task,
    network_windows_from_mobile_events,
    resolve_mobile_task_request,
    run_mobile_task,
)
from .validation import validate_mobile_collection, write_mobile_collection_validation
from collection.runtime.registry.tasks import CollectionTaskRun, require_collection_task


@dataclass(frozen=True, slots=True)
class RouterCaptureConfig:
    phone_ip: str
    host: str = ""
    user: str = "root"
    interface: str = "br-lan"
    identity_file: str | None = None

    def validate(self) -> None:
        if not self.phone_ip.strip():
            raise ValueError("phone_ip is required for router capture")
        validate_router_visible_ip(self.phone_ip)
        if not self.host.strip() or not self.user.strip() or not self.interface.strip():
            raise ValueError("router host, user, and interface are required")


@dataclass(frozen=True, slots=True)
class CollectionResult:
    platform: str
    app_name: str
    out_dir: str
    valid: bool
    task_outcome: str
    capture_bytes: int
    capture_header_valid: bool
    window_count: int
    platform_evidence_ready: bool
    formal_ready: bool
    error: str = ""
    attribution_mode: str = "app"
    collection_ready: bool = False


class CollectionEventLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> None:
        row = {
            "event_type": event,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "payload": _json_value(fields),
        }
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def resolve_collection_environment(request: MobileTaskRequest, registered_task: dict | None, *, profile=None):
    """Use the same effective request for preview and actual collection."""
    from ..collection_environment import environment_recipe, CONTINUATION_PROFILE
    if registered_task and registered_task["metadata"].get("collection_scope") == "single_app":
        from .status import Platform
        app = MobileAppCatalog.from_repository().require(Platform(request.platform), request.app_name)
        if app.task_family != registered_task["category"]:
            raise ValueError("App activity differs from the registered collection category")
    environment = environment_recipe(registered_task, request.app_name, profile=profile)
    if environment is not None:
        if request.monitor_seconds < 1800:
            raise ValueError("Supplementary foreground task requires at least 1800 seconds")
        request = replace(request, isolate_other_apps=False, preserve_recent_app_labels=(),
                          clear_app_cache_before_run=False, restart_app=False,
                          leave_app_open=not (request.platform == "android"
                              and environment.get("profile") == CONTINUATION_PROFILE))
    return request, environment


def collect_mobile_task(
    request: MobileTaskRequest,
    *,
    router: RouterCaptureConfig,
    out_dir: str | Path,
    serial: str = "",
    udid: str = "",
    wda_url: str = "http://127.0.0.1:8100",
    attribution_mode: str = "app",
    collection_task_id: str = "",
    capture_factory: Callable[..., RouterStreamCapture] = RouterStreamCapture,
    task_runner: Callable[..., RunResult] = run_mobile_task,
    evidence_factory: Callable[..., PlatformEvidence | None] | None = None,
    session_preparer: Callable[..., SessionIsolationResult] = clear_recent_app_cards,
    cache_preparer: Callable[..., AppCacheCleanupResult] = clear_target_app_cache,
    environment_preparer: Callable[..., None] | None = None,
    environment_operator: str = "human",
    resume_environment_from: str | Path | None = None,
    continue_environment_from: str | Path | None = None,
) -> CollectionResult:
    """Capture one verified semantic task without a plan/replay side channel."""

    if attribution_mode not in {"app", "none"}:
        raise ValueError("attribution_mode must be app or none")
    request = resolve_mobile_task_request(request)
    registered_task = (
        require_collection_task(
            collection_task_id,
            kind="mobile",
            platform=request.platform,
        )
        if collection_task_id
        else None
    )
    from ..collection_environment import prepare_environment
    from ..collection_environment import CONTINUATION_PROFILE, continuation_source
    if resume_environment_from and continue_environment_from:
        raise ValueError("Recovery and a new continuation boundary are mutually exclusive")
    request, environment = resolve_collection_environment(request, registered_task,
        profile=CONTINUATION_PROFILE if continue_environment_from else None)
    if continue_environment_from:
        if environment is None or request.platform not in {"android", "ios"}:
            raise ValueError("Continuation requires a registered mobile supplementary target")
        continuation_source(Path(continue_environment_from), environment)
    if resume_environment_from:
        from ..collection_environment import recovery_source
        if environment is None or request.platform != "android":
            raise ValueError("Recovery requires an Android supplementary collection task")
        source = recovery_source(Path(resume_environment_from), environment)
        if source["foreground_request"] != json.loads(json.dumps(asdict(request))):
            raise ValueError("Recovery must retain the source foreground request; use its request.effective.json")
    router = replace(
        router,
        phone_ip=resolve_phone_ip(
            request,
            explicit=router.phone_ip,
            serial=serial,
            wda_url=wda_url,
        ),
    )
    router.validate()
    # Compile before mutating device or router state.
    catalog = MobileAppCatalog.from_repository()
    binding, _playbook = compile_mobile_task(request, catalog)
    profile = catalog.profile(binding.platform, request.app_name)
    media_cache_paths = tuple(str(path) for path in profile.get("media_cache_paths", ()))
    destination = Path(out_dir)
    if any((destination / name).exists() for name in ('collection_manifest.json', 'screen_time_originals.json', 'capture.pcap')):
        raise FileExistsError('Collection requires a fresh run directory; existing evidence is preserved')
    if environment is not None and destination.exists() and any(destination.iterdir()):
        raise FileExistsError("Supplementary collection requires a new empty run directory")
    destination.mkdir(parents=True, exist_ok=True)
    task_tracking = CollectionTaskRun(destination, collection_task_id)
    task_tracking.start(
        kind="mobile",
        platform=request.platform,
        title=f"{request.platform} · {request.app_name}",
    )
    log = CollectionEventLog(destination / "collection_events.jsonl")
    capture_path = destination / "capture.pcap"
    task_dir = destination / "mobile_control"
    capture = capture_factory(
        user=router.user,
        host=router.host,
        interface=router.interface,
        phone_ip=router.phone_ip,
        local_pcap=capture_path,
        log=log,
        identity_file=router.identity_file,
    )
    evidence = None
    if attribution_mode == "app":
        if evidence_factory is None:
            evidence_factory = _default_evidence_factory
        evidence = evidence_factory(
            request=request,
            app_id=binding.app_id,
            out_dir=destination / "platform_evidence",
            serial=serial,
            udid=udid,
        )
    task_result: RunResult | None = None
    target_attempted = False
    target_cleanup = None
    target_cleanup_required = bool(request.platform == "android" and environment
                                   and environment.get("profile") == CONTINUATION_PROFILE)
    evidence_result: PlatformEvidenceResult | None = None
    isolation_result: SessionIsolationResult | None = None
    cache_cleanup_result: AppCacheCleanupResult | None = None
    error = ""
    started = False
    evidence_prepared = False
    log.write(
        "collection_started",
        platform=request.platform,
        app_name=request.app_name,
        phone_ip=router.phone_ip,
        attribution_mode=attribution_mode,
        collection_task_id=collection_task_id or None,
    )
    try:
        if request.clear_app_cache_before_run:
            cache_cleanup_result = cache_preparer(
                platform=binding.platform,
                target_app_id=binding.app_id,
                serial=serial,
                relative_paths=media_cache_paths,
            )
            _write_json(destination / "cache_cleanup.json", cache_cleanup_result)
            log.write("cache_cleanup_finished", result=cache_cleanup_result)
            if not cache_cleanup_result.success:
                raise RuntimeError(
                    "target app cache cleanup failed: "
                    + "; ".join(cache_cleanup_result.errors)
                )
        if request.isolate_other_apps:
            isolation_options = {
                "platform": binding.platform,
                "target_app_id": binding.app_id,
                "serial": serial,
                "wda_url": wda_url,
            }
            if request.preserve_recent_app_labels:
                isolation_options["preserve_app_labels"] = tuple(
                    request.preserve_recent_app_labels
                )
            isolation_result = session_preparer(
                **isolation_options,
            )
            _write_json(destination / "session_isolation.json", isolation_result)
            log.write("session_isolation_finished", result=isolation_result)
            if not isolation_result.success:
                raise RuntimeError(
                    "session isolation failed: " + "; ".join(isolation_result.errors)
                )
        if evidence is not None:
            evidence.prepare()
            evidence_prepared = True
        capture.start()
        started = True
        if environment is not None:
            if continue_environment_from:
                from ..collection_environment import continue_environment
                continue_environment(destination, environment, Path(continue_environment_from), serial=serial,
                                     udid=udid, wda_url=wda_url, operator_kind=environment_operator)
            elif resume_environment_from:
                from ..collection_environment import resume_environment
                resume_environment(destination, environment, Path(resume_environment_from), serial=serial)
            elif environment_preparer is not None:
                environment_preparer(destination, environment)
            else:
                prepare_environment(destination, environment, operator_kind=environment_operator, resetter=(
                    lambda packages: reset_android_experiment_apps(serial=serial, packages=packages)
                ) if environment.get("reset_packages") else None)
        if evidence is not None:
            evidence.start()
        task_options = {
            "out_dir": task_dir,
            "serial": serial,
            "wda_url": wda_url,
            "event_sink": (
                evidence if callable(getattr(evidence, "emit", None)) else None
            ),
            "session_prepared": request.isolate_other_apps,
        }
        if task_runner is run_mobile_task:
            task_options["network_capture_path"] = capture_path
            task_options["udid"] = udid
        if request.clear_app_cache_before_run:
            task_options["cache_prepared"] = True
        target_attempted = True
        task_result = task_runner(request, **task_options)
    except (Exception, KeyboardInterrupt) as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.write("collection_error", error=error)
    finally:
        if evidence is not None and evidence_prepared:
            try:
                evidence_result = evidence.stop()
            except Exception as exc:
                evidence_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; evidence stop: {evidence_error}" if error else evidence_error
                log.write("platform_evidence_stop_error", error=evidence_error)
        if started:
            try:
                capture.stop()
            except Exception as exc:
                stop_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; capture stop: {stop_error}" if error else stop_error
                log.write("collection_stop_error", error=stop_error)
        if target_cleanup_required and target_attempted:
            try:
                target_cleanup = close_android_target_tasks(serial=serial, target_app_id=binding.app_id)
                _write_json(destination / "target_cleanup.json", target_cleanup)
                log.write("target_cleanup_finished", result=target_cleanup)
            except Exception as exc:
                cleanup_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; target cleanup: {cleanup_error}" if error else cleanup_error
                log.write("target_cleanup_error", error=cleanup_error)

    windows = network_windows_from_mobile_events(task_dir / "events.jsonl")
    _write_json(destination / "network_capture_windows.json", windows)
    if evidence is not None and evidence_prepared and evidence_result is not None:
        try:
            evidence_result = evidence.finalize(
                capture_path=capture_path,
                network_windows=windows,
                phone_ip=router.phone_ip,
            )
        except Exception as exc:
            evidence_error = f"{type(exc).__name__}: {exc}"
            error = (
                f"{error}; evidence finalize: {evidence_error}"
                if error
                else f"evidence finalize: {evidence_error}"
            )
            log.write("platform_evidence_finalize_error", error=evidence_error)
    capture_bytes = capture_path.stat().st_size if capture_path.is_file() else 0
    capture_header_valid = valid_pcap_header(capture_path)
    task_outcome = task_result.outcome.value if task_result is not None else "not_run"
    platform_evidence_ready = bool(evidence_result and evidence_result.ready)
    valid = (
        not error
        and task_result is not None
        and task_result.successful
        and capture_header_valid
        and bool(windows)
        and all(bool(window.get("task_success")) for window in windows)
    )
    formal_ready = bool(valid and evidence_result and evidence_result.formal_ready)
    result = CollectionResult(
        request.platform,
        request.app_name,
        str(destination.resolve()),
        valid,
        task_outcome,
        capture_bytes,
        capture_header_valid,
        len(windows),
        platform_evidence_ready,
        formal_ready,
        error,
        attribution_mode,
    )
    manifest = {
        "schema_version": 1,
        "storage_policy": "screen-time-single-original-v1",
        "status": "complete" if valid else "failed",
        "collection_task_id": collection_task_id or None,
        "attribution_mode": attribution_mode,
        "traffic_scope": "device" if attribution_mode == "none" else "app_attributed",
        "request": asdict(request),
        "collection_environment": environment,
        "device_serial": serial or None,
        "device_udid": udid or None,
        "target_cleanup_required": target_cleanup_required and target_attempted,
        "resume_environment_from": str(Path(resume_environment_from).resolve()) if resume_environment_from else None,
        "continue_environment_from": str(Path(continue_environment_from).resolve()) if continue_environment_from else None,
        "router": asdict(router),
        "result": asdict(result),
        "platform_evidence": (
            asdict(evidence_result)
            if evidence_result is not None
            else {
                "platform": request.platform,
                "evidence_type": "disabled" if attribution_mode == "none" else "not_available",
                "ready": False,
                "formal_ready": False,
                "errors": [] if attribution_mode == "none" else ["platform evidence adapter is not connected"],
            }
        ),
        "session_isolation": (
            asdict(isolation_result)
            if isolation_result is not None
            else {
                "success": not request.isolate_other_apps,
                "disabled": not request.isolate_other_apps,
            }
        ),
        "cache_cleanup": (
            asdict(cache_cleanup_result)
            if cache_cleanup_result is not None
            else {
                "success": not request.clear_app_cache_before_run,
                "disabled": not request.clear_app_cache_before_run,
            }
        ),
        "artifacts": {
            "capture_pcap": str(capture_path),
            "task_events": str(task_dir / "events.jsonl"),
            "task_result": str(task_dir / "result.json"),
            "screen_evidence": str(task_dir / "screen_evidence.jsonl"),
            "screenshots": str(task_dir / "screenshots"),
            "network_windows": str(destination / "network_capture_windows.json"),
            "validation": str(destination / "collection_validation.json"),
            "session_isolation": str(destination / "session_isolation.json"),
            "cache_cleanup": str(destination / "cache_cleanup.json"),
        },
    }
    manifest_path = destination / "collection_manifest.json"
    _write_json(manifest_path, manifest)
    validation = validate_mobile_collection(destination)
    write_mobile_collection_validation(
        validation, destination / "collection_validation.json"
    )
    result = replace(
        result,
        valid=result.valid and validation.core_valid,
        formal_ready=result.formal_ready and validation.formal_ready,
        collection_ready=result.valid and validation.collection_ready,
    )
    manifest["result"] = asdict(result)
    manifest["status"] = "complete" if result.collection_ready else "failed"
    _write_json(manifest_path, manifest)
    log.write("collection_finished", result=result)
    task_metadata = registered_task.get("metadata", {}) if registered_task else {}
    minimum_monitor_seconds = max(float(task_metadata.get(key) or 0)
                                  for key in ("minimum_monitor_seconds", "minimum_window_seconds"))
    evidence_ready = (
        result.formal_ready if attribution_mode == "app" else result.collection_ready
    )
    counts_toward_task = bool(
        evidence_ready and request.monitor_seconds >= minimum_monitor_seconds
    )
    task_message = result.error
    if evidence_ready and not counts_toward_task:
        task_message = (
            f"validated smoke; payload cleanup automatic; monitor_seconds={request.monitor_seconds:g} "
            f"is below task minimum {minimum_monitor_seconds:g}"
        )
    task_tracking.finish(
        "complete" if evidence_ready else "failed",
        completed_units=1 if counts_toward_task else 0,
        message=task_message,
        details={
            "collection_ready": result.collection_ready,
            "formal_ready": result.formal_ready,
            "attribution_mode": result.attribution_mode,
            "monitor_seconds": request.monitor_seconds,
            "minimum_monitor_seconds": minimum_monitor_seconds,
            "counts_toward_task": counts_toward_task,
            "accepted_windows": (None if any("cannot derive task windows" in error for error in validation.core_errors)
                                 else validation.metrics.get("network_window_count")),
        },
        validation_finished=True,
    )
    return result


def _default_evidence_factory(
    *,
    request: MobileTaskRequest,
    app_id: str,
    out_dir: Path,
    serial: str,
    udid: str,
) -> PlatformEvidence | None:
    if request.platform == "android":
        return AndroidSocketEvidence(
            serial=serial,
            target_package=app_id,
            out_dir=out_dir,
        )
    app = MobileAppCatalog.from_repository().require(Platform.IOS, request.app_name)
    return IosProcessEvidence(
        bundle_id=app.app_id,
        process_name=app.process_name,
        out_dir=out_dir,
        udid=udid,
    )


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_json_value(payload), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
