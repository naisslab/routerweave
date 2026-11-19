"""Independent artifact validation for unified mobile collections."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

from .catalog import MobileAppCatalog
from .capture.router import parse_tcpdump_trailer
from .capture.pcap import (
    iter_decoded_packets,
    valid_pcap_header,
    verified_network_window_id,
)
from .device_ip import validate_router_visible_ip
from .status import Platform
from .task_runtime import network_windows_from_mobile_events


@dataclass(frozen=True, slots=True)
class MobileCollectionValidation:
    run_dir: str
    platform: str
    app_name: str
    core_valid: bool
    formal_ready: bool
    core_errors: tuple[str, ...]
    formal_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    metrics: dict[str, Any]
    attribution_mode: str = "app"
    collection_ready: bool = False


def validate_mobile_collection(run_dir: str | Path) -> MobileCollectionValidation:
    root = Path(run_dir).resolve()
    core_errors: list[str] = []
    formal_errors: list[str] = []
    warnings: list[str] = []
    metrics: dict[str, Any] = {}
    manifest = _read_json(root / "collection_manifest.json", core_errors, "collection manifest")
    if isinstance(manifest.get("request"), dict) and manifest["request"].get("request_kind") == "manual_ground_truth":
        from .manual_ground_truth import validate_manual_ground_truth
        return validate_manual_ground_truth(root, manifest)
    attribution_mode = str(manifest.get("attribution_mode", "app"))
    if attribution_mode not in {"app", "none"}:
        core_errors.append("unknown attribution_mode; expected app or none")
    request = manifest.get("request")
    if not isinstance(request, dict):
        core_errors.append("collection manifest has no request object")
        request = {}
    platform = str(request.get("platform") or "")
    app_name = str(request.get("app_name") or "")
    request_kind = str(request.get("request_kind") or "app_task")
    background_scenario = request_kind == "background_scenario"
    if platform not in {"android", "ios"}:
        core_errors.append("request platform is not android or ios")
    if not app_name:
        core_errors.append("request app_name is missing")

    from ..screen_time_storage import resolve_run_original
    try:
        capture_path = resolve_run_original(root, root / "capture.pcap")
    except (OSError, ValueError, KeyError) as exc:
        core_errors.append(f"invalid original ownership receipt: {exc}")
        capture_path = root / "capture.pcap"
    capture_bytes = capture_path.stat().st_size if capture_path.is_file() else 0
    metrics["capture_bytes"] = capture_bytes
    if not valid_pcap_header(capture_path, allow_pcapng=True) or capture_bytes <= 24:
        core_errors.append("router capture.pcap is missing, empty, or has an invalid header")
    _record_tcpdump_statistics(root, metrics, warnings)

    task_result = _read_json(
        root / "mobile_control" / "result.json", core_errors, "task result"
    )
    if task_result.get("outcome") != "success":
        core_errors.append("mobile task outcome is not success")
    events_path = root / "mobile_control" / "events.jsonl"
    try:
        derived_windows = network_windows_from_mobile_events(events_path)
    except Exception as exc:
        derived_windows = []
        core_errors.append(f"cannot derive task windows: {type(exc).__name__}: {exc}")
    recorded_windows = _read_json(
        root / "network_capture_windows.json",
        core_errors,
        "network windows",
        expected_type=list,
    )
    if not derived_windows:
        core_errors.append("task events contain no complete network window")
    elif any(window.get("task_success") is not True for window in derived_windows):
        core_errors.append("one or more derived task windows did not succeed")
    if recorded_windows != derived_windows:
        core_errors.append("recorded network windows do not match task event timestamps")
    metrics["network_window_count"] = len(derived_windows)
    from ..collection_environment import validate_run_environment
    starts = [w.get("actual", {}).get("start_epoch") for w in derived_windows]
    starts = [value for value in starts if value is not None]
    core_errors.extend(validate_run_environment(
        root, app_name, manifest.get("collection_environment"),
        foreground_start=min(starts) if starts else None))
    if manifest.get("collection_environment") and (
            request.get("isolate_other_apps", True) or request.get("restart_app", True)
            or request.get("clear_app_cache_before_run", False)):
        core_errors.append("supplementary run must retain apps and cache")
    if manifest.get("collection_environment") and not any(
            w.get("task_success") is True and float(w.get("actual", {}).get("duration_s") or 0) >= 1800
            for w in derived_windows):
        core_errors.append("supplementary foreground evidence is shorter than 1800 seconds")

    app = None
    if platform in {"android", "ios"} and app_name and not background_scenario:
        try:
            app = MobileAppCatalog.from_repository().require(Platform(platform), app_name)
        except (KeyError, ValueError) as exc:
            core_errors.append(f"registered app identity cannot be resolved: {exc}")

    if manifest.get("target_cleanup_required"):
        cleanup = _read_json(root / "target_cleanup.json", core_errors, "target cleanup")
        identity = app.app_id if app is not None else None
        remaining = cleanup.get("remaining_processes")
        tasks = cleanup.get("recent_tasks_after")
        if cleanup.get("target_app_id") != identity or cleanup.get("method") != "identity_checked_native_recent_task_removal":
            core_errors.append("target cleanup identity or method does not match")
        if not isinstance(remaining, dict) or set(remaining) != {identity} or remaining.get(identity) != []:
            core_errors.append("target cleanup did not verify process exit")
        if not isinstance(tasks, list) or any(not isinstance(t, dict) or t.get("app_id") == identity for t in tasks):
            core_errors.append("target cleanup did not verify recent task removal")
        before = cleanup.get("recent_tasks_before")
        def task_keys(rows):
            if not isinstance(rows, list) or any(not isinstance(t, dict)
                    or not isinstance(t.get("app_id"), str) or not t.get("app_id")
                    or type(t.get("task_id")) is not int for t in rows):
                return None
            return {(t["task_id"], t["app_id"]) for t in rows if t["app_id"] != identity}
        preserved, after = task_keys(before), task_keys(tasks)
        if preserved is None or after is None or not preserved.issubset(after):
            core_errors.append("target cleanup did not preserve other recent tasks")

    if request.get("isolate_other_apps", True):
        isolation = _read_json(
            root / "session_isolation.json",
            core_errors,
            "session isolation",
        )
        if isolation.get("success") is not True:
            core_errors.append("session isolation did not complete successfully")
        if isolation.get("platform") != platform:
            core_errors.append("session isolation platform does not match the task")
        if app is not None and isolation.get("target_app_id") != app.app_id:
            core_errors.append("session isolation target does not match the registered app")
        if isolation.get("method") != "app_switcher_swipe_up":
            core_errors.append("session isolation did not use app-switcher upward swipes")
        if isolation.get("command_status") != "accepted":
            core_errors.append("session isolation command was not accepted")
        preserved_labels = tuple(request.get("preserve_recent_app_labels") or ())
        if preserved_labels:
            if isolation.get("preservation_verified") is not True:
                core_errors.append("session isolation did not verify preserved app cards")
            if tuple(isolation.get("preserved_app_labels") or ()) != preserved_labels:
                core_errors.append("session isolation preservation allowlist does not match the task")
        else:
            if isolation.get("empty_verified") is not True:
                core_errors.append("session isolation did not verify an empty app switcher")
            if isolation.get("remaining_cards") != 0:
                core_errors.append("session isolation reports remaining app cards")
        evidence = isolation.get("evidence")
        if not isinstance(evidence, dict):
            core_errors.append("session isolation has no gesture evidence")
            evidence = {}
        if evidence.get("method") != "app_switcher_swipe_up":
            core_errors.append("session isolation evidence has the wrong method")
        if platform == "ios" and evidence.get("entry_method") != (
            "assistivetouch_system_app_switcher"
        ):
            core_errors.append("iOS session isolation did not use AssistiveTouch App Switcher")
        metrics["session_isolation_swipes"] = int(
            isolation.get("swipes_attempted") or 0
        )

    if request.get("clear_app_cache_before_run", False):
        cache_cleanup = _read_json(
            root / "cache_cleanup.json",
            core_errors,
            "target app cache cleanup",
        )
        if platform != "android":
            core_errors.append("target app cache cleanup was requested for a non-Android task")
        if cache_cleanup.get("success") is not True:
            core_errors.append("target app cache cleanup did not complete successfully")
        if cache_cleanup.get("platform") != platform:
            core_errors.append("target app cache cleanup platform does not match the task")
        if app is not None and cache_cleanup.get("target_app_id") != app.app_id:
            core_errors.append("target app cache cleanup target does not match the registry")
        if cache_cleanup.get("method") != "external_media_cache_paths":
            core_errors.append("target app cache cleanup did not use allowlisted media-cache paths")
        if cache_cleanup.get("postcondition_verified") is not True:
            core_errors.append("target app cache cleanup postcondition was not verified")
        evidence = cache_cleanup.get("evidence")
        if not isinstance(evidence, dict):
            core_errors.append("target app cache cleanup has no evidence")
            evidence = {}
        metrics["cache_before_bytes"] = _nonnegative_int(
            evidence.get("before_total_cache_bytes")
        )
        metrics["cache_after_bytes"] = _nonnegative_int(
            evidence.get("after_total_cache_bytes")
        )

    if attribution_mode == "none":
        if background_scenario:
            _validate_background_scenario(root, request, derived_windows, core_errors, metrics)
        _validate_device_capture(capture_path, manifest, derived_windows, core_errors, metrics)
        runtime_result = manifest.get("result")
        if isinstance(runtime_result, dict) and runtime_result.get("error"):
            core_errors.append("collection runtime error: " + str(runtime_result["error"]))
        core_errors = _unique(core_errors)
        return MobileCollectionValidation(
            str(root), platform, app_name, not core_errors, False,
            tuple(core_errors),
            ("app attribution was explicitly disabled; not an app-attributed sample",),
            tuple(_unique([
                *warnings,
                "Device traffic can include VPN and background traffic; app_name labels behavior only.",
            ])),
            metrics, attribution_mode, not core_errors,
        )

    evidence_root = root / "platform_evidence"
    evidence_filename = (
        "android_socket_evidence.json" if platform == "android" else "ios_process_evidence.json"
    )
    evidence = _read_json(
        evidence_root / evidence_filename,
        formal_errors,
        "platform evidence result",
    )
    if evidence.get("platform") != platform:
        formal_errors.append("platform evidence result has the wrong platform")
    if evidence.get("ready") is not True:
        formal_errors.append("platform evidence is not ready")
    if evidence.get("formal_ready") is not True:
        formal_errors.append("platform evidence did not pass its formal readiness checks")
    for item in evidence.get("errors", []) if isinstance(evidence.get("errors"), list) else []:
        formal_errors.append(f"platform evidence error: {item}")

    summary = _read_json(
        evidence_root / "packet_attribution_summary.json",
        formal_errors,
        "packet attribution summary",
    )
    target_packets = _nonnegative_int(summary.get("target_packets"))
    target_window_packets = _nonnegative_int(summary.get("target_window_packets"))
    metrics["target_packets"] = target_packets
    metrics["target_window_packets"] = target_window_packets
    if target_packets <= 0:
        formal_errors.append("no packets were attributed to the target app")
    if target_window_packets <= 0:
        formal_errors.append("no target-app packets fall inside a successful task window")
    for item in (
        summary.get("formal_readiness_failures", [])
        if isinstance(summary.get("formal_readiness_failures"), list)
        else []
    ):
        formal_errors.append(f"attribution readiness failure: {item}")

    attribution_rows = _jsonl_rows(
        evidence_root / "packet_attribution.jsonl",
        formal_errors,
        "packet attribution",
    )
    metrics["packet_attribution_rows"] = attribution_rows
    if attribution_rows <= 0:
        formal_errors.append("packet attribution artifact contains no rows")
    _read_json(
        evidence_root / "packet_attribution_windows_summary.json",
        formal_errors,
        "packet attribution window summary",
        expected_type=list,
    )
    export_manifest = _read_json(
        evidence_root / "app_attributed_packets_manifest.json",
        formal_errors,
        "app-attributed packet manifest",
    )
    exported_rows = _nonnegative_int(export_manifest.get("rows_written"))
    metrics["app_attributed_rows"] = exported_rows
    if exported_rows <= 0:
        formal_errors.append("app-attributed packet export contains no rows")
    csv_files = sorted((evidence_root / "app_attributed_packets").glob("*.csv"))
    if len(csv_files) != 1:
        formal_errors.append("expected exactly one target-app packet CSV")
    else:
        actual_csv_rows = _csv_rows(csv_files[0], formal_errors)
        metrics["app_attributed_csv_rows"] = actual_csv_rows
        if actual_csv_rows != exported_rows:
            formal_errors.append("app-attributed CSV row count does not match its manifest")

    if app is not None:
        if export_manifest.get("target_package") != app.app_id:
            formal_errors.append("app-attributed export identity does not match the registry")
        if platform == "android":
            _validate_android_evidence(evidence_root, evidence, app.app_id, formal_errors)
        else:
            _validate_ios_evidence(evidence_root, evidence, app.app_id, app.process_name, formal_errors)

    manifest_result = manifest.get("result")
    if isinstance(manifest_result, dict):
        if manifest_result.get("valid") is not True and not core_errors:
            warnings.append("manifest marks the run invalid although core artifacts now validate")
        if manifest_result.get("formal_ready") is not True and not formal_errors and not core_errors:
            warnings.append("manifest does not mark a formally reusable run as ready")

    core_errors = _unique(core_errors)
    formal_errors = _unique(formal_errors)
    warnings = _unique(warnings)
    core_valid = not core_errors
    formal_ready = core_valid and not formal_errors
    return MobileCollectionValidation(
        str(root),
        platform,
        app_name,
        core_valid,
        formal_ready,
        tuple(core_errors),
        tuple(formal_errors),
        tuple(warnings),
        metrics,
        attribution_mode,
        formal_ready,
    )


def _record_tcpdump_statistics(
    root: Path,
    metrics: dict[str, Any],
    warnings: list[str],
) -> None:
    """Surface router-side loss without failing historical runs that lack a trailer."""

    log = root / "capture.pcap.tcpdump.stderr.log"
    text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
    statistics = parse_tcpdump_trailer(text)
    metrics["tcpdump_statistics"] = statistics
    dropped = statistics["kernel_dropped"]
    if dropped is None:
        warnings.append(
            "tcpdump final statistics are missing; router-side packet loss is unverified"
        )
    elif dropped > 0:
        warnings.append(f"router tcpdump reported {dropped} packets dropped by kernel")


def _validate_device_capture(
    capture_path: Path,
    manifest: dict[str, Any],
    windows: list[dict[str, Any]],
    errors: list[str],
    metrics: dict[str, Any],
) -> None:
    router = manifest.get("router")
    phone_ip = str(router.get("phone_ip", "")) if isinstance(router, dict) else ""
    try:
        validate_router_visible_ip(phone_ip)
    except ValueError as exc:
        errors.append(f"device capture has no valid router-visible phone IP: {exc}")
        return
    metrics.update(device_ip=phone_ip, traffic_scope="device", captured_ip_packets=0,
                   device_packets=0, device_bytes=0, device_window_packets=0)
    try:
        for packet in iter_decoded_packets(capture_path, ip_only=True):
            metrics["captured_ip_packets"] += 1
            if phone_ip not in {packet["src_ip"], packet["dst_ip"]}:
                continue
            metrics["device_packets"] += 1
            metrics["device_bytes"] += int(packet["length"])
            if verified_network_window_id(float(packet["ts_epoch"]), windows) is not None:
                metrics["device_window_packets"] += 1
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(f"cannot decode complete device capture: {type(exc).__name__}: {exc}")
    if metrics["device_packets"] <= 0:
        errors.append("capture has no IP packets for the recorded phone IP")
    if metrics["device_window_packets"] <= 0:
        errors.append("no device IP packets fall inside a successful task window")


def _validate_background_scenario(
    root: Path,
    request: dict[str, Any],
    windows: list[dict[str, Any]],
    errors: list[str],
    metrics: dict[str, Any],
) -> None:
    scenario = str(request.get("scenario") or "")
    if request.get("platform") != "ios":
        errors.append("background scenario collection currently requires iOS")
    if scenario not in {"home_screen_idle", "idle_screen_off"}:
        errors.append("unknown background scenario")
    if request.get("app_name") != scenario:
        errors.append("background scenario app_name must equal the scenario label")
    if request.get("isolate_other_apps") is not True:
        errors.append("background scenario did not require prior app isolation")
    for required in ("request.effective.json", "compiled_task.json", "state_samples.jsonl"):
        if not (root / "mobile_control" / required).is_file():
            errors.append(f"background scenario artifact is missing: mobile_control/{required}")
    state_path = root / "mobile_control" / "state_samples.jsonl"
    samples: list[dict[str, Any]] = []
    if state_path.is_file():
        try:
            samples = [
                json.loads(line)
                for line in state_path.read_text(encoding="utf-8-sig").splitlines()
                if line.strip()
            ]
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot read background state samples: {type(exc).__name__}: {exc}")
    monitored = [row for row in samples if row.get("phase") == "monitor"]
    if len(monitored) < 2:
        errors.append("background scenario has fewer than two monitored state samples")
    if any(row.get("scenario") != scenario or row.get("matches") is not True for row in monitored):
        errors.append("background scenario contains an unverified monitored state")
    if scenario == "idle_screen_off" and any(row.get("locked") is not True for row in monitored):
        errors.append("screen-off scenario was not locked throughout monitoring")
    if scenario == "home_screen_idle" and any(
        row.get("locked") is not False
        or row.get("active_bundle_id") != "com.apple.springboard"
        for row in monitored
    ):
        errors.append("home-idle scenario did not remain on unlocked SpringBoard")
    monitor_windows = [
        row for row in windows
        if isinstance(row.get("actual"), dict)
        and row["actual"].get("step_id") == "monitor-active-state"
    ]
    if len(monitor_windows) != 1:
        errors.append("background scenario must contain one monitor-active-state window")
    metrics["background_scenario"] = scenario
    metrics["background_state_samples"] = len(monitored)


def write_mobile_collection_validation(
    validation: MobileCollectionValidation, path: str | Path
) -> None:
    Path(path).write_text(
        json.dumps(asdict(validation), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _validate_android_evidence(
    root: Path,
    evidence: dict[str, Any],
    app_id: str,
    errors: list[str],
) -> None:
    mapping = _read_json(root / "uid_packages.json", errors, "Android UID map")
    metrics = evidence.get("metrics") if isinstance(evidence.get("metrics"), dict) else {}
    target_uid = metrics.get("target_uid")
    packages = mapping.get(str(target_uid), []) if isinstance(mapping, dict) else []
    if app_id not in packages:
        errors.append("Android target package is absent from its recorded UID mapping")
    if metrics.get("target_uid_unique") is not True:
        errors.append("Android target UID is not unique to the target package")
    if _jsonl_rows(root / "socket_samples.jsonl", errors, "Android socket samples") <= 0:
        errors.append("Android socket evidence contains no samples")


def _validate_ios_evidence(
    root: Path,
    evidence: dict[str, Any],
    app_id: str,
    process_name: str,
    errors: list[str],
) -> None:
    metrics = evidence.get("metrics") if isinstance(evidence.get("metrics"), dict) else {}
    if metrics.get("bundle_id") != app_id:
        errors.append("iOS process evidence bundle ID does not match the registry")
    if metrics.get("process_name") != process_name:
        errors.append("iOS process evidence process name does not match the registry")
    from ..screen_time_storage import resolve_run_original
    process_pcap = resolve_run_original(root.parent if root.name == 'platform_evidence' else root,
                                       root / f"process-{_safe_label(process_name)}.pcap")
    if not valid_pcap_header(process_pcap) or process_pcap.stat().st_size <= 24:
        errors.append("iOS process-scoped pcap is missing, empty, or invalid")


def _read_json(
    path: Path,
    errors: list[str],
    label: str,
    *,
    expected_type: type[dict] | type[list] = dict,
) -> dict[str, Any] | list[Any]:
    if not path.is_file():
        errors.append(f"{label} is missing: {path.name}")
        return expected_type()
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label} is unreadable: {type(exc).__name__}: {exc}")
        return expected_type()
    if not isinstance(value, expected_type):
        errors.append(f"{label} has an invalid JSON root; expected {expected_type.__name__}")
        return expected_type()
    return value


def _jsonl_rows(path: Path, errors: list[str], label: str) -> int:
    if not path.is_file():
        errors.append(f"{label} is missing: {path.name}")
        return 0
    count = 0
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError(f"line {line_number} is not an object")
                count += 1
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{label} is unreadable: {type(exc).__name__}: {exc}")
        return 0
    return count


def _csv_rows(path: Path, errors: list[str]) -> int:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return sum(1 for _ in csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        errors.append(f"app-attributed CSV is unreadable: {type(exc).__name__}: {exc}")
        return 0


def _nonnegative_int(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


def _safe_label(value: str) -> str:
    return "".join(char if char.isalnum() or char in "_.-" else "_" for char in value).strip("._-") or "process"


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
