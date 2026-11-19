"""Generic Windows desktop ground-truth and router-capture runner."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import threading
import time
from dataclasses import asdict
from datetime import datetime
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Any

from .automation import ActivityRunner, WindowsDesktopDriver, load_plan, prepared_edge_profile_dir, select_plan_window
from .config import LoggerConfig
from .controller import SessionController
from .models import NetworkCaptureConfig
from .network_capture import find_default_router_key_path, guess_default_device_ip
from .platforms import create_snapshotter
from .validation import validate_windows_run
from .process_attribution import OWNERSHIP_POLICY, process_names
from collection.runtime.registry.tasks import CollectionTaskRun, require_collection_task


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_PLAN = REPO_ROOT / "configs" / "plans" / "windows_behavior.json"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expand_path(value: str) -> str:
    return os.path.expandvars(os.path.expanduser(value)) if value else ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Record Windows foreground activity while optionally executing a behavior plan and streaming router tcpdump."
    )
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--out", default="")
    parser.add_argument("--duration-seconds", type=float, default=0)
    parser.add_argument("--sample-interval-ms", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=-1)
    parser.add_argument("--category-id", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--existing-edge-profile", default="",
                        help="Attach to an already enabled local Edge profile; never launch or copy it.")
    parser.add_argument("--use-existing-edge", action="store_true",
                        help="Attach to the current default Edge user-data directory.")
    parser.add_argument("--existing-edge-tab-id", default="",
                        help="Pin a CDP target ID when more than one tab matches the service.")
    parser.add_argument("--native-control-dir", default="", help="Reuse an authorized native Computer Use consumer")
    parser.add_argument("--background-scenario", choices=['desktop_idle', 'locked_session'], default='')
    parser.add_argument("--browser-control-dir", default="",
                        help="Reuse an already authorized browser-use consumer; no new debugger attachment.")
    parser.add_argument("--background-control-only", action="store_true",
                        help="Exploratory browser control only; no foreground or network collection claim.")
    parser.add_argument("--allow-browsing-article-redirects", action="store_true")
    parser.add_argument("--tolerate-foreground-interruptions", action="store_true",
                        help="Keep checking a pinned target during foreground switches; count only Edge foreground samples.")
    parser.add_argument("--session-seconds", type=float, default=0)
    parser.add_argument("--minimum-accepted-seconds", type=float, default=0)
    parser.add_argument("--single-session", action="store_true")
    parser.add_argument("--resume-environment-from", default="")
    parser.add_argument("--continue-environment-from", default="")
    parser.add_argument("--environment-operator", choices=("human", "agent"), default="human")
    parser.add_argument("--require-media-probe", action="store_true")
    parser.add_argument("--media-poll-seconds", type=float, default=0)
    parser.add_argument("--no-automation", action="store_true", help="Record a manual Windows session without synthetic input.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the effective plan without controlling Windows or the router.")
    parser.add_argument("--enable-router-capture", action="store_true")
    parser.add_argument("--router-host", default=os.environ.get("ROUTERWEAVE_ROUTER_HOST", ""))
    parser.add_argument("--router-port", type=int, default=22)
    parser.add_argument("--router-user", default="root")
    parser.add_argument("--router-interface", default="br-lan")
    parser.add_argument("--router-identity", default=find_default_router_key_path())
    parser.add_argument("--device-ip", default="")
    parser.add_argument("--bpf-filter", default="")
    parser.add_argument("--snaplen-bytes", type=int, default=262144)
    parser.add_argument("--process-attribution", action="store_true")
    parser.add_argument("--rotation-size-mb", type=int, default=256)
    parser.add_argument("--collection-task-id", required=True)
    return parser


def _manual_window(
    run_dir: Path, started: float, ended: float, plan: dict[str, Any],
) -> None:
    defaults = plan["defaults"]
    _write_jsonl(
        run_dir / "events.jsonl",
        {"timestamp": datetime.now().astimezone().isoformat(), "epoch": started, "event": "manual_session_start"},
    )
    _write_jsonl(
        run_dir / "events.jsonl",
        {"timestamp": datetime.now().astimezone().isoformat(), "epoch": ended, "event": "manual_session_stop"},
    )
    _write_jsonl(
        run_dir / "usage_windows.jsonl",
        {
            "schema_version": "windows-usage-window-v1",
            "platform": "windows",
            "window_id": "manual-session",
            "category_id": "manual",
            "category": "Manual Windows activity",
            "target_name": "operator_controlled",
            "command": "manual",
            "quality_tier": "manual_unverified",
            "started_epoch": started,
            "ended_epoch": ended,
            "duration_seconds": round(max(0.0, ended - started), 3),
            "analysis_started_epoch": started - float(defaults.get("pre_roll_seconds", 0)),
            "analysis_ended_epoch": ended + float(defaults.get("post_roll_seconds", 0)),
            "pre_roll_seconds": float(defaults.get("pre_roll_seconds", 0)),
            "post_roll_seconds": float(defaults.get("post_roll_seconds", 0)),
            "action_count": 0,
            "status": "accepted",
            "reasons": [],
        },
    )


def reconcile_foreground_evidence(
    run_dir: Path,
    ground_truth_csv: Path,
    *,
    capture_ended_epoch: float,
    minimum_ratio: float,
) -> dict[str, Any]:
    samples: list[tuple[float, str]] = []
    with ground_truth_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            samples.append((int(row["timestamp_ms"]) / 1000.0, str(row.get("foreground_app", ""))))
    windows_path = run_dir / "usage_windows.jsonl"
    windows = []
    with windows_path.open("r", encoding="utf-8-sig") as handle:
        for raw in handle:
            if raw.strip():
                windows.append(json.loads(raw))

    accepted = 0
    failed = 0
    for window in windows:
        started = float(window["started_epoch"])
        ended = float(window["ended_epoch"])
        analysis_ended = float(window.get("analysis_ended_epoch", ended))
        observed = [name for timestamp, name in samples if started <= timestamp <= min(ended, capture_ended_epoch)]
        expected = PureWindowsPath(str(window.get("command", ""))).name.lower()
        observed_names = [PureWindowsPath(name).name.lower() for name in observed]
        matches = sum(1 for name in observed_names if name == expected)
        ratio = matches / len(observed_names) if observed_names else 0.0
        reasons = list(window.get("reasons") or [])
        if ended > capture_ended_epoch + 0.5:
            reasons.append("outside_ground_truth_capture")
        if analysis_ended > capture_ended_epoch + 0.5:
            reasons.append("analysis_window_outside_capture")
        if not observed_names:
            reasons.append("no_foreground_samples")
        elif ratio < minimum_ratio:
            reasons.append("foreground_mismatch")
        window["foreground_evidence"] = {
            "expected_process": expected,
            "sample_count": len(observed_names),
            "match_count": matches,
            "match_ratio": round(ratio, 6),
            "observed_top": Counter(observed_names).most_common(5),
            "minimum_ratio": minimum_ratio,
        }
        window["reasons"] = list(dict.fromkeys(reasons))
        window["status"] = "accepted" if not window["reasons"] else "failed"
        if window["status"] == "accepted":
            accepted += 1
        else:
            failed += 1
    with windows_path.open("w", encoding="utf-8", newline="\n") as handle:
        for window in windows:
            handle.write(json.dumps(window, ensure_ascii=False) + "\n")
    return {"windows": len(windows), "accepted_windows": accepted, "failed_windows": failed}


def main(argv: list[str] | None = None, *, network_capture_factory=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from ..collection_environment import environment_recipe, prepare_environment, resume_environment
    registered_environment_task = require_collection_task(args.collection_task_id, kind="windows", platform="windows")
    from ..collection_environment import CONTINUATION_PROFILE, continuation_source, continue_environment
    if args.resume_environment_from and args.continue_environment_from:
        parser.error("Recovery and continuation cannot be combined")
    environment = environment_recipe(registered_environment_task, args.target_name,
        profile=CONTINUATION_PROFILE if args.continue_environment_from else None)
    if args.continue_environment_from:
        if environment is None:
            parser.error("Continuation requires a registered supplementary target")
        continuation_source(Path(args.continue_environment_from), environment)
    if args.resume_environment_from and environment is None:
        parser.error("Environment recovery requires a registered supplementary target")
    if environment is not None:
        expected_category = {"music": "music_audio", "browsing": "web_browsing", "long_video": "long_form_video",
                             "live_stream": "live_streaming"}.get(registered_environment_task["category"], registered_environment_task["category"])
        if (args.category_id != expected_category or not args.single_session
                or args.session_seconds < 1800 or args.minimum_accepted_seconds < 1800
                or not args.enable_router_capture or args.no_automation
                or not (args.native_control_dir or (
                    (args.existing_edge_profile or args.use_existing_edge) and args.existing_edge_tab_id))
                or args.background_control_only):
            parser.error("Uncleared-background collection requires a registered target, 1800-second foreground window, router capture and the existing native transport or a separate pinned Edge tab")
    if args.use_existing_edge:
        if args.existing_edge_profile:
            parser.error("--use-existing-edge and --existing-edge-profile are alternatives")
        if not os.environ.get("LOCALAPPDATA"):
            parser.error("--use-existing-edge requires LOCALAPPDATA")
        args.existing_edge_profile = str(Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / "User Data")
    if args.existing_edge_tab_id and not args.existing_edge_profile:
        parser.error("--existing-edge-tab-id requires existing Edge attachment")
    if args.browser_control_dir and (not args.existing_edge_profile or not args.existing_edge_tab_id
                                    or args.no_automation):
        parser.error("Browser-use transport requires an explicit existing Edge profile and pinned tab")
    if args.native_control_dir and (args.browser_control_dir or args.existing_edge_profile
                                   or args.no_automation):
        parser.error("Native control is exclusive with browser attachment and manual capture")
    if args.sample_interval_ms < 200:
        parser.error("--sample-interval-ms must be at least 200")
    if args.snaplen_bytes < 64:
        parser.error("--snaplen-bytes must be at least 64")
    if args.rotation_size_mb <= 0:
        parser.error("--rotation-size-mb must be positive")
    if args.process_attribution and (not args.enable_router_capture or args.snaplen_bytes < 262144):
        parser.error("Process attribution requires full-packet router capture")

    plan_path = Path(args.plan).resolve()
    plan = load_plan(plan_path)
    targeted = bool(
        args.category_id or args.target_name or args.session_seconds
        or args.minimum_accepted_seconds or args.single_session
        or args.require_media_probe or args.media_poll_seconds
    )
    task_metadata = registered_environment_task["metadata"]
    minimum_window = float(task_metadata.get("minimum_window_seconds", 0))
    if task_metadata.get("collection_scope") == "single_app":
        categories = {"music": "music_audio", "browsing": "web_browsing",
                      "long_video": "long_form_video", "live_stream": "live_streaming"}
        category = registered_environment_task["category"]
        if (not args.target_name or args.category_id != categories.get(category, category)
                or not args.single_session or not args.enable_router_capture
                or min(args.minimum_accepted_seconds, args.session_seconds) < minimum_window):
            parser.error("Single-app collection requires the registered category, one named target, "
                         f"router capture and a verified window of at least {minimum_window:g} seconds")
    if targeted and args.no_automation:
        parser.error("targeted plan options require automation")
    if args.existing_edge_profile and (not targeted or args.no_automation):
        parser.error("--existing-edge-profile requires a targeted automated session")
    if args.collection_task_id == "windows-browser-control-smoke" and (
        not targeted or not args.existing_edge_profile or args.minimum_accepted_seconds < 10
    ):
        parser.error("Existing-browser smoke requires targeted attachment and at least 10 accepted seconds")
    if args.collection_task_id == "windows-native-control-smoke" and (
        not targeted or not args.native_control_dir or args.minimum_accepted_seconds < 10
    ):
        parser.error("Native smoke requires targeted native control and at least 10 accepted seconds")
    if args.background_control_only and (args.collection_task_id != "windows-browser-control-smoke"
                                        or args.enable_router_capture):
        parser.error("Background control only supports the exploratory browser smoke task without router capture")
    if args.tolerate_foreground_interruptions and (not (args.existing_edge_profile or args.native_control_dir) or args.background_control_only
                                                   or args.collection_task_id not in {
                                                       "windows-native-control-smoke", "windows-browser-control-smoke"} and environment is None):
        parser.error("Foreground interruption tolerance requires a targeted existing Edge smoke or coverage run")
    if targeted:
        if not args.single_session:
            parser.error("targeted collection requires --single-session")
        try:
            plan = select_plan_window(
                plan, category_id=args.category_id, target_name=args.target_name,
                session_seconds=args.session_seconds,
                minimum_accepted_seconds=args.minimum_accepted_seconds,
                foreground_match_min_ratio=0.0 if args.tolerate_foreground_interruptions else 0.9,
                require_media_probe=args.require_media_probe,
                media_poll_seconds=args.media_poll_seconds,
            )
        except ValueError as exc:
            parser.error(str(exc))
    if args.allow_browsing_article_redirects:
        if args.category_id != 'web_browsing' or not args.browser_control_dir or not targeted:
            parser.error('Article redirects require targeted browser-use browsing')
        plan['categories'][0]['targets'][0]['semantic_binding']['allow_external_article_redirects'] = True
    if args.background_scenario or args.collection_task_id == 'windows-background-parity':
        if (args.collection_task_id not in {'windows-background-parity', 'windows-workstation-traffic-probe'}
                or not args.background_scenario or not args.no_automation or targeted
                or args.existing_edge_profile or args.native_control_dir
                or not args.enable_router_capture or args.snaplen_bytes < 262144):
            parser.error('Background scenarios require read-only state monitoring and full device router capture')
        if args.collection_task_id == 'windows-background-parity' and args.duration_seconds < 1802:
            parser.error('Formal background capture must allow at least 1800 verified state seconds')
        args.process_attribution = True
    duration_seconds = args.duration_seconds or float(plan["defaults"]["duration_seconds"])
    if environment is not None:
        # Foreground duration is unchanged; reserve a bounded preparation allowance.
        duration_seconds = max(duration_seconds, args.session_seconds + 900)
    if duration_seconds <= 0:
        parser.error("Effective duration must be positive")
    if targeted and duration_seconds < args.session_seconds:
        parser.error("capture duration must be at least the targeted session duration")
    seed = args.seed if args.seed >= 0 else int(plan.get("seed", 20260820))
    native_target = None
    if args.native_control_dir:
        native_target = plan["categories"][0]["targets"][0]
        from .native_control import native_executable
        native_executable(native_target)
    elif any(t.get("native_binding") for c in plan["categories"] for t in c["targets"]) and targeted:
        parser.error("Native targets require the authorized native control transport")

    if args.collection_task_id == "windows-browser-control-smoke" and args.category_id == "web_browsing":
        from .semantic import require_browsing_interactions
        try:
            for category in plan["categories"]:
                for target in category.get("targets", []):
                    if target.get("name") == args.target_name:
                        require_browsing_interactions(target)
        except ValueError as exc:
            parser.error(str(exc))

    if args.dry_run:
        print(
            json.dumps(
                {
                    "ok": True,
                    "collection_environment": environment,
                    "platform": "windows",
                    "plan": str(plan_path),
                    "duration_seconds": duration_seconds,
                    "snaplen_bytes": args.snaplen_bytes,
                    "process_attribution": args.process_attribution,
                    "seed": seed,
                    "automation_enabled": not args.no_automation,
                    "router_capture_enabled": args.enable_router_capture,
                    "category_id": args.category_id,
                    "target_name": args.target_name,
                    "session_seconds": args.session_seconds,
                    "minimum_accepted_seconds": args.minimum_accepted_seconds,
                    "single_session": args.single_session,
                    "require_media_probe": args.require_media_probe,
                    "media_poll_seconds": args.media_poll_seconds,
                    "browser_profile_scope": "existing_operator" if args.existing_edge_profile else "prepared_persistent" if targeted else "run_local",
                    "existing_edge_profile": _expand_path(args.existing_edge_profile),
                    "existing_edge_tab_id": args.existing_edge_tab_id,
                },
                indent=2,
            )
        )
        return 0

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.out).resolve() if args.out else (REPO_ROOT / "runs" / f"windows-capture-{timestamp}")
    if any((run_dir / name).exists() for name in ('windows_capture_manifest.json', 'screen_time_originals.json')):
        parser.error('Collection requires a fresh run directory; existing evidence is preserved')
    if environment is not None and run_dir.exists() and any(run_dir.iterdir()):
        parser.error("Supplementary collection requires a new empty run directory")
    run_dir.mkdir(parents=True, exist_ok=True)
    plan = {**plan, "collection_task_id": args.collection_task_id}
    _write_json(run_dir / "effective_plan.json", plan)
    task_tracking = CollectionTaskRun(run_dir, args.collection_task_id)
    task_tracking.start(
        kind="windows",
        platform="windows",
        title=str(plan.get("name") or plan.get("behavior_label") or run_dir.name),
    )

    device_ip = args.device_ip.strip()
    if args.enable_router_capture and not device_ip and not args.bpf_filter.strip():
        device_ip = guess_default_device_ip(expected_gateway=args.router_host)
    bpf_filter = args.bpf_filter.strip()
    if args.enable_router_capture and not bpf_filter:
        if not device_ip:
            parser.error("Router capture requires --device-ip or --bpf-filter; automatic Windows IP detection failed.")
        bpf_filter = f"host {device_ip} and not (host {args.router_host} and tcp port {args.router_port})"

    manifest: dict[str, Any] = {
        "schema_version": "windows-capture-manifest-v1",
        "collection_task_id": args.collection_task_id,
        "status": "running",
        "ok": False,
        "run_dir": str(run_dir),
        "plan_path": str(plan_path),
        "collection_environment": environment,
        "plan_sha256": _sha256(plan_path),
        "resume_environment_from": str(Path(args.resume_environment_from).resolve()) if args.resume_environment_from else None,
        "continue_environment_from": str(Path(args.continue_environment_from).resolve()) if args.continue_environment_from else None,
        "duration_seconds": duration_seconds,
        "sample_interval_ms": args.sample_interval_ms,
        "seed": seed,
        "automation_enabled": not args.no_automation,
        "router_capture_enabled": args.enable_router_capture,
        "category_id": args.category_id,
        "target_name": args.target_name,
        "session_seconds": args.session_seconds,
        "minimum_accepted_seconds": args.minimum_accepted_seconds,
        "single_session": args.single_session,
        "require_media_probe": args.require_media_probe,
        "media_poll_seconds": args.media_poll_seconds,
        "browser_profile_scope": "native_window" if native_target else "existing_operator" if args.existing_edge_profile else "prepared_persistent" if targeted else "run_local",
        "existing_edge_profile": _expand_path(args.existing_edge_profile),
        "existing_edge_tab_id": args.existing_edge_tab_id,
        "browser_control_transport": "authorized_sky" if native_target else "authorized_browser_use" if args.browser_control_dir else "cdp",
        "background_control_only": args.background_control_only,
        "tolerate_foreground_interruptions": args.tolerate_foreground_interruptions,
        "allow_browsing_article_redirects": args.allow_browsing_article_redirects,
        "target_tab_focus_required": bool(targeted and args.existing_edge_profile
                                          and args.collection_task_id != "windows-browser-control-smoke"),
        "native_target": native_target.get("native_binding") if native_target else None,
        "background_scenario": ({'name': args.background_scenario, 'minimum_idle_seconds': 60,
            'minimum_accepted_seconds': 1800 if args.collection_task_id == 'windows-background-parity' else 10}
            if args.background_scenario else None),
        "process_attribution": {"enabled": args.process_attribution, "target_process": "" if args.background_scenario else native_target["command"] if native_target else "msedge.exe",
                                "policy": OWNERSHIP_POLICY,
                                "excluded_process_roots": sorted(process_names(plan.get("excluded_process_roots", []))),
                                "scope": "workstation_device" if args.background_scenario else "native_executable" if native_target else "browser_profile" if not args.no_automation else "process_name_probe"},
        "minimum_foreground_seconds": minimum_window,
        "router": {
            "host": args.router_host,
            "port": args.router_port,
            "user": args.router_user,
            "interface": args.router_interface,
            "device_ip": device_ip,
            "bpf_filter": bpf_filter,
            "snaplen_bytes": args.snaplen_bytes,
            "require_full_packets": args.snaplen_bytes >= 262144,
            "payload_policy": ("full_packet_capture" if args.snaplen_bytes >= 262144 else "snaplen_truncated_capture"),
        },
        "started_epoch": time.time(),
    }
    _write_json(run_dir / "windows_capture_manifest.json", manifest)

    stop_event = threading.Event()
    automation: ActivityRunner | None = None
    automation_thread: threading.Thread | None = None
    session_dir: Path | None = None
    network_result = None
    started_epoch = time.time()
    capture_ended_epoch = 0.0
    background_recorder = None
    if args.background_scenario:
        from .background import BackgroundStateRecorder
        background_recorder = BackgroundStateRecorder(run_dir, args.background_scenario,
            manifest['background_scenario']['minimum_accepted_seconds'], 60, stop_event)
        _write_jsonl(run_dir/'events.jsonl', {'event_type': 'background_state_monitor_started',
            'epoch': time.time(), 'scenario': args.background_scenario})
    error = ""
    ownership_recorder = None

    try:
        if args.existing_edge_profile and not args.browser_control_dir:
            from .media_probe import wait_for_devtools_port
            manifest["browser_attachment"] = {"status": "waiting_for_approval", "timeout_seconds": 120}
            _write_json(run_dir / "windows_capture_manifest.json", manifest)
            print("edge_attachment=waiting_for_approval; timeout_seconds=120; capture_not_started=true", flush=True)
            wait_for_devtools_port(Path(_expand_path(args.existing_edge_profile)).resolve(), 120)
            manifest["browser_attachment"]["status"] = "connected"
            manifest["browser_attachment"]["connected_epoch"] = time.time()
            _write_json(run_dir / "windows_capture_manifest.json", manifest)
            print("edge_attachment=connected; reusing_connection=true", flush=True)
        started_epoch = time.time()
        if not args.no_automation:
            if args.native_control_dir:
                from .native_control import NativeUseDesktopDriver
                driver = NativeUseDesktopDriver(Path(args.native_control_dir), native_target)
                manifest["native_attachment"] = {"status": "connected",
                    "transport": "authorized_sky", "session_id": driver.transport.session["session_id"],
                    "window_id": driver.transport.session["window_id"]}
                _write_json(run_dir / "windows_capture_manifest.json", manifest)
            elif args.browser_control_dir:
                from .browser_control import BrowserUseDesktopDriver
                driver = BrowserUseDesktopDriver(
                    Path(args.browser_control_dir),
                    edge_profile_dir=Path(_expand_path(args.existing_edge_profile)).resolve(),
                    tab_id=args.existing_edge_tab_id,
                    tolerate_foreground_interruptions=args.tolerate_foreground_interruptions,
                    background_control_only=args.background_control_only,
                )
                manifest["browser_attachment"] = {"status": "connected",
                    "transport": "authorized_browser_use", "connected_epoch": time.time(),
                    "session_id": driver.transport.session["session_id"]}
                _write_json(run_dir / "windows_capture_manifest.json", manifest)
            else:
                driver = WindowsDesktopDriver(
                    run_dir / "runtime",
                    edge_profile_dir=(Path(_expand_path(args.existing_edge_profile)).resolve()
                                      if args.existing_edge_profile else
                                      prepared_edge_profile_dir() if targeted else None),
                    attach_existing_edge=bool(args.existing_edge_profile),
                    existing_edge_tab_id=args.existing_edge_tab_id,
                    background_control_only=args.background_control_only,
                    tolerate_foreground_interruptions=args.tolerate_foreground_interruptions,
                    require_single_page=False,
                )
            automation = ActivityRunner(
                plan=plan,
                run_dir=run_dir,
                duration_seconds=duration_seconds,
                seed=seed,
                stop_event=stop_event,
                driver=driver,
                single_session=args.single_session,
            )

        if args.process_attribution:
            from .process_attribution import SocketOwnershipRecorder, CLOCK_MARGIN, MAX_SAMPLE_GAP
            debug_port = None
            profile = (Path(_expand_path(args.existing_edge_profile)) if args.existing_edge_profile
                       else prepared_edge_profile_dir())
            port_file = profile / "DevToolsActivePort"
            if port_file.is_file():
                debug_port = int(port_file.read_text().splitlines()[0])
            ownership_recorder = SocketOwnershipRecorder(
                run_dir / "platform_evidence" / "socket_samples.jsonl.gz",
                excluded_roots=manifest["process_attribution"]["excluded_process_roots"],
                target_process="" if args.background_scenario else native_target["command"] if native_target else "msedge.exe",
                target_pids=automation.driver._edge_profile_pids if automation is not None else None,
                debug_port=debug_port,
            )
            ownership_recorder.start()
            time.sleep(CLOCK_MARGIN + MAX_SAMPLE_GAP)

        def start_automation(_session_bundle) -> None:
            nonlocal automation_thread
            if automation is None:
                return
            def run_and_stop_single_target() -> None:
                if environment is not None:
                    try:
                        if args.continue_environment_from:
                            continue_environment(run_dir, environment, Path(args.continue_environment_from), serial="")
                        elif args.resume_environment_from:
                            resume_environment(run_dir, environment, Path(args.resume_environment_from), serial="")
                        else:
                            from ..collection_environment import _windows_checkpoint
                            _write_json(run_dir / "operator_machine_checkpoint.json", _windows_checkpoint()["machine"])
                            prepare_environment(run_dir, environment, operator_kind=args.environment_operator)
                        if stop_event.is_set():
                            raise RuntimeError("Capture stopped during background preparation")
                    except (Exception, KeyboardInterrupt) as exc:
                        automation.summary.error = f"Background preparation: {exc}"
                        stop_event.set()
                        return
                summary = automation.run()
                if targeted and (args.single_session or summary.failed_windows or summary.error):
                    # The single behavior window has finished. The duration is
                    # a capture ceiling, not a required idle tail.
                    stop_event.set()
            automation_thread = threading.Thread(target=run_and_stop_single_target,
                                                 name="windows-plan-automation", daemon=True)
            automation_thread.start()

        if args.background_control_only:
            automation.run()
        else:
            logger_config = LoggerConfig(
                sample_interval_ms=args.sample_interval_ms,
                output_root=run_dir / "windows_logger",
                export_root=run_dir / "windows_exports",
            )
            controller_options = ({"network_capture_factory": network_capture_factory}
                                  if network_capture_factory is not None else {})
            controller = SessionController(config=logger_config, snapshotter=create_snapshotter("windows"),
                                           **controller_options)
            result = controller.run(
                behavior_label=args.background_scenario or str(plan.get("behavior_label", "other")),
                duration_seconds=duration_seconds,
                export_on_stop=False,
                stop_event=stop_event,
                on_started=start_automation,
                on_record=background_recorder.record if background_recorder else None,
                network_config=NetworkCaptureConfig(
                    enabled=args.enable_router_capture,
                    bucket_interval_ms=args.sample_interval_ms,
                    rotation_size_mb=args.rotation_size_mb,
                    router_host=args.router_host,
                    router_port=args.router_port,
                    router_user=args.router_user,
                    router_interface=args.router_interface,
                    device_ip=device_ip,
                    bpf_filter=bpf_filter,
                    ssh_key_path=_expand_path(args.router_identity),
                    snaplen_bytes=args.snaplen_bytes,
                ),
            )
            session_dir = result.session_bundle.session_dir
            network_result = result.network_result
        capture_ended_epoch = time.time()
    except Exception as exc:
        error = str(exc)
        if manifest.get("browser_attachment", {}).get("status") == "waiting_for_approval":
            manifest["browser_attachment"]["status"] = "failed"
        capture_ended_epoch = time.time()
    finally:
        stop_event.set()
        if ownership_recorder is not None:
            try:
                time.sleep(3)
                ownership_recorder.stop()
            except Exception as exc:
                error = error or f"Process attribution recorder: {exc}"
        if automation_thread is not None:
            automation_thread.join(timeout=10)
        elif args.existing_edge_profile:
            from .media_probe import close_edge_connection
            close_edge_connection(Path(_expand_path(args.existing_edge_profile)).resolve())

    ended_epoch = time.time()
    if args.no_automation and background_recorder is None:
        _manual_window(run_dir, started_epoch, ended_epoch, plan)
    if session_dir is None:
        candidates = sorted((run_dir / "windows_logger" / "sessions").glob("*"))
        session_dir = candidates[-1] if candidates else run_dir / "windows_logger" / "sessions" / "missing"

    foreground_reconciliation = None
    if ((automation is not None)
            and (session_dir / "ground_truth.csv").is_file()
            and (run_dir / "usage_windows.jsonl").is_file()):
        foreground_reconciliation = reconcile_foreground_evidence(
            run_dir,
            session_dir / "ground_truth.csv",
            capture_ended_epoch=capture_ended_epoch,
            minimum_ratio=float(plan["defaults"].get("foreground_match_min_ratio", 0.5)),
        )

    pcap_files = list(network_result.raw_capture_files) if network_result is not None else []
    automation_summary = asdict(automation.summary) if automation is not None else {
        "sessions": 1 if args.no_automation else 0,
        "accepted_windows": 1 if args.no_automation else 0,
        "failed_windows": 0,
        "actions": 0,
        "error": None,
    }
    if foreground_reconciliation is not None:
        automation_summary.update(foreground_reconciliation)
    if automation_summary.get("error") and not error:
        error = str(automation_summary["error"])

    if args.browser_control_dir and automation is not None:
        try:
            target = plan['categories'][0]['targets'][0]
            focus = automation.driver.export_focus_evidence(run_dir, target)
            if focus:
                manifest['browser_tab_focus'] = focus
        except Exception as exc:
            error = error or f"Continuous browser focus evidence: {exc}"

    manifest.update(
        {
            "status": "failed" if error else "complete",
            "storage_policy": "screen-time-single-original-v1",
            "ok": not bool(error),
            "ended_epoch": ended_epoch,
            "capture_ended_epoch": capture_ended_epoch,
            "session_dir": _relative(session_dir, run_dir),
            "ground_truth_csv": _relative(session_dir / "ground_truth.csv", run_dir),
            "network_flow_buckets_csv": _relative(session_dir / "network" / "network_flow_buckets.csv", run_dir),
            "pcap_files": [_relative(path, run_dir) for path in pcap_files],
            "screen_sample_count": int(getattr(result, "screen_sample_count", 0)) if "result" in locals() else 0,
            "network_total_packets": int(network_result.total_packets) if network_result is not None else 0,
            "network_total_bytes": int(network_result.total_bytes) if network_result is not None else 0,
            "automation": automation_summary,
            "resolved_edge_tab_id": getattr(automation.driver, "_existing_target_id", None)
                if automation is not None and args.existing_edge_profile else None,
            "foreground_reconciliation": foreground_reconciliation,
            "error": error or None,
        }
    )
    _write_json(run_dir / "windows_capture_manifest.json", manifest)
    if args.process_attribution and pcap_files and not error:
        try:
            from .process_attribution import export_attribution
            attribution = export_attribution(pcap_files, run_dir / "platform_evidence" / "socket_samples.jsonl.gz",
                                             run_dir / "process_filter")
            manifest["process_attribution"]["ok"] = attribution["ok"]
            _write_json(run_dir / "windows_capture_manifest.json", manifest)
        except Exception as exc:
            manifest["process_attribution"]["error"] = f"{type(exc).__name__}: {exc}"
            _write_json(run_dir / "windows_capture_manifest.json", manifest)
    validation = validate_windows_run(run_dir)
    manifest["ok"] = bool(validation["ok"])
    manifest["validation_ok"] = bool(validation["ok"])
    _write_json(run_dir / "windows_capture_manifest.json", manifest)
    _write_json(run_dir / "strategy_validation.json", validation)

    success = bool(validation["ok"])
    if args.background_control_only:
        from .semantic import validate_shared_task
        windows_path = run_dir / "usage_windows.jsonl"
        windows = [json.loads(line) for line in windows_path.read_text(encoding="utf-8").splitlines()
                   if line.strip()] if windows_path.is_file() else []
        success = bool(not error and len(windows) == 1 and windows[0].get("status") == "accepted"
                       and validate_shared_task(run_dir / Path(windows[0]["semantic_events"]).parent, windows[0]))
        _write_json(run_dir / "background_control_validation.json", {
            "ok": success, "scope": "background_control_only", "formal_ready": False,
            "foreground_capture_verified": False, "network_capture_verified": False,
            "shared_task_independently_verified": success,
        })
        print(f"background_control_valid={str(success).lower()}", flush=True)

    print(f"windows_run_dir={run_dir}")
    print(f"windows_session_dir={session_dir}")
    print(f"windows_capture_valid={str(validation['ok']).lower()}")
    if error:
        print(f"windows_capture_error={error}")
    if not success:
        from .recovery import write_intervention
        write_intervention(run_dir, error_type="capture_or_validation_failed")
    task_tracking.finish(
        "complete" if success else "failed",
        completed_units=1 if background_recorder and success else int(automation_summary.get("accepted_windows") or 0),
        message=error,
        details={"validation_ok": bool(validation["ok"]), "background_control_ok": success if args.background_control_only else None,
                 "accepted_windows": validation.get("metrics", {}).get("accepted_windows")},
        validation_finished=True,
    )
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
