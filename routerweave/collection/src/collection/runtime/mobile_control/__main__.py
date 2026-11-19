"""Single command boundary for mobile diagnostics, execution, and collection."""

from __future__ import annotations

import argparse
import os
import json
import sys
from pathlib import Path
from dataclasses import asdict
from typing import Any

from .catalog import MobileAppCatalog
from .capture import default_router_identity
from .collection import RouterCaptureConfig, collect_mobile_task
from .task_runtime import MobileTaskRequest
from .validation import validate_mobile_collection
from .background_scenario import BackgroundScenarioRequest, collect_background_scenario


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m collection.runtime.mobile_control")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("list-apps")
    validate = subcommands.add_parser("validate")
    validate.add_argument("--run", required=True)
    manual = subcommands.add_parser("manual", help="Open local manual ground-truth controls")
    manual.add_argument("--out", required=True, help="Parent directory for new timestamped runs")
    manual.add_argument("--phone-ip", default="")
    manual.add_argument("--router-host", default=os.environ.get("ROUTERWEAVE_ROUTER_HOST", ""))
    manual.add_argument("--router-user", default="root")
    manual.add_argument("--router-interface", default="br-lan")
    manual.add_argument("--router-identity", default=default_router_identity())
    manual.add_argument("--collection-task-id", required=True)
    manual.add_argument("--marker-only", action="store_true", help="Open the IoT Events tab initially; Screen Time remains available")
    manual.add_argument("--timeline", help="Import a timeline JSON on opening; does not start capture")
    export_manual = subcommands.add_parser("export-manual", help="Export portable PCAP and behavior labels")
    export_manual.add_argument("--run", required=True)
    export_manual.add_argument("--out", required=True)
    verify_manual = subcommands.add_parser("verify-manual-export", help="Verify exported data without a model")
    verify_manual.add_argument("--out", required=True)
    collect = subcommands.add_parser("collect")
    collect.add_argument("--resume-environment-from", default="")
    collect.add_argument("--continue-environment-from", default="")
    source = collect.add_mutually_exclusive_group(required=True)
    source.add_argument("--task")
    source.add_argument("--app-name", help="Use the existing shared 30-minute foreground task")
    collect.add_argument("--preview", action="store_true", help="Print task and preparation without device operations")
    collect.add_argument("--environment-operator", choices=("human", "agent"), default="human")
    collect.add_argument("--out", required=True)
    collect.add_argument("--phone-ip", default="")
    collect.add_argument("--serial", default="")
    collect.add_argument("--udid", default="")
    collect.add_argument("--wda-url", default="http://127.0.0.1:8100")
    collect.add_argument("--router-host", default=os.environ.get("ROUTERWEAVE_ROUTER_HOST", ""))
    collect.add_argument("--router-user", default="root")
    collect.add_argument("--router-interface", default="br-lan")
    collect.add_argument("--router-identity", default=default_router_identity())
    collect.add_argument("--attribution-mode", choices=("app", "none"), default="app")
    collect.add_argument("--collection-task-id", required=True)
    background = subcommands.add_parser("collect-background")
    background.add_argument(
        "--scenario", choices=("home_screen_idle", "idle_screen_off"), required=True
    )
    background.add_argument("--duration-seconds", type=float, required=True)
    background.add_argument("--out", required=True)
    background.add_argument("--phone-ip", default="")
    background.add_argument("--udid", required=True)
    background.add_argument("--wda-url", default="http://127.0.0.1:8100")
    background.add_argument("--router-host", default=os.environ.get("ROUTERWEAVE_ROUTER_HOST", ""))
    background.add_argument("--router-user", default="root")
    background.add_argument("--router-interface", default="br-lan")
    background.add_argument("--router-identity", default=default_router_identity())
    background.add_argument("--collection-task-id", required=True)
    return parser


def _default(value: Any) -> Any:
    raw = getattr(value, "value", None)
    if raw is not None:
        return raw
    if isinstance(value, frozenset):
        return sorted(value)
    raise TypeError(f"cannot serialize {type(value).__name__}")


def _write_json(value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, default=_default) + "\n"
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload.encode("utf-8"))
        binary.flush()
        return
    sys.stdout.write(payload)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "export-manual":
        from .manual_annotations import export_snapshot
        value = export_snapshot(Path(args.run), Path(args.out))
        print(json.dumps({key: value[key] for key in ("capture_ready", "task_data_ready", "no_task_seconds", "review_seconds")}, ensure_ascii=False))
        return 0 if value["capture_ready"] else 1
    if args.command == "verify-manual-export":
        from .manual_annotations import verify_export
        print(json.dumps(verify_export(Path(args.out)), ensure_ascii=False))
        return 0
    if args.command == "manual":
        from .manual_ui import open_manual_window
        return open_manual_window(args)
    if args.command == "list-apps":
        rows = [asdict(app) for app in MobileAppCatalog.from_repository().apps]
        _write_json(rows)
        return 0
    if args.command == "validate":
        validation = validate_mobile_collection(args.run)
        _write_json(asdict(validation))
        if validation.collection_ready:
            return 0
        return 5 if validation.core_valid else 4
    if args.command == "collect":
        from ..registry.tasks import require_collection_task
        from .collection import resolve_collection_environment
        registered = require_collection_task(args.collection_task_id, kind="mobile")
        request = (MobileTaskRequest.from_path(args.task) if args.task else
                   MobileTaskRequest(platform=registered["platform"], app_name=args.app_name,
                                     monitor_seconds=1800))
        request.validate()
        if request.platform != registered["platform"]:
            raise ValueError("Task platform does not match the collection registration")
        from ..collection_environment import CONTINUATION_PROFILE, continuation_source
        if args.resume_environment_from and args.continue_environment_from:
            raise ValueError("Recovery and continuation cannot be combined")
        request, environment = resolve_collection_environment(request, registered,
            profile=CONTINUATION_PROFILE if args.continue_environment_from else None)
        if args.continue_environment_from:
            if environment is None or request.platform not in {"android", "ios"}:
                raise ValueError("Continuation requires a registered mobile supplementary target")
            continuation_source(Path(args.continue_environment_from), environment)
        if args.resume_environment_from:
            from ..collection_environment import recovery_source
            if environment is None or request.platform != "android":
                raise ValueError("Recovery requires an Android supplementary collection task")
            recovery_source(Path(args.resume_environment_from), environment)
        from .task_runtime import compile_mobile_task
        compile_mobile_task(request)
        if args.preview:
            _write_json({"request": asdict(request), "collection_environment": environment,
                         "resume_environment_from": args.resume_environment_from or None,
                         "continue_environment_from": args.continue_environment_from or None,
                         "retains_background": environment is not None,
                         "device_operations": False})
            return 0
        if request.platform == "android" and not args.serial:
            raise ValueError("Android collection requires --serial")
        result = collect_mobile_task(
            request,
            router=RouterCaptureConfig(
                args.phone_ip,
                args.router_host,
                args.router_user,
                args.router_interface,
                args.router_identity,
            ),
            out_dir=args.out,
            serial=args.serial,
            udid=args.udid,
            wda_url=args.wda_url,
            attribution_mode=args.attribution_mode,
            collection_task_id=args.collection_task_id,
            resume_environment_from=args.resume_environment_from or None,
            environment_operator=args.environment_operator,
            continue_environment_from=args.continue_environment_from or None,
        )
        _write_json(asdict(result))
        return 0 if (result.formal_ready if args.attribution_mode == "app" else result.collection_ready) else 4
    if args.command == "collect-background":
        result = collect_background_scenario(
            BackgroundScenarioRequest(
                args.scenario, args.duration_seconds, udid=args.udid
            ),
            router=RouterCaptureConfig(
                args.phone_ip,
                args.router_host,
                args.router_user,
                args.router_interface,
                args.router_identity,
            ),
            out_dir=args.out,
            wda_url=args.wda_url,
            collection_task_id=args.collection_task_id,
        )
        _write_json(asdict(result))
        return 0 if result.collection_ready else 4
if __name__ == "__main__":
    raise SystemExit(main())
