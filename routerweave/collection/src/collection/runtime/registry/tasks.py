"""Registered collection tasks and per-run status."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable



SCHEMA_VERSION = "collection-task-registry-v1"
RUN_SCHEMA_VERSION = "collection-task-run-v1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CONFIG_ROOT = Path(os.environ.get("ROUTERWEAVE_CONFIG_DIR") or REPOSITORY_ROOT / "configs").resolve()
TASK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,95}$")
RUNNABLE_STATUSES = {"ready", "collecting", "retry"}
TERMINAL_CONFIG_STATUSES = {"complete", "cancelled"}
PLATFORM_LABELS = {
    "android": "Android",
    "ios": "iOS",
    "windows": "Windows",
    "alexa": "Amazon Alexa",
    "apple_home": "Apple Home",
    "google_home": "Google Home",
    "generic": "Generic",
}


def _iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, result)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _normalized_task(raw: dict[str, Any], source_path: Path) -> dict[str, Any]:
    task_id = str(raw.get("id") or "").strip()
    if not TASK_ID_PATTERN.fullmatch(task_id):
        raise ValueError(f"invalid collection task id {task_id!r}")
    title = str(raw.get("title") or "").strip()
    if not title:
        raise ValueError(f"collection task {task_id!r} is missing title")
    target = raw.get("target") if isinstance(raw.get("target"), dict) else {}
    target_total = _integer(target.get("count"))
    target_unit = str(target.get("unit") or "samples").strip().lower()
    if target_total <= 0:
        raise ValueError(f"collection task {task_id!r} must have a positive target")
    if target_unit not in {"samples", "seconds", "runs", "events"}:
        raise ValueError(f"collection task {task_id!r} has unsupported target unit {target_unit!r}")
    status = str(raw.get("status") or "ready").strip().lower()
    if status not in RUNNABLE_STATUSES | TERMINAL_CONFIG_STATUSES | {"paused", "blocked"}:
        raise ValueError(f"collection task {task_id!r} has unsupported status {status!r}")
    platform = str(raw.get("platform") or "generic").strip().lower()
    domain = str(raw.get("domain") or "other").strip().lower()
    category = str(raw.get("category") or "other").strip().lower()
    kind = str(raw.get("kind") or "generic").strip().lower()
    return {
        "id": task_id,
        "title": title,
        "domain": domain,
        "domain_label": str(raw.get("domain_label") or domain.replace("_", " ").title()),
        "kind": kind,
        "platform": platform,
        "platform_label": str(raw.get("platform_label") or PLATFORM_LABELS.get(platform, platform.replace("_", " ").title())),
        "category": category,
        "category_label": str(raw.get("category_label") or category.replace("_", " ").title()),
        "priority": str(raw.get("priority") or "normal").strip().lower(),
        "configured_status": status,
        "target_unit": target_unit,
        "target_total": target_total,
        "baseline_completed": min(_integer(raw.get("baseline_completed")), target_total),
        "summary": str(raw.get("summary") or "").strip(),
        "collection_type": str(raw.get("collection_type") or kind).strip().lower(),
        "minimum_duration_seconds": max(0.0, float(raw.get("minimum_duration_seconds") or 0)),
        "breakdown": raw.get("breakdown") if isinstance(raw.get("breakdown"), list) else [],
        "source_type": "collection_task_registry",
        "source_path": str(source_path.resolve()),
        "metadata": raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {},
    }


def load_collection_tasks(config_root: str | Path = DEFAULT_CONFIG_ROOT) -> list[dict[str, Any]]:
    config_root = Path(config_root).resolve()
    source = config_root / "collection_tasks.json"
    payload = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"collection task registry must be an object: {source}")
    if payload and payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported collection task registry schema in {source}")
    tasks = [_normalized_task(raw, source) for raw in payload["tasks"]]
    seen: set[str] = set()
    for task in tasks:
        if task["id"] in seen:
            raise ValueError(f"duplicate collection task id {task['id']!r}")
        seen.add(task["id"])
    return sorted(tasks, key=lambda row: (row["domain"], row["platform"], row["category"], row["title"].casefold()))


def require_collection_task(
    task_id: str,
    *,
    config_root: str | Path = DEFAULT_CONFIG_ROOT,
    kind: str = "",
    platform: str = "",
) -> dict[str, Any]:
    task_id = task_id.strip()
    task = next((row for row in load_collection_tasks(config_root) if row["id"] == task_id), None)
    if task is None:
        raise ValueError(f"collection task {task_id!r} is not registered")
    if task["configured_status"] not in RUNNABLE_STATUSES:
        raise ValueError(
            f"collection task {task_id!r} is {task['configured_status']!r} and cannot start"
        )
    if kind and task["kind"] not in {kind, "generic"}:
        raise ValueError(
            f"collection task {task_id!r} kind {task['kind']!r} does not match {kind!r}"
        )
    if platform and task["platform"] not in {platform, "generic"}:
        raise ValueError(
            f"collection task {task_id!r} platform {task['platform']!r} does not match {platform!r}"
        )
    return task


class CollectionTaskRun:
    """Write the universal task-binding sidecar for one collector run."""

    def __init__(
        self,
        run_root: str | Path,
        task_id: str = "",
        *,
        config_root: str | Path = DEFAULT_CONFIG_ROOT,
    ) -> None:
        self.run_root = Path(run_root).resolve()
        self.task_id = task_id.strip()
        self.config_root = Path(config_root).resolve()
        self.path = self.run_root / "collection_task.json"
        self.payload: dict[str, Any] = {}

    def start(self, *, kind: str, platform: str, title: str = "", purpose: str = "") -> dict[str, Any]:
        task = (
            require_collection_task(
                self.task_id,
                config_root=self.config_root,
                kind=kind,
                platform=platform,
            )
            if self.task_id
            else None
        )
        now = _iso()
        from ..run_retention import purpose_for_task
        if purpose and purpose not in {"validation", "formal", "review"}:
            raise ValueError("invalid collection artifact purpose")
        self.payload = {
            "schema_version": RUN_SCHEMA_VERSION,
            "task_id": self.task_id or None,
            "registration_status": "registered" if task else "unregistered",
            "title": task["title"] if task else (title or self.run_root.name),
            "kind": kind,
            "platform": platform,
            "status": "running",
            "started_at": now,
            "updated_at": now,
            "completed_units": 0,
            "message": None,
            "artifact_purpose": purpose or purpose_for_task(task),
        }
        _atomic_json(self.path, self.payload)
        return dict(self.payload)

    def finish(
        self,
        status: str,
        *,
        completed_units: int = 0,
        message: str = "",
        details: dict[str, Any] | None = None,
        validation_finished: bool = False,
    ) -> dict[str, Any]:
        if status not in {"complete", "failed", "blocked", "cancelled"}:
            raise ValueError(f"unsupported collection task run status {status!r}")
        if not self.payload:
            value = _read_json(self.path, {})
            self.payload = value if isinstance(value, dict) else {}
        self.payload.update(
            {
                "schema_version": RUN_SCHEMA_VERSION,
                "task_id": self.task_id or self.payload.get("task_id"),
                "status": status,
                "updated_at": _iso(),
                "finished_at": _iso(),
                "completed_units": _integer(completed_units),
                "message": message or None,
                "details": details or {},
            }
        )
        if status == "complete" and (details or {}).get("counts_toward_task") is False:
            self.payload["artifact_purpose"] = "validation"
        _atomic_json(self.path, self.payload)
        from ..run_retention import closeout_run, _write_report
        try:
            closeout = closeout_run(self.run_root, validation_finished=validation_finished)
        except Exception as exc:
            # Collection evidence remains authoritative; storage failure must
            # fail the command rather than silently claim round completion.
            _write_report(self.run_root, {"status": "error", "error": f"{type(exc).__name__}: {exc}"})
            raise
        if closeout.get("status") in {"pending", "error"}:
            print(f"collection_storage={closeout['status']}; reason={closeout.get('reason', '')}; run={self.run_root}", flush=True)
        return dict(self.payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage unified collection-task bindings")
    parser.add_argument("--config-root", default=str(DEFAULT_CONFIG_ROOT))
    commands = parser.add_subparsers(dest="command_name", required=True)
    commands.add_parser("list")
    check = commands.add_parser("check")
    check.add_argument("--task-id", required=True)
    check.add_argument("--kind", default="")
    check.add_argument("--platform", default="")
    start = commands.add_parser("start")
    start.add_argument("--task-id", required=True)
    start.add_argument("--run-root", required=True)
    start.add_argument("--kind", required=True)
    start.add_argument("--platform", required=True)
    start.add_argument("--title", default="")
    start.add_argument("--purpose", choices=("validation", "formal", "review"), default="")
    finish = commands.add_parser("finish")
    finish.add_argument("--run-root", required=True)
    finish.add_argument("--status", choices=("complete", "failed", "blocked", "cancelled"), required=True)
    finish.add_argument("--completed-units", type=int, default=0)
    finish.add_argument("--message", default="")
    finish.add_argument("--validation-finished", action="store_true",
                        help="Close storage after the independently validated collection boundary")
    run = commands.add_parser("run")
    run.add_argument("--task-id", required=True)
    run.add_argument("--run-root", required=True)
    run.add_argument("--kind", required=True)
    run.add_argument("--platform", required=True)
    run.add_argument("--success-units", type=int, default=0)
    run.add_argument("--purpose", choices=("validation", "formal", "review"), default="")
    run.add_argument("collector", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command_name == "list":
        payload = {"schema_version": SCHEMA_VERSION, "tasks": load_collection_tasks(args.config_root)}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.command_name == "check":
        task = require_collection_task(
            args.task_id,
            config_root=args.config_root,
            kind=args.kind,
            platform=args.platform,
        )
        print(json.dumps(task, ensure_ascii=False, indent=2))
        return 0
    tracker = CollectionTaskRun(
        args.run_root,
        getattr(args, "task_id", ""),
        config_root=args.config_root,
    )
    if args.command_name == "start":
        payload = tracker.start(kind=args.kind, platform=args.platform, title=args.title, purpose=args.purpose)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if args.command_name == "finish":
        payload = tracker.finish(
            args.status,
            completed_units=args.completed_units,
            message=args.message,
            validation_finished=args.validation_finished,
        )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    collector = list(args.collector)
    if collector and collector[0] == "--":
        collector = collector[1:]
    if not collector:
        raise SystemExit("registered collection runner requires a collector command after --")
    tracker.start(kind=args.kind, platform=args.platform, purpose=args.purpose)
    try:
        completed = subprocess.run(collector, check=False).returncode
    except Exception as exc:
        tracker.finish("failed", message=f"{type(exc).__name__}: {exc}")
        raise
    tracker.finish(
        "complete" if completed == 0 else "failed",
        completed_units=args.success_units if completed == 0 else 0,
        message=f"collector exit code {completed}",
    )
    return completed


if __name__ == "__main__":
    raise SystemExit(main())
