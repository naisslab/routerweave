"""Calendar-driven IoT routines, independent of device names and action names.

Configuration references existing native control plans. Progress is committed
before dispatch; an interrupted or uncertain command is never replayed.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager, nullcontext
import copy
from datetime import datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Protocol

from collection.runtime.artifacts import EventLog
from collection.runtime.errors import DemoError

WORKSPACE = Path(__file__).resolve().parents[4]
SUCCESS = {"confirmed", "command_recorded", "already_satisfied", "skipped_limit", "observed"}


class ControlDeferred(DemoError):
    """Control has not been attempted because another owner is using the phone."""


class Control(Protocol):
    def observe(self, control: str) -> str: ...
    def issue(self, control: str, before: str, target: str, *, deadline_epoch: float) -> dict[str, Any]: ...
    def confirm(self, control: str, target: str) -> bool: ...
    def record_command(self, control: str, receipt: dict[str, Any]) -> dict[str, Any]: ...


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def capture_plan_matches(root: Path, plan: dict, digest: str) -> bool:
    """A reviewed control-contract revision must not restart continuous capture.

    Original plans are retained. Explicit acceptance annotations or independently
    checked future-time revisions may differ; capture and device identities stay pinned.
    """
    try:
        revisions = schedule_revisions(root, plan)
    except (OSError, ValueError, KeyError, TypeError):
        return False
    candidates = [plan] + [item["before_plan"] for item in revisions]
    if any(digest == fingerprint(candidate) for candidate in candidates):
        return True
    original_path = root / "routine.capture-plan.json"
    if not original_path.is_file():
        return False
    original = read_json(original_path)
    def without_contract(value):
        result = copy.deepcopy(value)
        for binding in result["controls"].values():
            binding.pop("acceptance_mode", None)
            binding["plan"].pop("acceptance_mode", None)
            for device in binding["plan"]["devices"]:
                device.pop("command_evidence", None)
        return result
    return digest == fingerprint(original) and any(
        without_contract(original) == without_contract(candidate) for candidate in candidates)


def check_schedule_revision(before: dict, after: dict, checkpoint: dict, epoch: float,
                            *, allow_action_changes: bool = False) -> None:
    """Revise untouched future events, retaining bindings and action definitions."""
    positive(epoch, "revision epoch")
    if before.get("capture_only") or checkpoint.get("plan_sha256") != fingerprint(before):
        raise ValueError("Schedule revision requires a matching automated checkpoint")
    if checkpoint.get("status") not in {"prepared", "running"}:
        raise ValueError("Ended routines cannot be rescheduled")
    if {k: v for k, v in before.items() if k != "events"} != {
            k: v for k, v in after.items() if k != "events"}:
        raise ValueError("Schedule revision cannot change capture, bindings or actions")
    old_events, new_events = before["events"], after["events"]
    progress = checkpoint["events"]
    if len(old_events) != len(new_events) or len(progress) != len(old_events):
        raise ValueError("Schedule revision cannot add or remove events")
    editable = {"day", "time", "at", "at_epoch"}
    if allow_action_changes:
        editable.add("actions")
    changed = False
    previous = float("-inf")
    start = datetime.fromisoformat(before["start_at"])
    for old, new, saved in zip(old_events, new_events, progress):
        if (old["id"] != saved["id"] or [s["action"] for s in saved["steps"]] != old["actions"]
                or any(s["status"] == "dispatching" for s in saved["steps"])):
            raise ValueError("Cannot revise an in-flight or mismatched checkpoint")
        at = new["at_epoch"]
        if not before["start_epoch"] <= at < before["end_epoch"] or at <= previous:
            raise ValueError("Revised events must remain ordered inside the original interval")
        previous = at
        if old == new:
            continue
        changed = True
        if ({k: v for k, v in old.items() if k not in editable} !=
                {k: v for k, v in new.items() if k not in editable}):
            raise ValueError("Only permitted future event fields may change")
        names = new.get("actions")
        if (not isinstance(names, list) or not names
                or any(not isinstance(name, str) or name not in before["actions"] for name in names)):
            raise ValueError("Revised events require existing action names")
        if old["at_epoch"] <= epoch or at <= epoch or saved["steps"] != [
                {"action": name, "status": "pending"} for name in old["actions"]]:
            raise ValueError("Started, attempted or elapsed events cannot change")
        moment = datetime.fromtimestamp(at, start.tzinfo)
        if (moment.second or moment.microsecond or new["at"] != moment.isoformat()
                or new["time"] != moment.strftime("%H:%M")
                or new["day"] != (moment.date() - start.date()).days + 1):
            raise ValueError("Revised calendar fields must describe the same minute")
    if not changed:
        raise ValueError("Schedule revision has no changed future events")


def schedule_revisions(root: Path, plan: dict, state: dict | None = None) -> list[dict]:
    """Recheck the preserved revision chain, including unchanged historical results."""
    if state is not None:
        if ([event["id"] for event in state["events"]] != [event["id"] for event in plan["events"]]
                or any([step["action"] for step in saved["steps"]] != event["actions"]
                       for saved, event in zip(state["events"], plan["events"]))):
            raise ValueError("Checkpoint event actions differ from the effective plan")
    records = []
    for index, path in enumerate(sorted(root.glob("routine.schedule-revision-*.json")), 1):
        if path.name != f"routine.schedule-revision-{index:04d}.json":
            raise ValueError("Missing or unordered schedule revision")
        item = read_json(path)
        schema = item.get("schema_version")
        if schema not in {"iot-routine-schedule-revision-v1", "iot-routine-schedule-revision-v2"} or not item.get("reason"):
            raise ValueError("Invalid schedule revision receipt")
        check_schedule_revision(item["before_plan"], item["after_plan"], item["checkpoint_before"], item["epoch"],
                                allow_action_changes=schema == "iot-routine-schedule-revision-v2")
        if records and (item["before_plan"] != records[-1]["after_plan"] or item["epoch"] <= records[-1]["epoch"]):
            raise ValueError("Broken schedule revision chain")
        if state is not None:
            current = {event["id"]: event for event in state["events"]}
            for saved in item["checkpoint_before"]["events"]:
                if any(step["status"] != "pending" for step in saved["steps"]) and current.get(saved["id"]) != saved:
                    raise ValueError("Historical operation results changed after rescheduling")
        records.append(item)
    if records and records[-1]["after_plan"] != plan:
        raise ValueError("Effective plan differs from the preserved schedule revision")
    return records


def revise_schedule(root: Path, event_times: dict[str, str], *, reason: str,
                    event_actions: dict[str, list[str]] | None = None, now=time.time) -> dict:
    """Apply reviewed future times/action lists while control is stopped and phone leased.

    The caller pauses only the idle supervisor/control, retaining the capture
    process. The routine lock refuses an active control worker. A partial write
    fails checkpoint validation closed; the exclusive receipt retains recovery inputs.
    """
    with exclusive_lock(root / "routine.lock"):
        before = read_json(root / "routine.effective.json")
        checkpoint = read_json(root / "routine_state.json")
        records = schedule_revisions(root, before, checkpoint)
        after = copy.deepcopy(before)
        event_actions = event_actions or {}
        if (not reason.strip() or not (event_times or event_actions)
                or (set(event_times) | set(event_actions)) - {e["id"] for e in after["events"]}):
            raise ValueError("Explicit reason and existing future event IDs are required")
        start = datetime.fromisoformat(before["start_at"])
        for event in after["events"]:
            if event["id"] in event_actions:
                event["actions"] = copy.deepcopy(event_actions[event["id"]])
            if event["id"] not in event_times:
                continue
            value = event_times[event["id"]]
            if not re.fullmatch(r"\d{2}:\d{2}", value):
                raise ValueError("Revised time requires HH:MM")
            hour, minute = map(int, value.split(":"))
            moment = start.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=event["day"] - 1)
            event.update(time=value, at_epoch=moment.timestamp(), at=moment.isoformat())
        epoch = now()
        check_schedule_revision(before, after, checkpoint, epoch, allow_action_changes=bool(event_actions))
        receipt = {"schema_version": "iot-routine-schedule-revision-v2" if event_actions else "iot-routine-schedule-revision-v1", "epoch": epoch,
                   "reason": reason, "before_plan": before, "after_plan": after,
                   "checkpoint_before": checkpoint}
        receipt_path = root / f"routine.schedule-revision-{len(records) + 1:04d}.json"
        with receipt_path.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        revised = copy.deepcopy(checkpoint)
        revised["plan_sha256"] = fingerprint(after)
        for old, new, saved in zip(before["events"], after["events"], revised["events"]):
            if old["actions"] != new["actions"]:
                saved["steps"] = [{"action": name, "status": "pending"} for name in new["actions"]]
        atomic_json(root / "routine.effective.json", after)
        atomic_json(root / "routine_state.json", revised)
        return receipt


def positive(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return float(value)


def capture_deadline(plan: dict) -> float:
    return plan["end_epoch"] + (plan.get("capture_margin_seconds", 0) if plan.get("capture_only") else 0)


def compile_plan(path: Path, start_at: str, *, workspace: Path = WORKSPACE) -> dict[str, Any]:
    """Resolve immutable bindings and an absolute timeline without device I/O."""
    from collection.runtime.ios.iot_routine_control import validate_binding
    from .plan_config import load_plan
    plan = load_plan(path)
    if plan.get("schema_version") != "iot-routine-v1":
        raise ValueError("Expected schema_version=iot-routine-v1")
    start = datetime.fromisoformat(start_at)
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("start-at must include a UTC offset, for example +08:00")
    duration = positive(plan["duration_seconds"], "duration_seconds")
    result = copy.deepcopy(plan)
    result.update(start_epoch=start.timestamp(), end_epoch=start.timestamp() + duration, start_at=start.isoformat())
    if not isinstance(plan.get("plan_id"), str) or not plan["plan_id"]:
        raise ValueError("plan_id is required")
    controls = result.get("controls") or {}
    if not controls:
        raise ValueError("At least one control binding is required")
    phone_ids = set()
    wda_urls = set()
    platforms = set()
    for name, binding in controls.items():
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise ValueError(f"Invalid control name {name!r}")
        source = (path.parent / binding["plan_path"]).resolve()
        if not source.is_file():
            source = (workspace / binding["plan_path"]).resolve()
        native = load_plan(source)
        platform = native.get("control_platform")
        matches = [d for d in native["devices"] if d["id"] == binding["device_id"]]
        if len(matches) != 1:
            raise ValueError(f"Binding {name!r} must select exactly one device")
        device = matches[0]
        mode = binding.get("acceptance_mode", "state_confirmed")
        if mode not in {"state_confirmed", "command_traffic"}:
            raise ValueError("Unknown routine acceptance_mode")
        if native.get("acceptance_mode") == "command_traffic" and mode != "command_traffic":
            raise ValueError("Command-traffic binding needs explicit routine acceptance_mode")
        if mode == "command_traffic":
            native["acceptance_mode"] = mode
            device["command_evidence"] = "native_toggle_selection"
        validate_binding(native, device)
        if not device.get("states") or not device.get("mac"):
            raise ValueError("A binding requires known states and a device MAC")
        for field in ("poll_seconds", "state_timeout_seconds", "tail_seconds"):
            positive(device[field], f"{name}.{field}")
        native["devices"] = [device]
        native.pop("command_input", None)
        binding.update(plan=native, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        phone_ids.add(native["controller"].get("identifier"))
        wda_urls.add(native["controller"]["wda_url"])
        platforms.add(platform)
    if len(phone_ids) != 1 or None in phone_ids or len(wda_urls) != 1:
        raise ValueError("One routine must use exactly one identified controller phone and WDA endpoint")
    result["controller_identifier"] = next(iter(phone_ids))
    if type(plan.get("share_controller", False)) is not bool:
        raise ValueError("share_controller must be boolean")
    for dependency in plan.get("control_wait_for", []):
        dependency_path = (workspace / dependency["path"]).resolve()
        if not dependency_path.is_relative_to((workspace / "runs").resolve()):
            raise ValueError("Control dependencies must be run-local state files")
        if not dependency.get("statuses") or not all(isinstance(s, str) for s in dependency["statuses"]):
            raise ValueError("Control dependencies require explicit allowed statuses")
    if plan.get("control_wait_for") and not plan.get("share_controller"):
        raise ValueError("Control dependencies require share_controller")
    result["control_platform"] = next(iter(platforms)) if len(platforms) == 1 else "generic"
    result["max_lateness_seconds"] = positive(plan.get("max_lateness_seconds", 120), "max_lateness_seconds")
    result["tick_seconds"] = min(10.0, positive(plan.get("tick_seconds", 5), "tick_seconds"))
    result["health_seconds"] = positive(plan.get("health_seconds", 30), "health_seconds")
    actions = result.get("actions") or {}
    if not actions:
        raise ValueError("At least one action is required")
    for name, action in actions.items():
        control = controls.get(action.get("control"))
        if control is None:
            raise ValueError(f"Unknown control in action {name!r}")
        states = control["plan"]["devices"][0]["states"]
        modes = sum(key in action for key in ("target", "relative", "observe"))
        if modes != 1:
            raise ValueError(f"Action {name!r} needs exactly one of target, relative, observe")
        if "target" in action and action["target"] not in states:
            raise ValueError(f"Unknown target for action {name!r}")
        if "observe" in action and action["observe"] is not True:
            raise ValueError("observe must be true")
        if "relative" in action:
            order = action.get("state_order") or []
            if (type(action["relative"]) is not int or action["relative"] not in {-1, 1}
                    or len(order) < 2 or len(set(order)) != len(order) or any(s not in states for s in order)):
                raise ValueError(f"Invalid adjacent-state action {name!r}")
        for required in action.get("requires", []):
            validate_state_reference(required, controls)
    for required in result.get("initial_states", []):
        validate_state_reference(required, controls)
    events = []
    for index, event in enumerate(plan.get("events") or []):
        day = event["day"]
        if type(day) is not int or day < 1 or not re.fullmatch(r"\d{2}:\d{2}", event["time"]):
            raise ValueError("Events need a positive integer day and HH:MM time")
        hour, minute = map(int, event["time"].split(":"))
        at = (start.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=day - 1)).timestamp()
        if not start.timestamp() <= at < result["end_epoch"]:
            raise ValueError("Every event must fall inside [start, end)")
        names = event["actions"]
        if not isinstance(names, list) or not names or any(name not in actions for name in names):
            raise ValueError("Event actions must reference defined actions")
        if events and at <= events[-1]["at_epoch"]:
            raise ValueError("Events must have strictly increasing calendar times; group same-time actions")
        events.append({**event, "id": f"event-{index + 1:04d}", "at_epoch": at,
                       "at": datetime.fromtimestamp(at, start.tzinfo).isoformat()})
    if not events:
        raise ValueError("At least one event is required")
    result["events"] = events
    return result


def validate_state_reference(required: dict, controls: dict) -> None:
    binding = controls.get(required.get("control"))
    if binding is None or required.get("state") not in binding["plan"]["devices"][0]["states"]:
        raise ValueError("Unknown control/state in a precondition")


class RoutineRunner:
    """Persisted scheduler. Inject time and control for accelerated offline tests."""

    def __init__(self, root: Path, compiled: dict, control: Control | None, *, resume: bool = False,
                 now: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 health: Callable[[], None] = lambda: None) -> None:
        self.root, self.plan, self.control = root, compiled, control
        self.now, self.sleep, self.health = now, sleep, health
        self.control_context = nullcontext
        self.capture_snapshot: Callable[[], dict] | None = None
        self.log = EventLog(root / "routine_events.jsonl")
        self.path = root / "routine_state.json"
        digest = fingerprint(compiled)
        if self.path.exists():
            if not resume:
                raise ValueError("Run already exists; use --resume with the same plan and start-at")
            self.state = read_json(self.path)
            if self.state.get("plan_sha256") != digest:
                raise ValueError("Cannot resume with a changed plan, binding, or start-at")
            schedule_revisions(root, compiled, self.state)
            for event in self.state["events"]:
                for step in event["steps"]:
                    if step["status"] == "dispatching":
                        step.update(status="uncertain", reason="interrupted_after_dispatch_checkpoint")
            if self.state.get("status") != "prepared":
                self.state["interruptions"].append({"last_checkpoint_epoch": self.state["updated_epoch"], "resumed_epoch": now()})
        else:
            if resume:
                raise ValueError("Cannot resume without an existing checkpoint")
            if any(path.name not in {"routine.lock", "runner.log", "supervisor.lock", "guardian.lock"} for path in root.iterdir()):
                raise ValueError("New routine output must be empty; refusing to overwrite existing artifacts")
            self.state = {"schema_version": "iot-routine-state-v1", "plan_sha256": digest,
                          "status": "prepared", "initial_checked": False, "interruptions": [],
                          "segments": [], "capture_gaps": [], "capture_issues": [],
                          "validation_status": "not_run", "formal_ready": False,
                          "events": [{"id": event["id"], "steps": [
                              {"action": name, "status": "pending"} for name in event["actions"]
                          ]} for event in compiled["events"]]}
            atomic_json(root / "routine.effective.json", compiled)
        self.save()

    def save(self) -> None:
        if self.capture_snapshot is not None:
            self.state.update(self.capture_snapshot())
        self.state["updated_epoch"] = self.now()
        atomic_json(self.path, self.state)
        sidecar = self.root / "collection_task.json"
        if sidecar.exists() and self.now() - getattr(self, "_task_heartbeat", 0) >= 30:
            sidecar.touch()
            self._task_heartbeat = self.now()

    def finish_step(self, event: dict, step: dict, status: str, **details: Any) -> None:
        step.update(status=status, finished_epoch=self.now(), **details)
        self.save()
        self.log.write("routine_step", event_id=event["id"], **step)

    def run_event(self, event: dict, progress: dict) -> None:
        if self.now() > event["at_epoch"] + self.plan["max_lateness_seconds"]:
            self._run_event(event, progress)  # Expired steps never touch the phone.
            return
        try:
            with self.control_context():
                self._run_event(event, progress)
        except ControlDeferred as exc:
            self.state["control_wait"] = {"epoch": self.now(), "reason": str(exc)}
            self.save()

    def _run_event(self, event: dict, progress: dict) -> None:
        for step in progress["steps"]:
            if step["status"] != "pending":
                continue
            if self.now() < step.get("next_attempt_epoch", 0):
                break
            if self.now() > event["at_epoch"] + self.plan["max_lateness_seconds"] or self.now() >= self.plan["end_epoch"]:
                self.finish_step(event, step, "missed", reason="calendar_deadline_passed")
                continue
            action = self.plan["actions"][step["action"]]
            kind = action["control"]
            try:
                self.health()
                for required in action.get("requires", []):
                    observed = self.control.observe(required["control"])
                    if observed != required["state"]:
                        self.finish_step(event, step, "skipped_precondition", observed=observed, required=required)
                        break
                if step["status"] != "pending":
                    continue
                before = self.control.observe(kind)
                known = self.plan["controls"][kind]["plan"]["devices"][0]["states"]
                if before not in known:
                    raise DemoError(f"Unknown observed state {before!r}")
                if self.now() > event["at_epoch"] + self.plan["max_lateness_seconds"] or self.now() >= self.plan["end_epoch"]:
                    self.finish_step(event, step, "missed", reason="deadline_passed_during_observation")
                    continue
                if action.get("observe"):
                    self.finish_step(event, step, "observed", before=before)
                    continue
                if "relative" in action:
                    order = action["state_order"]
                    if before not in order:
                        self.finish_step(event, step, "skipped_precondition", observed=before, reason="outside_relative_state_order")
                        continue
                    index = order.index(before) + action["relative"]
                    if not 0 <= index < len(order):
                        self.finish_step(event, step, "skipped_limit", before=before)
                        continue
                    target = order[index]
                else:
                    target = action["target"]
                if before == target:
                    self.finish_step(event, step, "already_satisfied", before=before, target=target)
                    continue
                # Navigation and health checks can consume the lateness window.
                self.health()
                if self.now() > event["at_epoch"] + self.plan["max_lateness_seconds"] or self.now() >= self.plan["end_epoch"]:
                    self.finish_step(event, step, "missed", reason="deadline_passed_during_preparation")
                    continue
                step.update(status="dispatching", before=before, target=target, dispatch_epoch=self.now())
                self.save()  # fsync + atomic replace BEFORE the non-idempotent gesture
                from collection.runtime.ios.iot_routine_control import CommandWithheld
                try:
                    step["receipt"] = self.control.issue(
                        kind, before, target,
                        deadline_epoch=min(event["at_epoch"] + self.plan["max_lateness_seconds"], self.plan["end_epoch"]),
                    )
                except CommandWithheld as exc:
                    if self.retry_not_issued(event, step, exc):
                        return
                    continue
                except Exception as exc:
                    step["receipt_error"] = f"{type(exc).__name__}: {exc}"
                # A timed-out command can have succeeded; only readback decides.
                if self.plan["controls"][kind].get("acceptance_mode") == "command_traffic":
                    if "receipt" not in step or "receipt_error" in step:
                        self.finish_step(event, step, "uncertain", state_confirmed=False)
                        continue
                    try:
                        evidence = self.control.record_command(kind, step["receipt"])
                        self.finish_step(event, step, "command_recorded", state_confirmed=False,
                                         command_observation=evidence)
                    except Exception as exc:
                        self.finish_step(event, step, "uncertain", state_confirmed=False,
                                         reason=f"command_observation_failed:{exc}")
                    continue
                try:
                    confirmed = self.control.confirm(kind, target)
                except Exception as exc:
                    confirmed = False
                    step["confirmation_error"] = f"{type(exc).__name__}: {exc}"
                self.finish_step(event, step, "confirmed" if confirmed else "uncertain")
            except Exception as exc:
                # Once dispatch was checkpointed, an unexpected failure is
                # uncertain. Never replay it, including after a save failure.
                if step["status"] == "dispatching":
                    self.finish_step(event, step, "uncertain", reason=f"{type(exc).__name__}: {exc}")
                elif step["status"] == "pending":
                    if self.retry_not_issued(event, step, exc):
                        return

    def retry_not_issued(self, event: dict, step: dict, exc: Exception) -> bool:
        attempts = step.get("preparation_failures", 0) + 1
        step.update(preparation_failures=attempts, last_error=f"{type(exc).__name__}: {exc}")
        deadline = min(event["at_epoch"] + self.plan["max_lateness_seconds"], self.plan["end_epoch"])
        if attempts < 5 and self.now() + self.plan["tick_seconds"] < deadline:
            if "dispatch_epoch" in step:
                step.setdefault("withheld_attempts", []).append({
                    "dispatch_epoch": step.pop("dispatch_epoch"), "reason": step["last_error"]})
            step.update(status="pending", next_attempt_epoch=self.now() + self.plan["tick_seconds"])
            self.save()
            self.log.write("routine_retry_not_issued", event_id=event["id"], **step)
            return True
        self.finish_step(event, step, "failed", reason=step["last_error"])
        return False

    def run(self) -> int:
        if self.control is None:
            raise ValueError("A control adapter must be attached before running")
        self.state["status"] = "running"
        self.save()
        next_health, failures, previous_epoch = 0.0, 0, self.now()
        while self.now() < self.plan["end_epoch"]:
            if (self.root / "STOP").exists():
                self.state["status"] = "cancelled"
                self.save()
                return 2
            now = self.now()
            if now < previous_epoch:
                next_health = now
                self.log.write("routine_clock_moved_back", previous_epoch=previous_epoch, observed_epoch=now)
            previous_epoch = now
            if now >= next_health:
                try:
                    self.health()
                    failures = 0
                    self.state["health"] = {"ok": True, "epoch": self.now()}
                    self.state["status"] = "running"
                except Exception as exc:
                    failures += 1
                    self.state["health"] = {"ok": False, "epoch": self.now(), "error": str(exc)}
                    self.log.write("routine_health_failed", failures=failures, error=str(exc))
                    self.state["status"] = "degraded"
                self.save()
                next_health = self.now() + self.plan["health_seconds"]
            if failures:
                self.sleep(min(self.plan["tick_seconds"], max(0, self.plan["end_epoch"] - self.now())))
                continue
            if now >= self.plan["start_epoch"]:
                if not self.state["initial_checked"]:
                    try:
                        if self.plan.get("initial_states"):
                            with self.control_context():
                                for required in self.plan["initial_states"]:
                                    observed = self.control.observe(required["control"])
                                    self.log.write("routine_initial_state", **required, observed=observed)
                                    if observed != required["state"]:
                                        self.state.setdefault("initial_issues", []).append({**required, "observed": observed, "epoch": self.now()})
                        self.state["initial_checked"] = True
                    except ControlDeferred as exc:
                        self.state["control_wait"] = {"epoch": self.now(), "reason": str(exc)}
                    except Exception as exc:
                        self.state["health"] = {"ok": False, "epoch": self.now(), "error": str(exc)}
                        self.state["status"] = "degraded"
                        self.log.write("routine_initial_state_unavailable", error=str(exc))
                        failures = 1
                    self.save()
                    # An unavailable initial observation does not poison later
                    # events. Each command still has its own fresh guards.
                for event, progress in zip(self.plan["events"], self.state["events"]):
                    if event["at_epoch"] <= self.now() and any(s["status"] == "pending" for s in progress["steps"]):
                        self.run_event(event, progress)
            future = [e["at_epoch"] for e in self.plan["events"] if e["at_epoch"] > self.now()]
            wake = min([self.plan["end_epoch"], next_health, *future])
            self.sleep(min(self.plan["tick_seconds"], max(0.01, wake - self.now())))
        for event, progress in zip(self.plan["events"], self.state["events"]):
            for step in progress["steps"]:
                if step["status"] == "pending":
                    self.finish_step(event, step, "missed", reason="routine_interval_ended")
        clean = all(s["status"] in SUCCESS for e in self.state["events"] for s in e["steps"])
        clean = clean and not any(self.state.get(key) for key in ("interruptions", "capture_gaps", "capture_issues", "initial_issues", "scheduler_issues"))
        if self.capture_snapshot is not None:
            clean = clean and bool(self.state["segments"]) and self.state.get("capture_health", {}).get("ok", False)
        self.state["status"] = "complete" if clean else "finished_with_gaps"
        self.save()
        return 0 if clean else 2


class RoutineCapture:
    """Owned router stream with checkpointed, non-overwriting reconnect segments."""

    def __init__(self, runner: RoutineRunner) -> None:
        self.runner = runner
        self.stream = None
        self.last_healthy: float | None = None
        self.log = EventLog(runner.root / "capture_events.jsonl")
        self.path = runner.root / "capture_state.json"
        self.state = {key: copy.deepcopy(runner.state[key]) for key in ("segments", "capture_gaps", "capture_issues")}
        if self.path.exists():
            retained = read_json(self.path)
            if not capture_plan_matches(runner.root, runner.plan, retained.get("plan_sha256")):
                raise ValueError("Capture checkpoint belongs to a different routine")
            self.state = retained
        self.state["plan_sha256"] = runner.state["plan_sha256"]
        self.state["identity_ready"] = False
        self.state["capture_health"] = {"ok": False, "epoch": runner.now(), "error": "capture_starting"}
        self._published = copy.deepcopy(self.state)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._orphans_checked = False

    def save(self) -> None:
        # Only the capture worker writes this file. The scheduler receives an
        # immutable published copy, so WDA waits cannot block capture recovery.
        self._published = copy.deepcopy(self.state)
        atomic_json(self.path, self.state)

    def snapshot(self) -> dict:
        return {key: copy.deepcopy(value) for key, value in self._published.items() if key != "plan_sha256"}

    def check(self) -> None:
        health = self._published.get("capture_health", {})
        if not health.get("ok") or self.runner.now() - health.get("epoch", 0) > max(120, self.runner.plan["health_seconds"] * 3):
            raise DemoError("Capture is recovering; appliance commands are paused")
        if not self._published.get("identity_ready"):
            raise DemoError("Passive capture continues; device identity must recover before commands")

    def start_watchdog(self) -> None:
        def watch():
            try:
                while not self._stop.is_set() and self.runner.now() < capture_deadline(self.runner.plan):
                    try:
                        if not self._orphans_checked:
                            self.recover_orphans()
                            self._orphans_checked = True
                        self.health()
                        self.state["capture_health"] = {"ok": True, "epoch": self.runner.now()}
                    except Exception as exc:
                        self.state["capture_health"] = {"ok": False, "epoch": self.runner.now(), "error": str(exc)}
                        try:
                            self.log.write("capture_recovery_pending", error=str(exc))
                        except OSError:
                            pass  # Keep the active stream even if diagnostic writes fail.
                    try:
                        self.save()
                    except Exception:
                        pass  # A checkpoint failure must not stop an existing PCAP stream.
                    remaining = max(0, capture_deadline(self.runner.plan) - self.runner.now())
                    self._stop.wait(min(self.runner.plan["health_seconds"], remaining))
            finally:
                try:
                    self.stop()
                except Exception as exc:
                    self.state["capture_issues"].append({"reason": f"capture_stop_failed:{exc}"})
                    self.save()
        self._thread = threading.Thread(target=watch, name="iot-routine-capture", daemon=True)
        self._thread.start()

    def stop_watchdog(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        else:
            self.stop()

    def start(self) -> None:
        from collection.runtime.ios.iot_identity_preflight import run_identity_preflight
        from collection.runtime.mobile_control.capture import RouterStreamCapture
        runner = self.runner
        plans = [binding["plan"] for binding in runner.plan["controls"].values()]
        router = plans[0]["router"]
        for plan in plans:
            if any(plan["router"][key] != router[key] for key in ("host", "user", "interface")):
                raise DemoError("One routine cannot capture from multiple routers")
        devices = {device["id"]: device for plan in plans for device in plan["devices"]}
        scope = {"router": router, "devices": list(devices.values())}
        number = len(self.state["segments"]) + 1
        directory = runner.root / "raw" / f"segment-{number:05d}"
        if directory.exists():
            raise DemoError("Unowned capture segment directory already exists; refusing to overwrite")
        record = {"path": str(directory / "capture.pcap"), "requested_epoch": runner.now(), "status": "starting"}
        self.state["segments"].append(record)
        self.save()
        identity = run_identity_preflight(scope, directory, mode="advisory", log=self.log)
        self.state["identity_ready"] = identity.get("status") in {"passed", "advisory_issues"}
        if runner.now() >= capture_deadline(runner.plan):
            raise DemoError("Capture preparation ended after the routine interval")
        macs = sorted({device["mac"].lower() for device in devices.values()})
        if any(not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) for mac in macs):
            raise DemoError("Invalid target MAC in routine binding")
        capture_filter = " or ".join(f"ether host {mac}" for mac in macs)
        record["capture_filter"] = capture_filter
        self.stream = RouterStreamCapture(
            user=router["user"], host=router["host"], interface=router["interface"], phone_ip=None,
            local_pcap=directory / "capture.pcap", log=self.log,
            identity_file=router.get("identity_file"), capture_filter=capture_filter,
            ssh_keepalive_seconds=15,
        )
        record["remote_pidfile"] = self.stream.remote_pidfile
        self.save()
        try:
            self.stream.start()
        except Exception:
            record["status"] = "failed_to_start"
            self.save()
            self.stop()
            raise
        ready = runner.now()
        record.update(status="streaming", ready_epoch=ready)
        if self.last_healthy is not None:
            self.state["capture_gaps"].append({"start_epoch": self.last_healthy, "end_epoch": ready,
                                                  "boundary": "conservative_last_health_to_ready"})
        elif ready > runner.plan["start_epoch"]:
            self.state["capture_gaps"].append({"start_epoch": runner.plan["start_epoch"], "end_epoch": ready,
                                                  "boundary": "startup_or_restart"})
        self.last_healthy = ready
        self.save()

    def recover_orphans(self) -> None:
        """Only stop a previous segment's persisted marker with tcpdump identity."""
        from collection.runtime.mobile_control.capture.router import _router_ssh
        router = next(iter(self.runner.plan["controls"].values()))["plan"]["router"]
        for record in self.state["segments"]:
            if record["status"] not in {"starting", "streaming"}:
                continue
            marker = record.get("remote_pidfile", "")
            if marker:
                if not re.fullmatch(r"/tmp/mobile-control-stream-[0-9a-f]+\.pid", marker):
                    raise DemoError("Invalid persisted capture PID marker")
                command = (
                    f"if [ -f '{marker}' ]; then pid=$(cat '{marker}'); "
                    "case \"$pid\" in ''|*[!0-9]*) exit 2;; esac; "
                    "if [ -e /proc/$pid/comm ]; then "
                    "[ \"$(cat /proc/$pid/comm)\" = tcpdump ] || exit 3; "
                    "kill -INT $pid || exit 4; fi; fi"
                )
                receipt = _router_ssh(router["user"], router["host"], command,
                                      identity_file=router.get("identity_file"))
                if receipt.returncode:
                    raise DemoError("Could not stop previous routine's exact tcpdump marker")
            record["status"] = "interrupted"
            self.state["capture_issues"].append({"segment": record["path"], "reason": "interrupted_segment_requires_validation"})
        self.save()

    def health(self) -> None:
        runner = self.runner
        if shutil.disk_usage(runner.root).free < 256 * 1024 * 1024:
            raise DemoError("Less than 256 MiB free on the capture volume")
        if self.stream is None:
            self.start()
        elif self.stream.proc is None or self.stream.proc.poll() is not None:
            self.stop()
            self.start()
        elif not self.state.get("identity_ready"):
            from collection.runtime.ios.iot_identity_preflight import run_identity_preflight
            plans = [binding["plan"] for binding in runner.plan["controls"].values()]
            devices = {device["id"]: device for plan in plans for device in plan["devices"]}
            scope = {"router": plans[0]["router"], "devices": list(devices.values())}
            number = self.state.get("identity_checks", 0) + 1
            self.state["identity_checks"] = number
            self.save()
            directory = Path(self.state["segments"][-1]["path"]).parent / "identity" / f"check-{number:05d}"
            identity = run_identity_preflight(scope, directory, mode="advisory", log=self.log)
            self.state["identity_ready"] = identity.get("status") in {"passed", "advisory_issues"}
        self.last_healthy = runner.now()

    def stop(self) -> None:
        from collection.runtime.mobile_control.capture.router import parse_tcpdump_trailer
        if self.stream is None:
            return
        stream, self.stream = self.stream, None
        record = self.state["segments"][-1]
        try:
            stream.stop()
        finally:
            text = stream.stderr_path.read_text(encoding="utf-8", errors="replace") if stream.stderr_path.exists() else ""
            stats = parse_tcpdump_trailer(text)
            record.update(status="stopped", stopped_epoch=self.runner.now(), statistics=stats)
            if stats.get("kernel_dropped") != 0:
                self.state["capture_issues"].append({"segment": record["path"], "reason": "drop_count_nonzero_or_unknown"})
            self.save()


@contextmanager
def exclusive_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if not stream.tell():
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise DemoError(f"Another routine owns {path.name}") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def keep_awake():
    if os.name == "nt":
        import ctypes
        if not ctypes.windll.kernel32.SetThreadExecutionState(0x80000001):
            raise DemoError("Could not prevent Windows idle sleep")
    try:
        yield
    finally:
        if os.name == "nt":
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)


@contextmanager
def control_lease(control, compiled: dict, phone_lock: Path, *, workspace: Path = WORKSPACE):
    """Yield one complete operation after dependencies and phone ownership."""
    for dependency in compiled.get("control_wait_for", []):
        path = workspace / dependency["path"]
        try:
            state = read_json(path)
            ready = state.get("status") in dependency["statuses"]
            # A shared owner can offer a cooling/idle interval while its
            # overall collection remains unfinished. The same OS lock still
            # protects entry, including when that interval expires mid-event.
            idle = state.get("shared_controller_idle") or {}
            ready = ready or (
                bool(compiled.get("controller_identifier"))
                and idle.get("identifier") == compiled["controller_identifier"]
                and type(idle.get("until_epoch")) in (int, float)
                and math.isfinite(idle["until_epoch"])
                and time.time() < idle["until_epoch"]
            )
        except (OSError, ValueError):
            ready = False
        if not ready:
            raise ControlDeferred(f"Waiting for {dependency['path']}")
    with ExitStack() as lease:
        try:
            lease.enter_context(exclusive_lock(phone_lock))
        except DemoError as exc:
            raise ControlDeferred("Controller is busy; no command issued") from exc
        try:
            control.health()
            yield
        finally:
            control.release()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--start-at", required=True, help="ISO calendar time including UTC offset")
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--collection-task-id")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--background", action="store_true")
    parser.add_argument("--capture-only", action="store_true", help="Passive capture only; never start phone/app control")
    parser.add_argument("--capture-margin-seconds", type=float,
                        help="Capture-only lead and tail buffer; new runs default to 300 seconds")
    parser.add_argument("--validate", action="store_true", help="Offline plan/binding validation; no device access")
    parser.add_argument("--worker-role", choices=("control", "capture"), help=argparse.SUPPRESS)
    parser.add_argument("--purpose", choices=("formal", "validation"), default="formal")
    parser.add_argument("--guardian", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    retained = args.run_root.resolve() / "routine.effective.json" if args.run_root else None
    if args.resume and retained and retained.exists():
        compiled = read_json(retained)
        if compiled["start_at"] != datetime.fromisoformat(args.start_at).isoformat():
            parser.error("Resume start-at differs from the retained plan")
        if bool(compiled.get("capture_only")) != args.capture_only:
            parser.error("Resume must preserve the retained capture-only mode")
        if (args.capture_margin_seconds is not None
                and args.capture_margin_seconds != compiled.get("capture_margin_seconds", 0)):
            parser.error("Resume must preserve the retained capture buffer")
    else:
        compiled = compile_plan(args.plan.resolve(), args.start_at)
        if args.capture_only:
            compiled["capture_only"] = True
            margin = args.capture_margin_seconds if args.capture_margin_seconds is not None else 300
            compiled["capture_margin_seconds"] = positive(margin, "capture_margin_seconds") if margin != 0 else 0
    if args.capture_margin_seconds is not None and not args.capture_only:
        parser.error("Capture buffer requires --capture-only")
    if args.capture_only and args.worker_role == "control":
        parser.error("Capture-only runs cannot launch a control worker")
    if args.validate:
        print(json.dumps({"plan_id": compiled["plan_id"], "start_at": compiled["start_at"],
                          "duration_hours": compiled["duration_seconds"] / 3600,
                          "controls": list(compiled["controls"]), "events": compiled["events"]}, ensure_ascii=False, indent=2))
        return 0
    if not args.run_root or not args.collection_task_id:
        parser.error("Execution requires --run-root and --collection-task-id")
    from collection.runtime.registry.tasks import CollectionTaskRun, require_collection_task
    task = require_collection_task(args.collection_task_id, kind="iot", platform=compiled["control_platform"])
    if task.get("metadata", {}).get("routine_plan_id") != compiled["plan_id"]:
        parser.error("Registered task metadata.routine_plan_id must match this plan_id; do not reuse completed action-sample tasks")
    if (args.purpose == "formal" and not args.capture_only
            and (task["collection_type"] != "iot_routine"
                 or not 0 < task["minimum_duration_seconds"] <= compiled["duration_seconds"])):
        parser.error("Register an iot_routine task with a positive minimum duration covered by the plan")
    root = args.run_root.resolve()
    if not root.is_relative_to(WORKSPACE / "runs"):
        parser.error("New routine output must be under runs/")
    if capture_deadline(compiled) <= time.time():
        if args.resume:
            from collection.runtime.ios.iot_routine_supervision import remove_restart_task, restart_name
            remove_restart_task(restart_name(root))
            return 0
        parser.error("Routine interval has already ended")
    if args.background:
        root.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, "-B", "-m", "collection.runtime.ios.iot_routine",
                   "--plan", str(args.plan.resolve()), "--start-at", args.start_at,
                   "--run-root", str(root), "--collection-task-id", args.collection_task_id]
        command.extend(("--purpose", args.purpose))
        if args.capture_only:
            command.append("--capture-only")
        if args.capture_margin_seconds is not None:
            command.extend(("--capture-margin-seconds", str(args.capture_margin_seconds)))
        command.append("--guardian")
        if args.resume:
            command.append("--resume")
        environment = dict(os.environ, PYTHONPATH=str(WORKSPACE / "src"), PYTHONUNBUFFERED="1")
        options = {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        with (root / "runner.log").open("ab") as log:
            process = subprocess.Popen(command, cwd=WORKSPACE, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, **options)
        print(json.dumps({"status": "dispatched", "pid": process.pid, "log": str(root / "runner.log")}))
        return 0
    compiled["collection_task_id"] = args.collection_task_id
    from collection.runtime.ios.iot_routine_supervision import supervise, run_capture_worker, CaptureCheckpoint, run_guardian
    if args.guardian:
        return run_guardian(args, root, compiled)
    if args.worker_role == "capture":
        return run_capture_worker(root, compiled)
    if args.worker_role is None:
        return supervise(args, root, compiled)
    from collection.runtime.ios.iot_routine_control import RecoveringRoutineControl
    phone_key = hashlib.sha256(compiled["controller_identifier"].encode()).hexdigest()[:20]
    with ExitStack() as stack:
        phone_lock = WORKSPACE / ".go-ios" / f"iot-routine-{phone_key}.lock"
        if not compiled.get("share_controller"):
            stack.enter_context(exclusive_lock(phone_lock))
        stack.enter_context(exclusive_lock(root / "routine.lock"))
        stack.enter_context(keep_awake())
        # Binding/task identity is also part of the restart identity.
        compiled["collection_task_id"] = args.collection_task_id
        runner = RoutineRunner(root, compiled, None, resume=args.resume)
        capture = CaptureCheckpoint(runner)
        registration = CollectionTaskRun(root, args.collection_task_id)
        registration.start(kind="iot", platform=compiled["control_platform"], purpose=args.purpose)
        code = 2
        try:
            control = RecoveringRoutineControl(root, compiled, runner.log)
            runner.control = control
            if compiled.get("share_controller"):
                runner.control_context = lambda: control_lease(control, compiled, phone_lock)
            def health():
                capture.check()
                if not compiled.get("share_controller"):
                    control.health()
            runner.health = health
            runner.capture_snapshot = capture.snapshot
            capture.start_watchdog()
            while True:
                try:
                    code = runner.run()
                    break
                except KeyboardInterrupt:
                    runner.state["status"] = "cancelled"
                    runner.save()
                    break
                except Exception as exc:
                    issue = {"epoch": runner.now(), "error": f"{type(exc).__name__}: {exc}"}
                    runner.state.setdefault("scheduler_issues", []).append(issue)
                    for event in runner.state["events"]:
                        for step in event["steps"]:
                            if step["status"] == "dispatching":
                                step.update(status="uncertain", reason="scheduler_interrupted_after_dispatch")
                    runner.state["status"] = "degraded"
                    try:
                        runner.save()
                        runner.log.write("scheduler_recovery_pending", **issue)
                    except OSError:
                        pass  # Independent capture remains alive while storage recovers.
                    runner.sleep(min(compiled["tick_seconds"], max(0, compiled["end_epoch"] - runner.now())))
        finally:
            try:
                capture.stop_watchdog()
            except Exception as exc:
                runner.state.setdefault("scheduler_issues", []).append({"error": f"capture_stop_failed:{exc}"})
            runner.save()
            if runner.state["capture_issues"] or runner.state.get("scheduler_issues"):
                code = 2
                if runner.state["status"] == "complete":
                    runner.state["status"] = "finished_with_gaps"
            runner.save()
            registration.finish("complete" if code == 0 else "blocked", completed_units=0,
                                message="Routine execution only; independent validation and promotion remain required",
                                details={"routine_status": runner.state["status"], "formal_ready": False})
        return code


if __name__ == "__main__":
    raise SystemExit(main())
