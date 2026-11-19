"""Operator annotations alongside the shared router stream; no phone automation."""

from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import datetime, timezone
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

from collection.runtime.registry.tasks import (
    DEFAULT_CONFIG_ROOT, CollectionTaskRun, load_collection_tasks, require_collection_task,
)
from .capture.pcap import iter_decoded_packets, valid_pcap_header
from .capture.router import RouterStreamCapture, _router_ssh
from .collection import CollectionEventLog, RouterCaptureConfig


REQUEST_KIND = "manual_ground_truth"
CAPTURE_SCOPES = {"device_ip": "Device only", "lan_diagnostic": "Whole network (diagnostic)"}


def manual_capture_filter(router, scope):
    # Exclude the SSH stream carrying the PCAP so it cannot capture itself.
    return (f"not (host {router.host} and tcp port 22)" if scope == "lan_diagnostic"
            else f"host {router.phone_ip}")


EVENT_TIMINGS = {"video_doorbell": (10, 30), "motion_sensor": (30, 120),
                 "environmental_sensor": (60, 300)}
CSV_FIELDS = (
    "segment_id", "label", "app", "note", "screen_state", "start_utc", "end_utc",
    "pc_start_epoch", "pc_end_epoch", "router_start_epoch", "router_end_epoch",
    "duration_seconds", "clock_uncertainty_seconds", "end_reason",
)


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def timestamp() -> dict[str, float]:
    return {"pc_epoch": time.time(), "monotonic": time.perf_counter()}


def measure_router_clock(router: RouterCaptureConfig) -> dict[str, Any]:
    """Bound offset by SSH round-trip and the router date command's resolution."""
    samples = []
    timeouts = []
    # Reading date is safe to retry. Still require three real samples and allow only
    # one replacement probe; never retry the capture lifecycle or reuse old clocks.
    for attempt in range(4):
        before = timestamp()
        try:
            result = _router_ssh(router.user, router.host, "date +%s.%N",
                                 identity_file=router.identity_file, timeout=8)
        except subprocess.TimeoutExpired as exc:
            def decoded_tail(value):
                return (value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or "")[-2000:]
            timeouts.append({"attempt": attempt + 1, "pc_epoch": before["pc_epoch"],
                             "timeout_seconds": 8, "stdout_tail": decoded_tail(exc.stdout),
                             "stderr_tail": decoded_tail(exc.stderr)})
            if len(timeouts) > 1:
                error = RuntimeError(
                    f"Two SSH clock checks on {router.host} timed out after 8 seconds each. Clock alignment could not be verified. "
                    "Diagnostic records were retained. Check the SSH subprocess for timeouts after login."
                )
                error.clock_probe_timeouts = timeouts
                raise error from exc
            continue
        after = timestamp()
        raw = result.stdout.strip()
        match = re.fullmatch(r"(\d{9,})(?:\.(\d*|%N|N))?", raw)
        if result.returncode or not match:
            raise RuntimeError("Cannot read the router clock: " + (result.stderr.strip() or raw))
        fraction = match.group(2) or ""
        resolution = 10 ** (-len(fraction)) if fraction.isdigit() else 1.0
        remote = float(match.group(1) + ("." + fraction if fraction.isdigit() else ""))
        rtt = after["monotonic"] - before["monotonic"]
        if abs(after["pc_epoch"] - before["pc_epoch"] - rtt) > 0.1:
            raise RuntimeError("The host clock jumped. Stabilize the system time and retry.")
        samples.append({
            "pc_midpoint_epoch": (before["pc_epoch"] + after["pc_epoch"]) / 2,
            "router_epoch": remote, "resolution_seconds": resolution,
            "round_trip_seconds": rtt,
            "offset_seconds": remote + resolution / 2 - (before["pc_epoch"] + after["pc_epoch"]) / 2,
            "uncertainty_seconds": (rtt + resolution) / 2,
        })
        if len(samples) == 3:
            break
    best = min(samples, key=lambda row: row["uncertainty_seconds"])
    if best["uncertainty_seconds"] > 1:
        raise RuntimeError("Clock calibration error exceeds one second. Check the router connection and retry.")
    return {**best, "samples": samples, "method": "ssh_date_midpoint", "probe_timeouts": timeouts}


def read_events(root: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (root / "manual_ground_truth" / "events.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]


def segments_from_events(events: list[dict[str, Any]], clock: dict[str, Any], *, allow_open=False) -> list[dict[str, Any]]:
    """Rebuild closed operator intervals; fail on overlap or ambiguous boundaries."""
    active = None
    rows = []
    previous_mono = -math.inf
    ready = False
    finished = False
    seen = set()
    anchor = None
    expanded = []
    for event in events:
        if event["event"] == "segment_switch":
            expanded.extend([{**event, "event": "segment_end", "segment_id": event["previous_segment_id"],
                              "reason": "operator_switch"}, {**event, "event": "segment_start"}])
        else:
            expanded.append(event)
    end_requested = False
    for event in expanded:
        kind = event["event"]
        pc, mono = float(event["pc_epoch"]), float(event["monotonic"])
        if not math.isfinite(pc) or not math.isfinite(mono) or mono < previous_mono:
            raise ValueError("Annotation timestamps are invalid or out of order.")
        previous_mono = mono
        if anchor and abs((pc - anchor[0]) - (mono - anchor[1])) > 0.25:
            raise ValueError("The host clock jumped during collection. Review the clock alignment.")
        if kind == "capture_ready":
            if ready or finished:
                raise ValueError("Duplicate collection start event.")
            ready, anchor = True, (pc, mono)
        elif kind == "segment_start":
            if not ready or finished or end_requested or active or event["segment_id"] in seen:
                raise ValueError("A task overlaps another task, is duplicated, or falls outside the capture window.")
            if not event.get("label", "").strip() or event.get("screen_state") not in {"on", "off", "unknown"}:
                raise ValueError("Invalid task label or screen state.")
            seen.add(event["segment_id"])
            active = event
        elif kind == "event_mark":
            if not ready or finished or end_requested or active:
                raise ValueError("An event marker falls outside the capture window or overlaps a continuous task.")
            if not event.get("label", "").strip():
                raise ValueError("Missing event label.")
        elif kind == "segment_end":
            if not active or active["segment_id"] != event["segment_id"]:
                raise ValueError("Task end has no matching start.")
            if mono <= active["monotonic"]:
                raise ValueError("Task duration must be positive.")
            offset = float(clock["offset_seconds"])
            rows.append({
                "segment_id": active["segment_id"], "label": active["label"],
                "app": active["app"], "note": active["note"], "screen_state": active["screen_state"],
                "start_utc": datetime.fromtimestamp(active["pc_epoch"], timezone.utc).isoformat(timespec="milliseconds"),
                "end_utc": datetime.fromtimestamp(pc, timezone.utc).isoformat(timespec="milliseconds"),
                "pc_start_epoch": active["pc_epoch"], "pc_end_epoch": pc,
                "router_start_epoch": active["pc_epoch"] + offset, "router_end_epoch": pc + offset,
                "duration_seconds": mono - active["monotonic"],
                "clock_uncertainty_seconds": clock["uncertainty_seconds"],
                "end_reason": event["reason"],
            })
            active = None
        elif kind == "capture_end_requested":
            if not ready or finished or active or end_requested:
                raise ValueError("The stop request is inconsistent with the task state.")
            end_requested = True
        elif kind == "capture_stopped":
            if not ready or finished or active:
                raise ValueError("The collection end event is inconsistent with the task state.")
            finished = True
        else:
            raise ValueError("Unknown annotation event: " + str(kind))
    if active and not allow_open:
        raise ValueError("A task is still open. The original start event was retained for review.")
    return rows


def csv_text(rows: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def network_windows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": row["segment_id"], "label": row["label"],
             "annotation_source": "operator", "screen_state": row["screen_state"],
             "actual": {"start_epoch": row["router_start_epoch"], "end_epoch": row["router_end_epoch"]}}
            for row in rows]


def event_windows(events, manifest, *, now=None):
    """Keep point timestamps distinct from their surrounding traffic windows."""
    protocol = manifest.get("manual_protocol", {})
    if protocol.get("mode") != "event_markers":
        return []
    start = events[0]
    end = next((e for e in events if e["event"] == "capture_end_requested"), now)
    offset = manifest["clock_start"]["offset_seconds"]
    pre, post = protocol["pre_seconds"], protocol["post_seconds"]
    rows, seen = [], set()
    for mark in (e for e in events if e["event"] == "event_mark"):
        if (mark["event_id"] in seen or mark["label"] not in protocol["actions"]
                or mark["input_source"] not in {"keyboard_space", "button"}
                or mark.get("evidence_basis") != "operator_physical_action"):
            raise ValueError("Invalid event marker identity, label, or operator source.")
        seen.add(mark["event_id"])
        complete_pre = mark["monotonic"] - start["monotonic"] >= pre
        complete_post = end is not None and end["monotonic"] - mark["monotonic"] >= post
        rows.append(dict(event_id=mark["event_id"], label=mark["label"], note=mark["note"],
                         pc_event_epoch=mark["pc_epoch"], router_event_epoch=mark["pc_epoch"] + offset,
                         pc_start_epoch=mark["pc_epoch"] - pre, pc_end_epoch=mark["pc_epoch"] + post,
                         router_start_epoch=mark["pc_epoch"] + offset - pre,
                         router_end_epoch=mark["pc_epoch"] + offset + post,
                         pre_seconds=pre, post_seconds=post, complete_pre=complete_pre,
                         complete_post=complete_post, input_eligible=complete_pre and complete_post,
                         input_source=mark["input_source"], evidence_basis=mark["evidence_basis"],
                         state_verified=False,
                         clock_uncertainty_seconds=manifest["clock_start"]["uncertainty_seconds"]))
    # Windows may overlap: these are distinct physical actions, not disjoint screen states.
    for row in rows:
        row["overlaps_other_event"] = any(other is not row and
            row["pc_start_epoch"] < other["pc_end_epoch"] and other["pc_start_epoch"] < row["pc_end_epoch"]
            for other in rows)
    return rows


class ManualGroundTruthSession:
    def __init__(self, root: Path, router: RouterCaptureConfig, task_id: str, *,
                 capture_factory=RouterStreamCapture, clock_reader=measure_router_clock,
                 config_root: str | Path = DEFAULT_CONFIG_ROOT, capture_scope="device_ip") -> None:
        if capture_scope not in CAPTURE_SCOPES:
            raise ValueError("Unknown manual capture scope")
        self.capture_scope = capture_scope
        self.root = Path(root).resolve()
        self.router = router
        self.task_id = task_id
        self.capture_factory = capture_factory
        self.clock_reader = clock_reader
        # The task registry is injectable so a test can pin the task states it
        # needs instead of depending on the operator's current progress markers.
        self.config_root = Path(config_root).resolve()
        self.capture = None
        self.active: dict[str, Any] | None = None
        self.rows: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.state = "idle"
        self.error = ""
        self.manifest: dict[str, Any] = {}
        self.protocol: dict[str, Any] = {}
        self.tracker = CollectionTaskRun(self.root, task_id, config_root=self.config_root)

    def configure_iot(self, *, observation=False):
        if self.state != "idle":
            raise ValueError("Choose a mode before starting collection.")
        task = require_collection_task(self.task_id, config_root=self.config_root, kind="iot")
        if task["kind"] != "iot" or (not observation and task["category"] not in EVENT_TIMINGS):
            raise ValueError("Select a registered doorbell, motion, or environmental sensor task.")
        if task["metadata"].get("manual_observation_only") and not observation:
            raise ValueError("This task supports continuous device observation only and produces no platform state events.")
        pre, post = EVENT_TIMINGS.get(task["category"], (0, 0))
        self.protocol = dict(mode="background_observation" if observation else "event_markers",
                             pre_seconds=pre, post_seconds=post, category=task["category"],
                             actions=[row["key"] for row in task["breakdown"]],
                             device_id=task["metadata"].get("dataset_device_id") or task["metadata"].get("device_id"),
                             device_name=task["title"], platform=task["platform"],
                             evidence_basis="operator_physical_action", state_verification="not_performed",
                             human_timing_uncertainty_seconds=None,
                             capture_identity="operator_entered_ip")

    def _event(self, kind: str, at: dict[str, float] | None = None, **fields: Any) -> dict[str, Any]:
        row = {**(at or timestamp()), "event": kind, **fields}
        with (self.root / "manual_ground_truth" / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.events.append(row)
        return row

    def start(self) -> None:
        if self.state != "idle":
            raise ValueError("This run has already started.")
        self.router.validate()
        task = require_collection_task(self.task_id, config_root=self.config_root,
                                       kind="iot" if self.protocol else "manual",
                                       **({'platform': self.protocol['platform']} if self.protocol else {}))
        if self.capture_scope == "lan_diagnostic" and not self.protocol:
            raise ValueError("Whole-network diagnostics require an IoT observation session")
        # Never overwrite a former run, including an interrupted one.
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root / "manual_ground_truth").mkdir()
        self.tracker.start(kind=task["kind"], platform=task["platform"])
        self.state = "starting"
        self.manifest = {
            "schema_version": "manual-ground-truth-v2", "collection_task_id": self.task_id,
            "request": {"request_kind": REQUEST_KIND, "platform": task["platform"], "app_name": "",
                        "isolate_other_apps": False},
            "attribution_mode": "none", "traffic_scope": self.capture_scope,
            "capture_filter": manual_capture_filter(self.router, self.capture_scope),
            "diagnostic_only": self.capture_scope == "lan_diagnostic",
            "annotation_source": "operator", "router": asdict(self.router),
            "status": "starting", "error": "",
        }
        if self.protocol:
            self.manifest["manual_protocol"] = self.protocol.copy()
        write_json(self.root / "collection_manifest.json", self.manifest)
        try:
            self.manifest["clock_start"] = self.clock_reader(self.router)
            self.capture = self.capture_factory(
                user=self.router.user, host=self.router.host, interface=self.router.interface,
                phone_ip=self.router.phone_ip, local_pcap=self.root / "capture.pcap",
                log=CollectionEventLog(self.root / "collection_events.jsonl"),
                identity_file=self.router.identity_file,
                **({"capture_filter": self.manifest['capture_filter']} if self.capture_scope == "lan_diagnostic" else {}),
            )
            self.capture.start()
            deadline = time.monotonic() + 6
            while not valid_pcap_header(self.root / "capture.pcap"):
                if self.capture.proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("No valid PCAP header received. Check the router and capture interface.")
                time.sleep(0.1)
            self._event("capture_ready")
            self.state = "recording"
            self.manifest["status"] = self.state
            write_json(self.root / "collection_manifest.json", self.manifest)
            self._export()
        except Exception as exc:
            self.error = str(exc)
            if hasattr(exc, "clock_probe_timeouts"):
                self.manifest["clock_probe_timeouts"] = exc.clock_probe_timeouts
            try:
                self._stop_capture()
            except Exception as cleanup_error:
                self.error += "; cleanup: " + str(cleanup_error)
            self.state = "failed"
            self.manifest.update(status="failed", error=self.error)
            write_json(self.root / "collection_manifest.json", self.manifest)
            self.tracker.finish("failed", message=self.error)
            raise

    def _stop_capture(self) -> None:
        if not self.capture:
            return
        try:
            self.capture.stop()
        except Exception:
            # Do not leave an unmonitored local SSH process on cleanup failure.
            # The run retains its exact remote PID marker in collection events.
            proc = self.capture.proc
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            self.capture.close_files()
            raise

    def health_error(self) -> str:
        if self.state != "recording":
            return ""
        if self.capture.proc.poll() is not None:
            return "The router capture connection was interrupted. Review this run."
        now = timestamp()
        start = self.events[0]
        if abs(now["pc_epoch"] - start["pc_epoch"] - now["monotonic"] + start["monotonic"]) > 0.25:
            return "The host clock jumped. Review clock alignment for this run."
        return ""

    def begin_segment(self, label: str, app: str = "", note: str = "", screen_state: str = "on", *, at=None) -> None:
        at = at or timestamp()
        if self.protocol:
            raise ValueError("Select event marking or continuous observation for IoT collection.")
        if self.state != "recording" or self.active:
            raise ValueError("Start collection or finish the active task first.")
        if problem := self.health_error():
            raise RuntimeError(problem)
        if not label.strip() or len(label) > 160 or len(app) > 160 or len(note) > 2000:
            raise ValueError("Enter a task label of up to 160 characters and a note of up to 2,000 characters.")
        if screen_state not in {"on", "off", "unknown"}:
            raise ValueError("Select a screen state.")
        self.active = self._event("segment_start", at, segment_id=f"segment-{len(self.rows)+1:04d}",
                                  label=label.strip(), app=app.strip(), note=note.strip(), screen_state=screen_state)

    def mark_event(self, label, note="", *, at=None, input_source="button"):
        at = at or timestamp()
        if self.state != "recording" or self.protocol.get("mode") != "event_markers":
            raise ValueError("Start IoT event collection first.")
        if label not in self.protocol["actions"] or len(note) > 2000:
            raise ValueError("Select a registered event for this device and limit the note to 2,000 characters.")
        if input_source not in {"keyboard_space", "button"}:
            raise ValueError("Unknown event marker source.")
        if problem := self.health_error():
            raise RuntimeError(problem)
        previous = self.events[-1]
        if (at["monotonic"] < previous["monotonic"] or
                abs(at["pc_epoch"] - previous["pc_epoch"] - at["monotonic"] + previous["monotonic"]) > .25):
            raise ValueError("The marker timestamps are out of order or the host clock changed.")
        count = sum(e["event"] == "event_mark" for e in self.events)
        self._event("event_mark", at, event_id=f"event-{count+1:04d}", label=label,
                    note=note.strip(), input_source=input_source, evidence_basis="operator_physical_action")
        self._export()

    def end_segment(self, reason: str = "operator_end", at: dict[str, float] | None = None) -> None:
        at = at or timestamp()
        if not self.active:
            raise ValueError("No task is being recorded.")
        self._event("segment_end", at, segment_id=self.active["segment_id"], reason=reason)
        self.active = None
        self._export()

    def switch_segment(self, label: str, app: str = "", note: str = "", screen_state: str = "on") -> None:
        """One durable event closes the old task and opens the new at the same instant."""
        at = timestamp()
        if self.state != "recording" or not self.active:
            raise ValueError("Start the current task first.")
        if problem := self.health_error():
            raise RuntimeError(problem)
        if not label.strip() or len(label) > 160 or len(app) > 160 or len(note) > 2000:
            raise ValueError("Invalid task label or note.")
        if screen_state not in {"on", "off", "unknown"}:
            raise ValueError("Select a screen state.")
        self.active = self._event("segment_switch", at, previous_segment_id=self.active["segment_id"],
                                  segment_id=f"segment-{len(self.rows)+2:04d}", label=label.strip(),
                                  app=app.strip(), note=note.strip(), screen_state=screen_state)
        self._export()

    def _export(self) -> None:
        self.rows = segments_from_events(self.events, self.manifest["clock_start"], allow_open=True)
        temporary = self.root / "labels.csv.tmp"
        with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
            handle.write(csv_text(self.rows))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.root / "labels.csv")
        write_json(self.root / "network_capture_windows.json", network_windows(self.rows))
        if self.protocol:
            write_json(self.root / "manual_event_windows.json", event_windows(self.events, self.manifest))

    def stop(self, error: str = "", at: dict[str, float] | None = None) -> Any:
        if self.state != "recording":
            raise ValueError("Collection is not running.")
        at = at or timestamp()
        error = error or self.health_error()
        self.state = "stopping"
        self.error = error
        try:
            if self.active:
                self.end_segment("interrupted" if error else "session_stop", at=at)
            self._event("capture_end_requested", at, error=error)
        except Exception as exc:
            self.error = self.error or str(exc)
        try:
            self._stop_capture()
        except Exception as exc:
            self.error = self.error or str(exc)
        try:
            self.manifest["clock_end"] = self.clock_reader(self.router)
        except Exception as exc:
            self.error = self.error or str(exc)
            if hasattr(exc, "clock_probe_timeouts"):
                self.manifest["clock_probe_timeouts"] = exc.clock_probe_timeouts
        self._event("capture_stopped", error=self.error)
        self._export()
        self.manifest.update(status="stopped", error=self.error)
        write_json(self.root / "collection_manifest.json", self.manifest)
        from .validation import validate_mobile_collection, write_mobile_collection_validation
        validation = validate_mobile_collection(self.root)
        write_mobile_collection_validation(validation, self.root / "collection_validation.json")
        self.state = "complete" if validation.collection_ready else "failed"
        self.tracker.finish(self.state, completed_units=0,
                            message="Manual annotations retained for review; no dataset promotion.",
                            details={"operator_segments": len(self.rows), "collection_ready": validation.collection_ready},
                            validation_finished=True)
        return validation


def _manual_actions_match(protocol: dict, task: dict, manifest: dict) -> bool:
    actions = protocol.get("actions")
    if actions == [row["key"] for row in task["breakdown"]]:
        return True
    # Retired quotas must not invalidate evidence captured before their removal.
    started = float(manifest["clock_start"]["pc_midpoint_epoch"])
    return any(actions == previous["actions"] and started < previous["retired_at_epoch"]
               for previous in task.get("metadata", {}).get("retired_manual_protocols", []))


def validate_manual_ground_truth(root: Path, manifest: dict[str, Any]):
    """Validate disk evidence, never infer app ownership or actual attention."""
    from .validation import MobileCollectionValidation
    errors: list[str] = []
    warnings = ["Operator labels are self-reported. Human reaction delay is not included in clock uncertainty."]
    metrics: dict[str, Any] = {}
    try:
        protocol = manifest.get("manual_protocol", {})
        platform = manifest["request"]["platform"]
        kind = "iot" if protocol else "manual"
        scope = manifest.get("traffic_scope")
        diagnostic = scope == "lan_diagnostic"
        if (manifest["attribution_mode"] != "none"
                or manifest.get("annotation_source") != "operator" or scope not in CAPTURE_SCOPES):
            raise ValueError("Invalid platform or traffic mode for manual collection.")
        if diagnostic and (not protocol or manifest.get("diagnostic_only") is not True
                           or manifest.get("capture_filter") != manual_capture_filter(
                               RouterCaptureConfig(**manifest['router']), scope)):
            raise ValueError("Whole-network diagnostics require an explicit scope and diagnostic flag.")
        if diagnostic:
            warnings.append("Whole-network diagnostic capture; unrelated endpoints are not target-device or formal action evidence.")
        else:
            warnings.append("Only traffic matching the recorded IP is captured; other addresses and cellular traffic are excluded.")
        binding = json.loads((root / "collection_task.json").read_text(encoding="utf-8"))
        task_id = manifest["collection_task_id"]
        task = next((row for row in load_collection_tasks() if row["id"] == task_id), None)
        if (not task or task["kind"] != kind or task["platform"] != platform
                or binding.get("task_id") != task_id or binding.get("registration_status") != "registered"
                or binding.get("kind") != kind or binding.get("platform") != platform
                or (not protocol and platform not in ("ios", "android", "windows"))):
            raise ValueError("The collection task is unregistered or its binding is inconsistent.")
        if protocol:
            if (protocol["mode"] not in {"event_markers", "background_observation"}
                    or (protocol["mode"] == "event_markers" and task["category"] not in EVENT_TIMINGS)
                    or protocol["category"] != task["category"]
                    or protocol["platform"] != platform
                    or (protocol["pre_seconds"], protocol["post_seconds"]) != EVENT_TIMINGS.get(task["category"], (0, 0))
                    or not _manual_actions_match(protocol, task, manifest)
                    or protocol.get("state_verification") != "not_performed"):
                raise ValueError("The manual IoT protocol differs from the registered task.")
            if task["metadata"].get("manual_observation_only") and protocol["mode"] != "background_observation":
                raise ValueError("Continuous device observation cannot be bound to platform state events.")
        if manifest["status"] != "stopped" or manifest.get("error"):
            errors.append("Collection ended unexpectedly: " + str(manifest.get("error") or manifest["status"]))
        start, end = manifest["clock_start"], manifest["clock_end"]
        for clock in (start, end):
            for key in ("offset_seconds", "uncertainty_seconds", "pc_midpoint_epoch"):
                if not math.isfinite(float(clock[key])):
                    raise ValueError("Invalid clock calibration data.")
            if not 0 <= clock["uncertainty_seconds"] <= 1:
                errors.append("Clock alignment error exceeds one second.")
        drift = abs(end["offset_seconds"] - start["offset_seconds"])
        metrics["clock_offset_change_seconds"] = drift
        metrics["clock_uncertainty_seconds"] = start["uncertainty_seconds"]
        if drift > start["uncertainty_seconds"] + end["uncertainty_seconds"] + 0.25:
            errors.append("The offset between router and host clocks changed during collection.")
        events = read_events(root)
        rows = segments_from_events(events, start)
        if not events or events[-1]["event"] != "capture_stopped" or events[-1].get("error"):
            errors.append("Missing collection completion event.")
        if not rows and not protocol:
            errors.append("No complete manually marked task interval.")
        marks = [e for e in events if e["event"] == "event_mark"]
        if marks and protocol.get("mode") != "event_markers":
            errors.append("Event markers do not match the collection mode.")
        if protocol and rows:
            errors.append("IoT point events and continuous task labels cannot be combined.")
        if protocol:
            points = event_windows(events, manifest)
            if json.loads((root / "manual_event_windows.json").read_text(encoding="utf-8")) != points:
                errors.append("Event windows differ from the original markers.")
            if protocol["mode"] == "event_markers" and not points:
                errors.append("No manually recorded event markers.")
            metrics.update(event_count=len(points), complete_event_windows=sum(p["input_eligible"] for p in points))
            if any(not p["input_eligible"] for p in points):
                warnings.append("Incomplete pre/post event windows are retained but excluded from event input.")
            warnings.append("Point labels describe operator physical actions, not verified sensor-state timestamps.")
        if manifest.get("schema_version") == "manual-ground-truth-v2" and not any(
                event["event"] == "capture_end_requested" for event in events):
            errors.append("Missing collection stop-request time.")
        if any(row["end_reason"] not in {"operator_end", "session_stop", "operator_switch"} for row in rows):
            errors.append("A task interval ended unexpectedly.")
        logical_end = next((e["pc_epoch"] for e in events if e["event"] == "capture_end_requested"),
                           rows[-1]["pc_end_epoch"] if rows else events[-1]["pc_epoch"])
        if start["pc_midpoint_epoch"] > events[0]["pc_epoch"] or end["pc_midpoint_epoch"] < logical_end:
            errors.append("Clock measurements do not cover the annotation interval.")
        with (root / "labels.csv").open(encoding="utf-8-sig", newline="") as handle:
            actual = list(csv.DictReader(handle))
        expected = list(csv.DictReader(io.StringIO(csv_text(rows))))
        if actual != expected:
            errors.append("labels.csv differs from the original button events.")
        windows = json.loads((root / "network_capture_windows.json").read_text(encoding="utf-8"))
        if windows != network_windows(rows):
            errors.append("Traffic windows differ from the original button events.")
        ip = manifest["router"]["phone_ip"]
        total, matching = 0, 0
        counts = {row["segment_id"]: 0 for row in rows}
        for packet in iter_decoded_packets(root / "capture.pcap", ip_only=True):
            total += 1
            if ip not in {packet["src_ip"], packet["dst_ip"]}:
                if diagnostic:
                    continue
                errors.append("The PCAP contains IP traffic that does not involve the target address.")
                break
            matching += 1
            for row in rows:
                if row["router_start_epoch"] <= packet["ts_epoch"] < row["router_end_epoch"]:
                    counts[row["segment_id"]] += 1
                    break
        if not matching:
            (warnings if diagnostic else errors).append("The PCAP contains no IP packets for the target device.")
        if diagnostic and not total:
            errors.append("The whole-network diagnostic PCAP contains no IP packets.")
        metrics.update(capture_bytes=(root / "capture.pcap").stat().st_size,
                       decoded_ip_packets=total, device_packets=matching,
                       traffic_scope=scope, diagnostic_only=diagnostic,
                       segment_count=len(rows), packets_by_segment=counts,
                       annotated_seconds=sum(row["duration_seconds"] for row in rows))
        if any(count == 0 for count in counts.values()):
            warnings.append("Some labeled intervals have zero packets; this does not imply the screen was off.")
    except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    return MobileCollectionValidation(
        str(root), manifest.get("request", {}).get("platform", "ios"), "", not errors, False, tuple(dict.fromkeys(errors)),
        ("Manual device-level annotations have no app attribution or automatic behavior verification.",),
        tuple(warnings), metrics, "none", not errors,
    )
