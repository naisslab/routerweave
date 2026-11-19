"""Operator annotations with optional shared manual capture ownership.

Reuses the manual collector lifecycle; never advances formal sample progress.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import threading
import uuid
from dataclasses import replace

from collection.runtime.registry.tasks import load_collection_tasks
from .collection import RouterCaptureConfig
from .manual_ground_truth import EVENT_TIMINGS, measure_router_clock, timestamp, write_json

FIELDS = ("event_id", "task_id", "device_name", "platform", "action", "note",
          "received_utc", "pc_epoch", "monotonic", "router_epoch",
          "clock_uncertainty_seconds", "clock_alignment_valid", "input_source",
          "client_epoch", "voided", "evidence_basis", "state_verified",
          "pre_seconds", "post_seconds", "cooldown_seconds", "baseline_start_monotonic",
          "baseline_ready", "timing_protocol_source", "post_window_complete",
          "requires_outcome", "outcome", "outcome_note", "confirmed_pc_epoch",
          "confirmed_monotonic", "confirmed_router_epoch", "outcome_clock_alignment_valid",
          "interval_seconds", "outcome_evidence_basis")


def marker_protocol(task, action, *, plans_root=None):
    """Use the existing physical-event protocol or an exact plan/action match."""
    pre, post = EVENT_TIMINGS.get(task.get("category"), (5, 30))
    protocol = {"pre_seconds": pre, "post_seconds": post, "cooldown_seconds": 0,
                "source": "manual-screen-time category protocol" if task.get("category") in EVENT_TIMINGS else "manual annotation default: 5s baseline / 30s blank"}
    if task.get("category") in EVENT_TIMINGS:
        return protocol
    folder = Path(plans_root) if plans_root else Path(__file__).resolve().parents[4] / "configs" / "plans"
    identities = {task["metadata"].get(k) for k in ("device_id", "dataset_device_id") if task.get("metadata", {}).get(k)} if task.get("metadata") else set()
    matches = []
    for path in folder.glob("*.json"):
        try:
            plan = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(plan, dict) or plan.get("control_platform") != task.get("platform"):
                continue
            for device in plan.get("devices", []):
                if device.get("id") not in identities:
                    continue
                if action not in {r.get("name") for r in device.get("actions", []) if isinstance(r, dict)}:
                    continue
                if "baseline_seconds" in device and "tail_seconds" in device:
                    matches.append((path, float(device["baseline_seconds"]), float(device["tail_seconds"]),
                                    float(device.get("inter_action_cooldown_seconds", 0))))
        except (OSError, ValueError, TypeError):
            continue
    if matches:
        # Where historical plans coexist, disclose a conservative timing prompt.
        protocol = {"pre_seconds": max(r[1] for r in matches), "post_seconds": max(r[2] for r in matches),
                    "cooldown_seconds": max(r[3] for r in matches), "source": "; ".join(str(r[0]) for r in matches)}
    return protocol


def marker_schedule(protocol, *, selected_at, started_at, last_mark, now):
    pre, post, cooldown = (protocol[k] for k in ("pre_seconds", "post_seconds", "cooldown_seconds"))
    tail_end = (last_mark["monotonic"] + last_mark.get("post_seconds", post)) if last_mark else started_at
    cooldown_end = tail_end + last_mark.get("cooldown_seconds", 0) if last_mark else started_at
    baseline_start = max(selected_at, started_at, cooldown_end)
    ready = baseline_start + pre
    phase = "post" if now < tail_end else "cooldown" if now < cooldown_end else "baseline" if now < ready else "ready"
    target = tail_end if phase == "post" else cooldown_end if phase == "cooldown" else ready
    return {"phase": phase, "remaining_seconds": max(0, target - now), "ready_monotonic": ready,
            "baseline_start_monotonic": baseline_start, "baseline_ready": now >= ready,
            "post_remaining_seconds": max(0, tail_end - now)}


class MarkerSession:
    def __init__(self, parent, router, *, clock_reader=measure_router_clock, tasks=None):
        self.parent = Path(parent).resolve()
        self.router, self.clock_reader = router, clock_reader
        self.tasks = {t["id"]: t for t in (tasks if tasks is not None else load_collection_tasks())
                      if t["kind"] == "iot" and t.get("breakdown")
                      and t.get("configured_status") != "cancelled"
                      and not t.get("metadata", {}).get("manual_observation_only")}
        self.lock = threading.RLock()
        self.root = None
        self.manifest = {"status": "idle", "capture_owned": False}
        self.events, self.requests = [], {}
        self.capture_session = None

    def start_capture(self, task_id, router, *, session_factory=None, identity_resolver=None,
                      capture_scope="device_ip"):
        """Compose the existing manual capture lifecycle with this annotation log."""
        from .manual_ground_truth import CAPTURE_SCOPES, ManualGroundTruthSession
        from collection.runtime.registry.tasks import require_collection_task
        from .manual_network import resolve_task_identity
        with self.lock:
            if capture_scope not in CAPTURE_SCOPES:
                raise ValueError("Unknown manual capture scope")
            if self.manifest['status'] == 'recording':
                raise ValueError('Finish the current session before starting a new capture')
            task = require_collection_task(task_id, kind='iot')
            identity = (identity_resolver or resolve_task_identity)(task, router)
            router = replace(router, phone_ip=identity['ip'])
            router.validate()
            self.router = router
            self.start()
            self.manifest.update(capture_owned=True, capture_task_id=task_id,
                                 network_identity=identity,
                                 traffic_scope=capture_scope,
                                 diagnostic_only=capture_scope == 'lan_diagnostic',
                                 capture_reference=str(self.root / 'network'))
            write_json(self.root / 'marker_manifest.json', self.manifest)
            factory = session_factory or ManualGroundTruthSession
            try:
                self.capture_session = factory(self.root / 'network', router, task['id'],
                    **({'capture_scope': capture_scope} if capture_scope != 'device_ip' else {}))
                self.capture_session.configure_iot(observation=True)
                self.capture_session.protocol['capture_identity'] = (
                    'network_context' if capture_scope == 'lan_diagnostic' else identity['scope'])
                self.capture_session.start()
                self.capture_session.manifest['network_identity'] = identity.copy()
                write_json(self.capture_session.root / 'collection_manifest.json', self.capture_session.manifest)
            except Exception as exc:
                self.manifest['capture_error'] = str(exc)
                self.stop()
                raise
            try:
                self._append({'event': 'capture_linked', 'capture_reference': self.manifest['capture_reference'], **timestamp()})
            except Exception:
                self.stop()
                raise
            return self.state()

    def capture_status(self):
        capture = self.capture_session
        if not capture:
            return {'recording': False, 'bytes': 0, 'ip': '', 'error': self.manifest.get('capture_error', '')}
        path = capture.root / 'capture.pcap'
        problem = capture.health_error() if capture.state == 'recording' else capture.error
        return {'recording': capture.state == 'recording' and not problem,
                'bytes': path.stat().st_size if path.exists() else 0,
                'ip': capture.router.phone_ip, 'error': problem, 'state': capture.state}

    def catalog(self):
        return [{"id": t["id"], "name": t["title"], "platform": t["platform"],
                 "platform_label": t["platform_label"], "category": t.get("category"),
                 "metadata": t.get("metadata", {}), "actions": t["breakdown"]}
                for t in self.tasks.values()]

    def start(self, capture_reference=""):
        with self.lock:
            if self.manifest["status"] == "recording":
                return self.state()
            if not isinstance(capture_reference, str) or len(capture_reference) > 500:
                raise ValueError("Capture reference must be at most 500 characters")
            # Calibrate before creating an annotation session. No capture is started.
            clock = self.clock_reader(self.router)
            at = timestamp()
            self.root = self.parent / (datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])
            self.root.mkdir(parents=True, exist_ok=False)
            self.events, self.requests = [], {}
            self.capture_session = None
            self.manifest = {"schema_version": "manual-event-marker-v2", "session_id": self.root.name,
                             "status": "recording", "capture_owned": False,
                             "capture_reference": capture_reference.strip(),
                             "clock_start": clock, "started": at,
                             "timestamp_basis": "local_input_handler",
                             "human_timing_uncertainty_seconds": None,
                             "state_verification": "not_performed"}
            write_json(self.root / "marker_manifest.json", self.manifest)
            self._append({"event": "session_start", **at})
            self._export()
            return self.state()

    def _append(self, row):
        with (self.root / "events.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.events.append(row)

    def _require_recording(self):
        if self.manifest["status"] != "recording":
            raise ValueError("Start a marker session first")

    def mark(self, payload, *, at=None):
        at = at or timestamp()
        with self.lock:
            self._require_recording()
            request_id = str(payload.get("request_id", ""))
            try:
                uuid.UUID(request_id)
            except ValueError as exc:
                raise ValueError("A valid event request ID is required") from exc
            task = self.tasks.get(payload.get("task_id"))
            action, note = payload.get("action"), payload.get("note", "")
            if not task or action not in {r["key"] for r in task["breakdown"]}:
                raise ValueError("Select a registered action for this device")
            if not isinstance(note, str) or len(note) > 2000:
                raise ValueError("Note must be at most 2000 characters")
            source = payload.get("input_source", "button")
            if source not in {"button", "keyboard_space"}:
                raise ValueError("Unknown event input source")
            signature = (task["id"], action, note, source)
            if request_id in self.requests:
                old = self.requests[request_id]
                if old[0] != signature:
                    raise ValueError("Request ID is already used by another event")
                self._export()
                return old[1]
            previous = self.events[-1]
            if at["monotonic"] < previous["monotonic"]:
                raise ValueError("Event timestamp is out of order; retry")
            start = self.manifest["started"]
            jump = at["pc_epoch"] - start["pc_epoch"] - (at["monotonic"] - start["monotonic"])
            # Retain the point if the wall clock jumped, but disclose invalid alignment.
            valid = abs(jump) <= .25
            client_epoch = payload.get("client_epoch")
            if client_epoch is not None:
                if not isinstance(client_epoch, (int, float)) or not 0 <= client_epoch <= 1e11:
                    raise ValueError("Invalid client timestamp")
            clock = self.manifest["clock_start"]
            row = {"event": "event_mark", "event_id": request_id, "task_id": task["id"],
                   "device_name": task["title"], "platform": task["platform"], "action": action,
                   "note": note.strip(), **at,
                   "received_utc": datetime.fromtimestamp(at["pc_epoch"], timezone.utc).isoformat(),
                   "router_epoch": at["pc_epoch"] + clock["offset_seconds"] if valid else None,
                   "clock_uncertainty_seconds": clock["uncertainty_seconds"] if valid else None,
                   "clock_alignment_valid": valid, "wall_clock_jump_seconds": jump,
                   "client_epoch": client_epoch, "input_source": source,
                   "evidence_basis": "operator_reported_action", "state_verified": False}
            for key in ("pre_seconds", "post_seconds", "cooldown_seconds", "baseline_start_monotonic", "baseline_ready", "timing_protocol_source", "requires_outcome"):
                if key in payload:
                    row[key] = payload[key]
            self._append(row)
            self.requests[request_id] = (signature, row)
            self._export()
            return row

    def confirm(self, event_id, outcome, *, note="", at=None):
        """Record the operator's observed result without claiming machine verification."""
        at = at or timestamp()
        with self.lock:
            self._require_recording()
            if outcome not in {"success", "failed", "uncertain"}:
                raise ValueError("Choose success, failed, or uncertain")
            if not isinstance(note, str) or len(note) > 2000:
                raise ValueError("Note must be at most 2000 characters")
            mark = next((r for r in self.events if r['event'] == 'event_mark' and r['event_id'] == event_id), None)
            if not mark or any(r['event'] == 'event_void' and r['event_id'] == event_id for r in self.events):
                raise ValueError("Select an existing, non-voided command")
            previous = next((r for r in self.events if r['event'] == 'event_result' and r['event_id'] == event_id), None)
            if previous:
                if (previous['outcome'], previous['note']) != (outcome, note.strip()):
                    raise ValueError("This command already has a recorded result")
                self._export()
                return previous
            if at['monotonic'] < self.events[-1]['monotonic']:
                raise ValueError("Result timestamp is out of order")
            start = self.manifest['started']
            jump = at['pc_epoch'] - start['pc_epoch'] - (at['monotonic'] - start['monotonic'])
            valid = abs(jump) <= .25
            row = {'event': 'event_result', 'event_id': event_id, 'outcome': outcome,
                   'note': note.strip(), **at, 'clock_alignment_valid': valid,
                   'router_epoch': at['pc_epoch'] + self.manifest['clock_start']['offset_seconds'] if valid else None,
                   'evidence_basis': 'operator_reported_result', 'state_verified': False}
            self._append(row)
            self._export()
            return row

    def undo(self, event_id):
        with self.lock:
            self._require_recording()
            marks = {r["event_id"] for r in self.events if r["event"] == "event_mark"}
            if event_id not in marks:
                raise ValueError("Event not found")
            if not any(r["event"] == "event_void" and r["event_id"] == event_id for r in self.events):
                self._append({"event": "event_void", "event_id": event_id, **timestamp()})
            self._export()
            return self.state()

    def stop(self):
        with self.lock:
            if self.manifest["status"] == "saved":
                self._export()
                return self.state()
            self._require_recording()
            persistence_error = None
            if not any(e['event'] == 'session_stop' for e in self.events):
                try:
                    self._append({"event": "session_stop", **timestamp()})
                except Exception as exc:
                    persistence_error = exc
                    self.manifest['stop_record_error'] = str(exc)
            if self.capture_session and self.capture_session.state == 'recording':
                try:
                    validation = self.capture_session.stop(error=self.manifest.get('capture_error', ''))
                    self.manifest['capture_collection_ready'] = bool(validation.collection_ready)
                    if self.capture_session.error:
                        self.manifest['capture_error'] = self.capture_session.error
                except Exception as exc:
                    self.manifest['capture_error'] = str(exc)
                    # Shared lifecycle owns exact PID cleanup; never stop another capture.
                    self.capture_session._stop_capture()
            # Also retry exact cleanup after a failed start or interrupted stop.
            capture = getattr(self.capture_session, 'capture', None)
            proc = getattr(capture, 'proc', None)
            if proc is not None and proc.poll() is None:
                self.capture_session._stop_capture()
                if proc.poll() is None:
                    raise RuntimeError('Capture is still running; retry Finish & save.')
            self.manifest["status"] = "saved"
            try:
                self.manifest["clock_end"] = self.clock_reader(self.router)
            except Exception as exc:
                self.manifest["clock_end_error"] = str(exc)
            write_json(self.root / "marker_manifest.json", self.manifest)
            self._export()
            if persistence_error:
                raise persistence_error
            return self.state()

    def rows(self):
        voids = {r["event_id"] for r in self.events if r["event"] == "event_void"}
        results = {r['event_id']: r for r in self.events if r['event'] == 'event_result'}
        end = self.manifest.get("clock_end")
        start = self.manifest.get("clock_start", {})
        end_error = self.manifest.get("clock_end_error")
        drift = abs(end["offset_seconds"] - start["offset_seconds"]) if end else 0
        bound = max(start.get("uncertainty_seconds", 0), end["uncertainty_seconds"] + drift) if end else start.get("uncertainty_seconds")
        result = []
        for r in self.events:
            if r["event"] != "event_mark":
                continue
            row = {k: r.get(k) for k in FIELDS}
            row["voided"] = r["event_id"] in voids
            outcome = results.get(r['event_id'])
            row['outcome'] = outcome['outcome'] if outcome else 'unconfirmed'
            if outcome:
                row.update(outcome_note=outcome['note'], confirmed_pc_epoch=outcome['pc_epoch'],
                           confirmed_monotonic=outcome['monotonic'], confirmed_router_epoch=outcome['router_epoch'],
                           outcome_clock_alignment_valid=outcome['clock_alignment_valid'] and not bool(end_error),
                           interval_seconds=outcome['monotonic'] - r['monotonic'],
                           outcome_evidence_basis=outcome['evidence_basis'])
            if row["clock_alignment_valid"]:
                row["clock_uncertainty_seconds"] = bound
            if end_error:
                row["clock_alignment_valid"] = False
            stopped = next((e for e in self.events if e["event"] == "session_stop"), None)
            if stopped and "post_seconds" in r:
                anchor = outcome['monotonic'] if outcome else r['monotonic']
                row["post_window_complete"] = (not r.get('requires_outcome') or bool(outcome)) and stopped["monotonic"] >= anchor + r["post_seconds"]
            result.append(row)
        return result

    def csv(self):
        with self.lock:
            out = io.StringIO(newline="")
            writer = csv.DictWriter(out, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(self.rows())
            return out.getvalue()

    def _export(self):
        temp = self.root / "markers.csv.tmp"
        with temp.open("w", encoding="utf-8-sig", newline="") as handle:
            handle.write(self.csv())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.root / "markers.csv")

    def state(self):
        with self.lock:
            rows = self.rows()
            return {"status": self.manifest["status"], "session_id": self.manifest.get("session_id"),
                    "count": sum(not r["voided"] for r in rows), "rows": rows[-50:],
                    "clock_start": self.manifest.get("clock_start"),
                    "clock_end_error": self.manifest.get("clock_end_error"),
                    "catalog": self.catalog(), "capture_owned": self.manifest.get('capture_owned', False),
                    "server_epoch": timestamp()["pc_epoch"]}
