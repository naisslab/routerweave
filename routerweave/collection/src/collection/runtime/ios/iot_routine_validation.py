"""Independent artifact checks for calendar routines; no appliance control."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
from xml.etree.ElementTree import ParseError

from collection.runtime.ios.iot_apple_home_capture import AppleHomeCollector
from collection.runtime.ios.iot_continuous_capture import Collector
from collection.runtime.ios.iot_routine import SUCCESS, atomic_json, fingerprint, read_json, capture_plan_matches, schedule_revisions
from collection.runtime.mobile_control.capture.pcap import iter_decoded_packets
from collection.runtime.mobile_control.capture.router import parse_tcpdump_trailer


def assess_loading_interruption(plan: dict, event: dict, step: dict, observations: list, rows: list) -> dict:
    """Derive a traffic-only view from retained evidence; never rewrite a step.

    Only the known loading-view observation failure is eligible. A later real
    read must bracket thirty seconds before any further command or deadline.
    Complete PCAP/own-unicast/drop checks still run in the normal validator.
    """
    try:
        kind = plan["actions"][step["action"]]["control"]
        if (step.get("status") != "uncertain" or plan["controls"][kind].get("acceptance_mode") != "command_traffic"
                or step.get("receipt_error")
                or step.get("reason") != f"command_observation_failed:Unknown or unguarded {kind} state: unknown"):
            return step
        start = float(step["receipt"]["gesture_start_epoch"])
        raw_post = [r for r in rows if r.get("event") == "routine_state_observed" and r.get("kind") == kind
                    and start <= r.get("observed_epoch", -1) <= step["finished_epoch"]]
        if not raw_post:
            return step
        failure = max(raw_post, key=lambda r: r["observed_epoch"])
        if not any(r["kind"] == kind and r["state"] == "loading" and r["source"] == failure["source"]
                   and r["observed_epoch"] == failure["observed_epoch"] for r in observations):
            return step
        limit = min(plan["end_epoch"], event["at_epoch"] + plan["max_lateness_seconds"])
        next_commands = [r["receipt"]["gesture_start_epoch"] for r in rows
                         if r.get("event") == "routine_step" and r.get("receipt", {}).get("gesture_start_epoch", -1) > start
                         and plan["actions"].get(r.get("action"), {}).get("control") == kind]
        device_id = plan["controls"][kind]["plan"]["devices"][0]["id"]
        next_commands.extend(r["epoch"] for r in rows if r.get("event") == "semantic_control_gesture_start"
                             and r.get("device") == device_id and r.get("epoch", -1) > start)
        if next_commands:
            limit = min(limit, min(next_commands))
        later = [r for r in observations if r["kind"] == kind and start + 30 <= r["observed_epoch"] <= limit]
        if not later:
            return step
        end = min(r["observed_epoch"] for r in later)
        if any(not any(o["source"] == r.get("source") and o["observed_epoch"] == r["observed_epoch"] for o in observations)
               for r in rows if r.get("event") == "routine_state_observed" and r.get("kind") == kind
               and start <= r.get("observed_epoch", -1) <= end):
            return step  # Unknown/blocked evidence cannot be hidden by a later readable view.
        observation = {"start_epoch": start, "end_epoch": end, "state_confirmed": False,
                       "acceptance_contract": "operator_accepted_command_traffic",
                       "scope": "retained known-loading interruption and later actual read; original checkpoint remains uncertain"}
        return {**step, "status": "command_recorded", "finished_epoch": end,
                "command_observation": observation, "retrospective_loading_assessment": True}
    except (KeyError, TypeError, ValueError):
        return step


def validate_run(root: Path) -> dict:
    root = root.resolve()
    plan = read_json(root / "routine.effective.json")
    state = read_json(root / "routine_state.json")
    capture_only = bool(plan.get("capture_only"))
    errors, captures, observations, action_errors, coverage_errors = [], [], [], [], []
    if state.get("plan_sha256") != fingerprint(plan):
        errors.append("checkpoint/effective-plan fingerprint mismatch")
    try:
        schedule_revisions(root, plan, state)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"schedule revision: {exc}")
    if state.get("updated_epoch", 0) < plan["end_epoch"]:
        coverage_errors.append("routine interval has not ended")
    # A control-worker interruption is separate from the capture's coverage.
    for key in ("capture_gaps", "capture_issues"):
        if state.get(key):
            coverage_errors.append(f"recorded {key}")
    sidecar = read_json(root / "collection_task.json")
    if (sidecar.get("registration_status") != "registered"
            or sidecar.get("task_id") != plan.get("collection_task_id")):
        errors.append("missing or mismatched registered collection task")
    log_path = root / "routine_events.jsonl"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows:
        if row.get("event") != "routine_state_observed":
            continue
        try:
            binding = plan["controls"][row["kind"]]["plan"]
            device = binding["devices"][0]
            if row.get("state") not in device["states"] and not (
                    binding.get("acceptance_mode") == "command_traffic" and row.get("state") in {"unknown", "loading"}):
                # A failed preparation can retain an empty/blocked view. It is
                # never usable as a successful step's state evidence.
                continue
            path = Path(row["source"]).resolve()
            if not path.is_relative_to(root / "evidence"):
                raise ValueError("native source path is outside the run's evidence directory")
            source = path.read_text(encoding="utf-8")
            if binding["control_platform"] == "alexa":
                reader = Collector.__new__(Collector)
                reader.plan = binding
                observed = reader.state(device, source) if reader._detail_is_target(device, source) else "unknown"
                from collection.runtime.ios.iot_routine_control import native_toggle_loading
                if observed == "unknown" and native_toggle_loading(binding, device, source):
                    observed = "loading"
            else:
                reader = AppleHomeCollector.__new__(AppleHomeCollector)
                reader.plan = binding
                observed = reader.observed_state(device, source)
            if row["state"] == "unknown":
                if observed != "loading":
                    continue
                row = {**row, "state": "loading", "recorded_state": "unknown"}
            if observed != row["state"]:
                raise ValueError("recorded native state disagrees with retained XML")
            if observed in device["states"] or observed == "loading":
                observations.append(row)
        except (OSError, KeyError, ValueError, RuntimeError, ParseError) as exc:
            errors.append(f"native evidence: {exc}")
    if not observations and not capture_only:
        action_errors.append("no independently readable native state evidence")
    if len(state["events"]) != len(plan["events"]):
        errors.append("event count differs from the effective plan")
    confirmed = 0
    command_windows = []
    for event, progress in zip(plan["events"], state["events"]):
        if event["id"] != progress["id"] or event["actions"] != [s["action"] for s in progress["steps"]]:
            errors.append("event/action identity differs from the effective plan")
        for step in progress["steps"]:
            recorded_step = step
            step = assess_loading_interruption(plan, event, step, observations, rows)
            if capture_only:
                if step["status"] != "manual_unverified":
                    errors.append("capture-only run contains an automated action checkpoint")
                continue
            if step["status"] not in SUCCESS:
                action_errors.append(f"{event['id']}/{step['action']}: {step['status']}")
                continue
            action = plan["actions"][step["action"]]
            control = action["control"]
            before = step.get("before")
            known = plan["controls"][control]["plan"]["devices"][0]["states"]
            finish = step.get("finished_epoch", -1)
            deadline = min(plan["end_epoch"], event["at_epoch"] + plan["max_lateness_seconds"])
            if before not in known or not event["at_epoch"] <= finish <= plan["end_epoch"]:
                errors.append("invalid successful step state or timestamp")
            if not any(row["kind"] == control and row["state"] == before
                       and event["at_epoch"] <= row.get("observed_epoch", -1) <= step.get("dispatch_epoch", finish)
                       for row in observations):
                errors.append("successful step lacks retained source-state evidence")
            status = step["status"]
            if status == "confirmed" and plan["controls"][control].get("acceptance_mode") == "command_traffic":
                errors.append("command-traffic contract cannot assert confirmed state")
            if status == "skipped_limit":
                order = action.get("state_order", [])
                if ("relative" not in action or before not in order
                        or 0 <= order.index(before) + action["relative"] < len(order)):
                    errors.append("skipped_limit is not an actual relative boundary")
            elif status == "observed":
                if action.get("observe") is not True:
                    errors.append("observed status used for a mutating action")
            elif status == "already_satisfied":
                if action.get("target") != before or step.get("target") != before:
                    errors.append("already_satisfied does not match the requested target")
            elif status in {"confirmed", "command_recorded"}:
                expected = action.get("target")
                if "relative" in action:
                    order = action["state_order"]
                    index = order.index(before) + action["relative"] if before in order else -1
                    expected = order[index] if 0 <= index < len(order) else None
                if expected is None or step.get("target") != expected or before == expected:
                    errors.append("confirmed target differs from requested action semantics")
                for required in action.get("requires", []):
                    if not any(row["kind"] == required["control"] and row["state"] == required["state"]
                               and event["at_epoch"] <= row.get("observed_epoch", -1) <= step.get("dispatch_epoch", -1)
                               for row in observations):
                        errors.append("confirmed command lacks its retained prerequisite")
            if status not in {"confirmed", "command_recorded"} and finish > deadline:
                errors.append("successful read/skip is outside the action deadline")
            if not any(row.get("event") == "routine_step" and row.get("event_id") == event["id"]
                       and row.get("action") == step["action"] and row.get("status") == recorded_step["status"]
                       and row.get("finished_epoch") == recorded_step.get("finished_epoch") for row in rows):
                errors.append("successful checkpoint lacks matching step event log")
            if status == "command_recorded":
                try:
                    binding = plan["controls"][control]
                    device = binding["plan"]["devices"][0]
                    from collection.runtime.ios.iot_routine_control import validate_binding
                    validate_binding(binding["plan"], device)
                    receipt, observation = step["receipt"], step["command_observation"]
                    start = receipt["gesture_start_epoch"]
                    end = observation["end_epoch"]
                    if (binding.get("acceptance_mode") != "command_traffic"
                            or step.get("receipt_error")
                            or binding["plan"].get("acceptance_mode") != "command_traffic"
                            or step.get("state_confirmed") is not False
                            or observation.get("state_confirmed") is not False
                            or observation.get("acceptance_contract") != "operator_accepted_command_traffic"
                            or receipt.get("gesture_type") != "tap"
                            or receipt.get("selected_control_name") != device["control_element_name"]
                            or receipt.get("source_state") != before
                            or receipt.get("requested_target") != step["target"]
                            or not event["at_epoch"] <= step["dispatch_epoch"] <= start <= deadline
                            or not start <= receipt["gesture_complete_epoch"] < end <= finish
                            or start - receipt["baseline_epoch"] < 5
                            or observation.get("start_epoch") != start or end - start < 30):
                        raise ValueError("invalid explicit command contract or gesture timing")
                    sources = [row for row in observations if row["kind"] == control and row["state"] == before
                               and receipt["baseline_epoch"] <= row["observed_epoch"] <= start]
                    reader = Collector.__new__(Collector)
                    if not any(reader._visible_named(Path(row["source"]).read_text(encoding="utf-8"),
                                                    device["control_element_name"]) is not None for row in sources):
                        raise ValueError("command lacks a fresh native named control")
                    if not any(row["kind"] == control and start + 30 <= row["observed_epoch"] <= end
                               for row in observations):
                        raise ValueError("command lacks retained post-command observation")
                    if not any(row.get("event") == "routine_step" and row.get("event_id") == event["id"]
                               and row.get("action") == step["action"] and row.get("receipt") == receipt
                               and (row.get("command_observation") == observation or (
                                   step.get("retrospective_loading_assessment") is True
                                   and row.get("status") == "uncertain" and row.get("reason") == recorded_step.get("reason")
                                   and row.get("finished_epoch") == recorded_step.get("finished_epoch")))
                               and row.get("dispatch_epoch") == step["dispatch_epoch"] for row in rows):
                        raise ValueError("command checkpoint disagrees with its event evidence")
                    command_windows.append({"event_id": event["id"], "action": step["action"],
                                            "start": start, "end": end, "mac": device["mac"].lower(),
                                            "ip": device["ip"], "unicast_packets": 0,
                                            "recorded_status": recorded_step["status"],
                                            "retrospective_loading_assessment": bool(step.get("retrospective_loading_assessment"))})
                except (KeyError, TypeError, ValueError, OSError) as exc:
                    errors.append(f"command evidence: {exc}")
                continue
            if step["status"] != "confirmed":
                continue
            confirmed += 1
            start, finish = step["dispatch_epoch"], step["finished_epoch"]
            if not event["at_epoch"] <= start <= min(plan["end_epoch"], event["at_epoch"] + plan["max_lateness_seconds"]):
                errors.append("command timestamp is outside its allowed calendar interval")
            control = plan["actions"][step["action"]]["control"]
            if not any(row["kind"] == control and row["state"] == step["target"]
                       and start <= row.get("observed_epoch", -1) <= finish for row in observations):
                errors.append(f"{event['id']}/{step['action']}: no retained postcondition XML in command window")
            if not any(row.get("event") == "routine_step" and row.get("event_id") == event["id"]
                       and row.get("action") == step["action"] and row.get("status") == "confirmed"
                       and row.get("dispatch_epoch") == start for row in rows):
                errors.append("confirmed checkpoint lacks matching command event log")
    target_macs = {b["plan"]["devices"][0]["mac"].lower() for b in plan["controls"].values()}
    target_counts = dict.fromkeys(target_macs, 0)
    usable_windows = []
    for segment in state.get("segments", []):
        try:
            path = Path(segment["path"]).resolve()
            if not path.is_relative_to(root / "raw"):
                raise ValueError("capture path is outside this run")
            count = inside = 0
            segment_targets = dict.fromkeys(target_macs, 0)
            for packet in iter_decoded_packets(path, ip_only=True, include_link_identity=True):
                count += 1
                inside += plan["start_epoch"] <= packet["ts_epoch"] < plan["end_epoch"]
                matches = {packet.get("src_mac"), packet.get("dst_mac")} & target_macs
                if not matches:
                    raise ValueError("IP packet is outside the registered device MAC scope")
                if plan["start_epoch"] <= packet["ts_epoch"] < plan["end_epoch"]:
                    for mac in matches:
                        segment_targets[mac] += 1
                if packet["captured_length"] != packet["length"]:
                    raise ValueError("capture contains truncated frames")
                for window in command_windows:
                    if (window["start"] <= packet["ts_epoch"] < window["end"]
                            and window["mac"] in {packet.get("src_mac"), packet.get("dst_mac")}
                            and window["ip"] in {packet.get("src_ip"), packet.get("dst_ip")}
                            and not int(packet["dst_mac"].split(":")[0], 16) & 1
                            and all(not ipaddress.ip_address(packet[key]).is_multicast
                                    and packet[key] != "255.255.255.255" for key in ("src_ip", "dst_ip"))):
                        window["unicast_packets"] += 1
            stderr = path.with_suffix(path.suffix + ".tcpdump.stderr.log")
            statistics = parse_tcpdump_trailer(stderr.read_text(encoding="utf-8", errors="replace"))
            if statistics["kernel_dropped"] != 0:
                raise ValueError("nonzero or unavailable final drop count")
            if statistics["captured"] is None or statistics["captured"] < count:
                raise ValueError("final tcpdump packet count is missing or smaller than decoded IP count")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            captures.append({"path": str(path), "bytes": path.stat().st_size,
                             "sha256": digest, "ip_packet_count": count,
                             "ip_packets_inside_routine": inside, "statistics": statistics,
                             "device_packet_counts": segment_targets})
            for mac, number in segment_targets.items():
                target_counts[mac] += number
            if inside:
                usable_windows.append({"start_epoch": max(plan["start_epoch"], segment.get("ready_epoch", plan["start_epoch"])),
                                       "end_epoch": min(plan["end_epoch"], segment.get("stopped_epoch", plan["end_epoch"])),
                                       "capture": str(path), "scope": "validated capture segment; action success is separate"})
        except (OSError, KeyError, ValueError, RuntimeError) as exc:
            errors.append(f"capture: {exc}")
    if not captures or not sum(c["ip_packets_inside_routine"] for c in captures):
        errors.append("no decoded IP packets inside the routine interval")
    if any(number == 0 for number in target_counts.values()):
        errors.append("at least one registered device has no retained IP traffic")
    if any(window["unicast_packets"] == 0 for window in command_windows):
        action_errors.append("a recorded command has no device MAC/IP unicast in its actual window")
    capture_state_path = root / "capture_state.json"
    if capture_state_path.exists() and not capture_plan_matches(root, plan, read_json(capture_state_path).get("plan_sha256")):
        errors.append("capture checkpoint plan mismatch")
    segments = state.get("segments", [])
    for previous, current in zip(segments, segments[1:]):
        if current.get("ready_epoch", float("inf")) > previous.get("stopped_epoch", 0):
            coverage_errors.append("independently detected a gap between capture segments")
    margin = plan.get("capture_margin_seconds", 0) if capture_only else 0
    required_start, required_end = plan["start_epoch"] - margin, plan["end_epoch"] + margin
    if (not segments or segments[0].get("ready_epoch", float("inf")) > required_start
            or segments[-1].get("stopped_epoch", 0) < required_end):
        coverage_errors.append("capture does not bracket the planned interval")
    capture_complete = (not coverage_errors and bool(captures) and all(target_counts.values())
                        and not any(e.startswith("capture:") for e in errors))
    report = {"schema_version": "iot-routine-validation-v1", "artifact_valid": not (errors or action_errors or coverage_errors),
              "capture_complete": capture_complete, "actions_complete": not capture_only and not action_errors and not errors,
              "capture_only": capture_only, "actions_assessed": not capture_only,
              "required_capture_window": {"start_epoch": required_start, "end_epoch": required_end},
              "integrity_errors": errors, "action_errors": action_errors, "coverage_errors": coverage_errors,
              "usable_capture_windows": usable_windows, "device_packet_counts": target_counts,
              "formal_ready": False, "errors": errors + action_errors + coverage_errors, "confirmed_steps": confirmed,
              "native_observations": len(observations), "captures": captures,
              "command_recorded_steps": len(command_windows), "command_traffic_windows": command_windows,
              "scope": "artifact integrity and retained UI evidence; not physical-state, per-device causal traffic, or energy accuracy"}
    inputs = {root / name for name in ("routine.effective.json", "routine_state.json", "routine_events.jsonl")}
    inputs.update(path for path in (capture_state_path, root / "routine.capture-plan.json") if path.exists())
    inputs.update(root.glob("routine.schedule-revision-*.json"))
    inputs.update(Path(row["source"]) for row in observations)
    for capture in captures:
        path = Path(capture["path"])
        inputs.update((path, path.with_suffix(path.suffix + ".tcpdump.stderr.log")))
    report["inputs"] = [{"path": str(path.resolve()), "bytes": path.stat().st_size,
                         "mtime_ns": path.stat().st_mtime_ns} for path in sorted(inputs) if path.is_file()]
    atomic_json(root / "routine_validation.json", report)
    return report


def accepted_routine_units(root: Path, sidecar: dict) -> int:
    """Cheap dashboard freshness gate for the independently accepted receipt."""
    try:
        details = sidecar.get("details") or {}
        if not isinstance(details, dict):
            return 0
        if (sidecar.get("completed_units") != 1 or sidecar.get("artifact_purpose") != "formal"
                or sidecar.get("status") != "complete" or not details.get("routine_artifact_valid")):
            return 0
        report_path = root / "routine_validation.json"
        if hashlib.sha256(report_path.read_bytes()).hexdigest() != details.get("validation_sha256"):
            return 0
        report = read_json(report_path)
        if (not report.get("artifact_valid") or not report.get("actions_complete")
                or report.get("capture_only") or not report.get("inputs")):
            return 0
        for item in report["inputs"]:
            path = Path(item["path"]).resolve()
            if not path.is_relative_to(root.resolve()):
                return 0
            stat = path.stat()
            if stat.st_size != item["bytes"] or stat.st_mtime_ns != item["mtime_ns"]:
                return 0
        return 1
    except (OSError, KeyError, TypeError, ValueError):
        return 0


def accept_run(root: Path, *, defer_closeout_pid: int | None = None) -> dict:
    """Revalidate real artifacts and credit one routine, never an action quota."""
    from collection.runtime.registry.tasks import CollectionTaskRun, require_collection_task
    report = validate_run(root)
    plan, sidecar = read_json(root / "routine.effective.json"), read_json(root / "collection_task.json")
    task = require_collection_task(plan["collection_task_id"], kind="iot", platform=plan["control_platform"])
    eligible = (report["artifact_valid"] and report["actions_complete"] and not plan.get("capture_only")
                and task.get("collection_type") == "iot_routine"
                and task.get("metadata", {}).get("routine_plan_id") == plan["plan_id"]
                and 0 < float(task.get("minimum_duration_seconds") or 0) <= plan["duration_seconds"]
                and sidecar.get("artifact_purpose") == "formal" and not (root / "STOP").exists())
    registration = CollectionTaskRun(root, plan["collection_task_id"])
    passive_ok = bool(plan.get("capture_only") and report["artifact_valid"])
    registration.finish("complete" if eligible or passive_ok else "blocked", completed_units=1 if eligible else 0,
                        message=("Passive capture validated; manual actions not assessed" if passive_ok else
                                 "Independent routine validation accepted" if eligible else "Routine retained; review validation dimensions"),
                        details={"formal_ready": False,
                                 **({"counts_toward_task": False} if sidecar.get("artifact_purpose") == "validation" else {}),
                                 "routine_artifact_valid": report["artifact_valid"],
                                 "validation_sha256": hashlib.sha256((root / "routine_validation.json").read_bytes()).hexdigest()},
                        validation_finished=defer_closeout_pid is None)
    if defer_closeout_pid is not None:
        from collection.runtime.run_retention import defer_closeout_run
        defer_closeout_run(root, wait_pid=defer_closeout_pid)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--accept", action="store_true", help="Revalidate and update the registered routine progress")
    args = parser.parse_args()
    try:
        report = accept_run(args.run_root) if args.accept else validate_run(args.run_root)
    except (OSError, KeyError, ValueError, RuntimeError) as exc:
        report = {"artifact_valid": False, "formal_ready": False, "errors": [f"unreadable run: {exc}"]}
        atomic_json(args.run_root / "routine_validation.json", report)
    print(f"artifact_valid={report['artifact_valid']}; errors={len(report['errors'])}")
    return 0 if report["artifact_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
