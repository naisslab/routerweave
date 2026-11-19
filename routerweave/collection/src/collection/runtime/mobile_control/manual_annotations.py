"""Complete operator timeline and append-only reviews, separate from model outputs."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import shutil
from datetime import datetime, timezone

from collection.runtime.capture.pcap import pcap_format
from .capture.router import parse_tcpdump_trailer
from .manual_ground_truth import read_events, segments_from_events, write_json, event_windows

SOURCE_FILES = ("capture.pcap", "collection_manifest.json", "collection_task.json",
                "manual_ground_truth/events.jsonl", "labels.csv", "network_capture_windows.json",
                "capture.pcap.tcpdump.stderr.log", "manual_event_windows.json")
GAP_POLICY = "operator_unassigned_intervals_are_no_task"
PACKET_FIELDS = ['packet_index','ts_epoch','length','captured_length','direction','ip_protocol','in_collection_interval']


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sources(root):
    return {name: sha256(root / name) for name in SOURCE_FILES if (root / name).is_file()}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def bounds(root):
    events = read_events(root)
    manifest = read_json(root / "collection_manifest.json")
    ready = next(row for row in events if row["event"] == "capture_ready")
    end = next((row for row in events if row["event"] == "capture_end_requested"), events[-1])
    if events[-1]["event"] != "capture_stopped" or end["pc_epoch"] <= ready["pc_epoch"]:
        raise ValueError("Finish collection before reviewing or scoring this run.")
    return ready["pc_epoch"], end["pc_epoch"], manifest


def validate_timeline(rows, start, end):
    cursor = start
    if not rows:
        raise ValueError("The timeline is empty.")
    for row in rows:
        a, b = row["pc_start_epoch"], row["pc_end_epoch"]
        if not all(math.isfinite(x) for x in (a, b)) or abs(a - cursor) > 1e-6 or b <= a:
            raise ValueError("The timeline contains a gap, overlap, or invalid boundary.")
        if row["screen_state"] not in {"on", "off", "unknown"} or not row["label"].strip():
            raise ValueError("Invalid screen state or label.")
        if row["review_status"] not in {"pending", "recorded", "confirmed", "excluded"}:
            raise ValueError("Invalid review status.")
        if row["review_status"] in {"recorded", "confirmed"} and row["label"] in {"unknown", "no_task"}:
            raise ValueError("Label the unknown activity or exclude its interval before confirming ground truth.")
        if row["review_status"] == "excluded" and not row.get("reason", "").strip():
            raise ValueError("Provide a reason for excluding the interval.")
        cursor = b
    if abs(cursor - end) > 1e-6:
        raise ValueError("The timeline does not cover the full run.")


def original_timeline(root):
    start, end, manifest = bounds(root)
    completed = segments_from_events(read_events(root), manifest["clock_start"])
    rows, cursor = [], start
    for segment in completed:
        a, b = segment["pc_start_epoch"], segment["pc_end_epoch"]
        if a > cursor:
            rows.append(no_task_interval(cursor, a))
        rows.append({key: segment[key] for key in ("pc_start_epoch", "pc_end_epoch", "label", "app", "screen_state")}
                    | dict(review_status="pending" if segment["label"] == "unknown" else "recorded",
                           reason=segment["note"], source=segment["segment_id"]))
        cursor = b
    if end > cursor:
        rows.append(no_task_interval(cursor, end))
    validate_timeline(rows, start, end)
    return rows


def no_task_interval(start, end):
    return dict(pc_start_epoch=start, pc_end_epoch=end, label="no_task", app="",
                screen_state="unknown", review_status="excluded", reason=GAP_POLICY, source="gap")


def load_timeline(root):
    root = Path(root).resolve()
    rows = original_timeline(root)
    start, end, _ = bounds(root)
    fingerprint = None
    parent = None
    for index, path in enumerate(sorted((root / "manual_ground_truth" / "reviews").glob("*.json")), 1):
        review = read_json(path)
        if fingerprint is None:
            fingerprint = sources(root)
        if (path.name != f"{index:06d}.json" or review["revision"] != index
                or review["previous_sha256"] != parent or review["source_sha256"] != fingerprint):
            raise ValueError("The source files or review records have changed. Check the source and revision history.")
        rows = review["timeline"]
        validate_timeline(rows, start, end)
        parent = sha256(path)
    # Apply the operator's current rule to untouched gaps in older reviews without rewriting them.
    return [no_task_interval(row['pc_start_epoch'], row['pc_end_epoch'])
            if row['source']=='gap' and row['label']=='unknown' and row['review_status']=='pending'
            else row for row in rows]


def revise_interval(root, *, start, end, label, app, screen_state, reason, exclude=False):
    """Replace a range, splitting its neighbors; exclusive file creation prevents lost updates."""
    root = Path(root).resolve()
    rows = load_timeline(root)
    lower, upper, _ = bounds(root)
    if not math.isfinite(start) or not math.isfinite(end) or not lower <= start < end <= upper:
        raise ValueError("The revised interval must fall within the collection window.")
    if not reason.strip() or len(reason) > 2000 or not label.strip() or len(label) > 160 or len(app) > 160:
        raise ValueError("Enter a label and the basis for the annotation or revision (up to 2,000 characters).")
    if label in {"unknown", "no_task"} and not exclude:
        raise ValueError("Exclude any interval you cannot confirm and provide a reason.")
    revised = []
    for row in rows:
        a, b = row["pc_start_epoch"], row["pc_end_epoch"]
        if b <= start or a >= end:
            revised.append(row)
        else:
            if a < start:
                revised.append({**row, "pc_end_epoch": start})
            if b > end:
                revised.append({**row, "pc_start_epoch": end})
    revised.append(dict(pc_start_epoch=start, pc_end_epoch=end, label=label.strip(), app=app.strip(),
                        screen_state=screen_state, review_status="excluded" if exclude else "confirmed",
                        reason=reason.strip(), source="operator_review"))
    revised.sort(key=lambda row: row["pc_start_epoch"])
    validate_timeline(revised, lower, upper)
    folder = root / "manual_ground_truth" / "reviews"
    folder.mkdir(exist_ok=True)
    previous = sorted(folder.glob("*.json"))
    revision = len(previous) + 1
    value = dict(schema="manual-timeline-review-v1", revision=revision,
                 created_utc=datetime.now(timezone.utc).isoformat(),
                 previous_sha256=sha256(previous[-1]) if previous else None,
                 source_sha256=sources(root), timeline=revised)
    with (folder / f"{revision:06d}.json").open("x", encoding="utf-8") as handle:
        import os
        json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())
    return revised


def capture_audit(root):
    """Count every stored frame, including ARP, and require a clean tcpdump trailer."""
    path = root / "capture.pcap"
    count = truncated = 0
    with path.open("rb") as handle:
        header = handle.read(24)
        endian, _ = pcap_format(header, path)
        while record := handle.read(16):
            if len(record) != 16:
                raise ValueError("Incomplete PCAP record header.")
            _, _, captured, original = struct.unpack(endian + "IIII", record)
            if len(handle.read(captured)) != captured:
                raise ValueError("Incomplete PCAP packet.")
            count += 1
            truncated += captured < original
    log = root / "capture.pcap.tcpdump.stderr.log"
    text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
    statistics = parse_tcpdump_trailer(text)
    captured, dropped = statistics["captured"], statistics["kernel_dropped"]
    errors = []
    if captured is None or dropped is None:
        errors.append("Missing tcpdump completion or packet-drop statistics.")
    elif captured != count or dropped:
        errors.append("Packet counts disagree or the router reported dropped packets.")
    if truncated:
        errors.append("The capture contains truncated packets.")
    return dict(pcap_frames=count, truncated_frames=truncated,
                kernel_dropped=dropped, errors=errors)


def snapshot(root):
    from .validation import validate_mobile_collection
    root = Path(root).resolve()
    validation = validate_mobile_collection(root)
    start, end, manifest = bounds(root)
    rows = load_timeline(root)
    clock = manifest["clock_start"]
    # Retain the recorded initial offset; increase the guard to include the final bound.
    uncertainty = max(clock["uncertainty_seconds"],
                      abs(manifest["clock_end"]["offset_seconds"] - clock["offset_seconds"])
                      + manifest["clock_end"]["uncertainty_seconds"])
    for row in rows:
        row.update(router_start_epoch=row["pc_start_epoch"] + clock["offset_seconds"],
                   router_end_epoch=row["pc_end_epoch"] + clock["offset_seconds"])
    durations = {status: sum(row["pc_end_epoch"] - row["pc_start_epoch"] for row in rows
                            if row["review_status"] == status) for status in ("pending", "recorded", "confirmed", "excluded")}
    audit = capture_audit(root)
    errors = list(validation.core_errors) + audit["errors"]
    value = dict(schema="manual-ground-truth-timeline-v2", run=str(root), source_sha256=sources(root),
                pc_start_epoch=start, pc_end_epoch=end,
                router_start_epoch=start + clock["offset_seconds"], router_end_epoch=end + clock["offset_seconds"],
                clock_uncertainty_seconds=uncertainty, phone_ip=manifest["router"]["phone_ip"],
                duration_seconds=end-start, review_seconds=durations,
                gap_policy=GAP_POLICY,
                no_task_seconds=sum(row['pc_end_epoch']-row['pc_start_epoch'] for row in rows if row['label']=='no_task'),
                task_data_ready=not errors and not durations['pending'] and bool(durations['recorded']+durations['confirmed']),
                labels_complete=all(row["review_status"] in {"recorded", "confirmed"} for row in rows),
                review_complete=all(row["review_status"] != "pending" for row in rows),
                capture_ready=not errors, errors=errors, capture_audit=audit, timeline=rows,
                review_sha256={p.name: sha256(p) for p in sorted((root/'manual_ground_truth'/'reviews').glob('*.json'))},
                warnings=list(validation.warnings),
                legacy_end_includes_teardown=not any(e["event"] == "capture_end_requested" for e in read_events(root)))
    if manifest.get("manual_protocol"):
        points = event_windows(read_events(root), manifest)
        for point in points:
            point["clock_uncertainty_seconds"] = uncertainty
        value.update(manual_protocol=manifest["manual_protocol"], event_windows=points,
                     task_data_ready=not errors and (manifest["manual_protocol"]["mode"] == "background_observation"
                                                     or any(p["input_eligible"] for p in points)))
    return value


def write_csv(path, rows, fields=None):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields or (list(rows[0]) if rows else []))
        writer.writeheader()
        writer.writerows(rows)


def export_snapshot(root, out):
    root = Path(root).resolve()
    value = snapshot(root)
    if not value['capture_ready']:
        raise ValueError('Capture integrity check failed. Original files retained: '+'; '.join(value['errors']))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    write_json(out/'export_manifest.json', dict(schema='manual-ground-truth-export-v2', status='writing'))
    write_json(out / "ground_truth.json", value)
    if "event_windows" in value:
        write_json(out / "event_windows.json", value["event_windows"])
        if value["event_windows"]:
            write_csv(out / "event_windows.csv", value["event_windows"])
    rows = export_rows(value)
    write_csv(out / "ground_truth.csv", rows)
    usable = [row for row in rows if row['usable_label']]
    write_csv(out / "labeled_segments.csv", usable, fields=list(rows[0]))
    shutil.copyfile(root/'capture.pcap', out/'capture.pcap')
    evidence = out/'evidence'
    evidence.mkdir()
    for name in value['source_sha256']:
        if name == 'capture.pcap':
            continue
        target = evidence/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/name, target)
    for name in ('collection_events.jsonl','collection_validation.json'):
        if (root/name).is_file():
            shutil.copyfile(root/name, evidence/name)
    for name in value['review_sha256']:
        target = evidence/'manual_ground_truth'/'reviews'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/'manual_ground_truth'/'reviews'/name, target)
    for name, expected in value['source_sha256'].items():
        copied = out/'capture.pcap' if name=='capture.pcap' else evidence/name
        if sha256(copied) != expected:
            raise ValueError('The copy differs from its source: '+name)
    packet_count = write_packet_csv(out, value)
    current = snapshot(root)
    if current != value:
        raise ValueError('Collection data or annotations changed during export. The partial export was retained. Start a new export.')
    manifest = dict(schema='manual-ground-truth-export-v2', status='complete',
                    capture_ready=value['capture_ready'], labels_complete=value['labels_complete'],
                    review_complete=value['review_complete'],
                    fully_labeled_ready=value['capture_ready'] and value['labels_complete'],
                    task_data_ready=value['task_data_ready'], gap_policy=GAP_POLICY,
                    no_task_seconds=value['no_task_seconds'],
                    usable_labeled_seconds=sum(row['duration_seconds'] for row in usable) if value['capture_ready'] else 0,
                    pending_seconds=value['review_seconds']['pending'], excluded_seconds=value['review_seconds']['excluded'],
                    ip_packets=packet_count, label_segments=len(usable), phone_ip=value['phone_ip'],
                    input_scope='ground_truth_intervals_with_input_eligible_true', input_pcap='capture.pcap',
                    packet_scope='continuous_capture',
                    timestamp_unit='Unix seconds', packet_clock='router',
                    label_interval='half-open [router_start_epoch, router_end_epoch)',
                    clock_uncertainty_seconds=value['clock_uncertainty_seconds'],
                    source_run=str(root), original_source_sha256=value['source_sha256'],
                    errors=value['errors'])
    (out/'README.md').write_text(
        '# Manually annotated activity data\n\n'
        'capture.pcap contains the full continuous capture with its original timestamps.\n'
        'packets.csv contains all target-IP packets. ground_truth.csv covers the full run, including no_task gaps.\n'
        'Use intervals marked input_eligible=True in ground_truth.csv to construct inputs. These intervals are also listed in labeled_segments.csv.\n'
        'Match packet ts_epoch to [router_start_epoch, router_end_epoch) in the label table. All times are in Unix seconds.\n'
        'length is the original frame length in bytes. The in/out direction is relative to the target phone.\n'
        'Intervals marked no_task are excluded from inputs and scores and do not belong to the background class.\n'
        'Preserve the continuous timeline and keep samples within eligible intervals. Explicit transition tasks follow their own scoring protocol.\n'
        'In packets.csv, in_collection_interval indicates whether a packet falls within the run boundaries. Use the label table to determine input eligibility.\n'
        'Startup and shutdown packets outside those boundaries are retained and excluded from inputs and scores.\n'
        'Annotation status is recorded for button labels, confirmed for reviewed or revised labels, pending for unknown activities, and excluded for explicit exclusions.\n'
        'In export_manifest.json, task_data_ready indicates whether task data are ready. no_task_seconds measures excluded idle gaps that require no further annotation.\n'
        'pending_seconds counts only tasks marked unknown. excluded_seconds includes no-task intervals and manual exclusions.\n'
        'clock_uncertainty_seconds excludes operator reaction time. The evidence/ directory contains the raw evidence and each revision.\n'
        'The export contains capture data and annotations only.\n', encoding='utf-8')
    if "manual_protocol" in value:
        observation = value['manual_protocol']['mode'] == 'background_observation'
        manifest.update(manual_protocol=value['manual_protocol'],
                        input_scope='continuous_background_observation' if observation else 'event_windows_with_input_eligible_true',
                        event_count=len(value['event_windows']),
                        complete_event_windows=sum(p['input_eligible'] for p in value['event_windows']))
        (out/'README.md').write_text(
            '# Manually recorded IoT events\n\n'
            'capture.pcap contains the continuous raw capture. packets.csv contains all target-IP packets. Times are in Unix seconds.\n'
            'manual_protocol records the platform, device, annotation method, and requested pre- and post-event windows. The operator supplies the IP address without automatic identity verification.\n'
            'The event window JSON and CSV record pc_event_epoch, the router-aligned router_event_epoch, and the windows before and after each event.\n'
            'Match packet ts_epoch to [router_start_epoch, router_end_epoch). input_eligible=True requires complete traffic coverage on both sides of the event.\n'
            'overlaps_other_event=True flags overlapping windows. Treat these as potentially correlated, multi-event samples.\n'
            'Labels identify the action taken by the operator. With state_verified=False, the recorded time does not establish when the sensor changed state.\n'
            'clock_uncertainty_seconds includes clock alignment error at both ends of the run. It excludes manual synchronization error and sensor response delay. PCAP timestamps retain their original values.\n'
            'Continuous observation records routine traffic without automatic state labels. Analyze packets within the run boundaries.\n'
            'ground_truth.csv describes the continuous task timeline. Use event_windows for point events and the continuous traffic for observation runs.\n'
            'The evidence/ directory contains original markers, task registration, clock measurements, and window evidence. Runs with formal_ready=False do not count toward formal sample totals.\n',
            encoding='utf-8')
    manifest['artifact_sha256'] = {p.relative_to(out).as_posix(): sha256(p) for p in out.rglob('*')
                                   if p.is_file() and p.name != 'export_manifest.json'}
    write_json(out/'export_manifest.json', manifest)
    verify_export(out)
    return value


def packet_rows(path, value):
    """Retain every IP packet in source order; eligibility belongs to the label timeline."""
    from .capture.pcap import iter_decoded_packets
    phone_ip = value['phone_ip']
    for packet in iter_decoded_packets(path, ip_only=True):
        if phone_ip not in {packet['src_ip'], packet['dst_ip']}:
            raise ValueError('The PCAP contains IP traffic from outside the target device.')
        yield dict(packet_index=packet['index'], ts_epoch=packet['ts_epoch'],
                   length=packet['length'], captured_length=packet['captured_length'],
                   direction='in' if packet['dst_ip']==phone_ip else 'out', ip_protocol=packet['ip_protocol'],
                   in_collection_interval=value['router_start_epoch'] <= packet['ts_epoch'] < value['router_end_epoch'])


def write_packet_csv(out, value):
    count = 0
    with (out/'packets.csv').open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=PACKET_FIELDS)
        writer.writeheader()
        for row in packet_rows(out/'capture.pcap', value):
            writer.writerow(row)
            count += 1
    return count


def export_rows(value):
    rows = []
    for index,row in enumerate(value['timeline'],1):
        rows.append(dict(segment_id=f'interval-{index:04d}', label=row['label'], app=row['app'],
                         pc_start_utc=datetime.fromtimestamp(row['pc_start_epoch'],timezone.utc).isoformat(),
                         pc_end_utc=datetime.fromtimestamp(row['pc_end_epoch'],timezone.utc).isoformat(),
                         pc_start_epoch=row['pc_start_epoch'],pc_end_epoch=row['pc_end_epoch'],
                         router_start_epoch=row['router_start_epoch'],router_end_epoch=row['router_end_epoch'],
                         duration_seconds=row['pc_end_epoch']-row['pc_start_epoch'],
                         label_status=row['review_status'],
                         usable_label=row['review_status'] in {'recorded','confirmed'} and row['label']!='unknown',
                         clock_uncertainty_seconds=value['clock_uncertainty_seconds'],
                         reason=row['reason'],source=row['source']))
        if value['schema'] == 'manual-ground-truth-timeline-v2':
            rows[-1]['input_eligible'] = rows[-1]['usable_label']
    return rows


def verify_export(out):
    out = Path(out).resolve()
    manifest = read_json(out/'export_manifest.json')
    if manifest['status'] != 'complete':
        raise ValueError('Export incomplete.')
    for name,expected in manifest['artifact_sha256'].items():
        path = (out/name.replace('\\','/')).resolve()
        if not path.is_relative_to(out) or sha256(path)!=expected:
            raise ValueError('Export verification failed: '+name)
    for name,expected in manifest['original_source_sha256'].items():
        path = out/'capture.pcap' if name=='capture.pcap' else out/'evidence'/name
        if sha256(path) != expected:
            raise ValueError('The exported copy has a different hash from the source: '+name)
    value = read_json(out/'ground_truth.json')
    if "manual_protocol" in value:
        source_manifest = read_json(out/'evidence'/'collection_manifest.json')
        points = event_windows(read_events(out/'evidence'), source_manifest)
        clock, end_clock = source_manifest['clock_start'], source_manifest['clock_end']
        uncertainty = max(clock['uncertainty_seconds'],
                          abs(end_clock['offset_seconds']-clock['offset_seconds'])+end_clock['uncertainty_seconds'])
        for point in points:
            point['clock_uncertainty_seconds'] = uncertainty
        if (value['manual_protocol'] != source_manifest['manual_protocol'] or
                value['event_windows'] != points or read_json(out/'event_windows.json') != points):
            raise ValueError('Exported event windows differ from the original markers.')
        if points:
            with (out/'event_windows.csv').open(encoding='utf-8-sig', newline='') as handle:
                if list(csv.DictReader(handle)) != [{k:str(v) for k,v in p.items()} for p in points]:
                    raise ValueError('The event CSV differs from the original markers.')
    validate_timeline(value['timeline'],value['pc_start_epoch'],value['pc_end_epoch'])
    expected = export_rows(value)
    for filename,rows in [('ground_truth.csv',expected),('labeled_segments.csv',[r for r in expected if r['usable_label']])]:
        with (out/filename).open(encoding='utf-8-sig',newline='') as handle:
            actual = list(csv.DictReader(handle))
        if actual != [{key:str(v) for key,v in row.items()} for row in rows]:
            raise ValueError('Exported labels differ from the saved timeline.')
    with (out/'packets.csv').open(encoding='utf-8',newline='') as handle:
        if sum(1 for _ in csv.DictReader(handle)) != manifest['ip_packets']:
            raise ValueError('Exported packet counts disagree.')
    if manifest['schema']=='manual-ground-truth-export-v2':
        verify_packet_csv(out, value)
    return dict(valid=True, capture_ready=manifest['capture_ready'], fully_labeled_ready=manifest['fully_labeled_ready'],
                task_data_ready=manifest.get('task_data_ready'),
                ip_packets=manifest['ip_packets'], label_segments=manifest['label_segments'])


def verify_packet_csv(out, value):
    """Replay the copied PCAP, including gaps, and compare every exported packet field."""
    with (out/'packets.csv').open(encoding='utf-8', newline='') as handle:
        actual = iter(csv.DictReader(handle))
        for row in packet_rows(out/'capture.pcap', value):
            if next(actual, None) != {key: str(item) for key, item in row.items()}:
                raise ValueError('The packet CSV differs from the continuous PCAP.')
        if next(actual, None) is not None:
            raise ValueError('The packet CSV contains data outside the original capture.')
