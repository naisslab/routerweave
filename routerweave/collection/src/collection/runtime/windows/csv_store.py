from __future__ import annotations

import csv
import json
import shutil
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import (
    GROUND_TRUTH_CSV_HEADER,
    NETWORK_FLOW_BUCKETS_CSV_HEADER,
    DesktopLogRecord,
    NetworkFlowBucketRecord,
    SessionBundle,
    SessionManifestData,
)
from .time_utils import format_local_timestamp_ms, format_recent_user_input_local


class SessionBundleStore:
    def __init__(self, sessions_dir: Path, export_dir: Path) -> None:
        self.sessions_dir = sessions_dir
        self.export_dir = export_dir

    def create_session_bundle(self, session_id: str, timestamp_ms: int, *, ground_truth_header: str = GROUND_TRUTH_CSV_HEADER) -> SessionBundle:
        started_at = datetime.fromtimestamp(timestamp_ms / 1000)
        bundle_name = f"{started_at:%Y%m%d_%H%M%S}_{session_id}"
        session_dir = self.sessions_dir / bundle_name
        network_dir = session_dir / "network"
        raw_capture_root = network_dir / "raw"
        ground_truth_csv = session_dir / "ground_truth.csv"
        network_summary_csv = network_dir / "network_flow_buckets.csv"
        manifest_json = session_dir / "manifest.json"

        raw_capture_root.mkdir(parents=True, exist_ok=True)
        self._ensure_csv(ground_truth_csv, ground_truth_header)
        self._ensure_csv(network_summary_csv, NETWORK_FLOW_BUCKETS_CSV_HEADER)

        return SessionBundle(
            session_id=session_id,
            session_dir=session_dir,
            ground_truth_csv=ground_truth_csv,
            network_summary_csv=network_summary_csv,
            raw_capture_root=raw_capture_root,
            manifest_json=manifest_json,
            started_at_ms=timestamp_ms,
        )

    def append_ground_truth_record(self, ground_truth_csv: Path, record: DesktopLogRecord) -> None:
        with ground_truth_csv.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    record.timestamp_ms,
                    format_local_timestamp_ms(record.timestamp_ms),
                    record.session_id,
                    record.behavior_label,
                    record.foreground_app,
                    record.recent_user_input,
                    format_recent_user_input_local(record.recent_user_input),
                    str(record.screen_or_session_active).lower(),
                ]
            )

    def append_network_bucket_records(self, network_summary_csv: Path, records: Iterable[NetworkFlowBucketRecord]) -> None:
        rows = list(records)
        if not rows:
            return
        with network_summary_csv.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            for record in rows:
                writer.writerow(
                    [
                        record.bucket_start_ms,
                        format_local_timestamp_ms(record.bucket_start_ms),
                        record.bucket_end_ms,
                        format_local_timestamp_ms(record.bucket_end_ms),
                        record.session_id,
                        record.interface_name,
                        record.direction,
                        record.ip_version,
                        record.transport,
                        record.local_ip,
                        record.local_port,
                        record.remote_ip,
                        record.remote_port,
                        record.packet_count,
                        record.byte_count,
                        record.min_packet_bytes,
                        record.max_packet_bytes,
                        f"{record.avg_packet_bytes:.6f}",
                    ]
                )

    def finalize_session_bundle(self, bundle: SessionBundle, ended_at_ms: int) -> SessionBundle:
        return SessionBundle(
            session_id=bundle.session_id,
            session_dir=bundle.session_dir,
            ground_truth_csv=bundle.ground_truth_csv,
            network_summary_csv=bundle.network_summary_csv,
            raw_capture_root=bundle.raw_capture_root,
            manifest_json=bundle.manifest_json,
            started_at_ms=bundle.started_at_ms,
            ended_at_ms=ended_at_ms,
        )

    def write_manifest(self, bundle: SessionBundle, manifest: SessionManifestData) -> Path:
        bundle.manifest_json.write_text(json.dumps(asdict(manifest), ensure_ascii=False, indent=2), encoding="utf-8")
        return bundle.manifest_json

    def export_session_bundle(self, bundle: SessionBundle) -> Path:
        exported_dir = self.export_dir / bundle.session_dir.name
        if exported_dir.exists():
            shutil.rmtree(exported_dir)
        shutil.copytree(bundle.session_dir, exported_dir)
        return exported_dir

    def delete_session_bundle(self, bundle: SessionBundle) -> None:
        if bundle.session_dir.exists():
            shutil.rmtree(bundle.session_dir)

    def resolve_session_bundle(self, preferred_path: str | None = None) -> SessionBundle | None:
        candidate_dir: Path | None = None
        if preferred_path:
            candidate = Path(preferred_path)
            if candidate.exists():
                candidate_dir = candidate if candidate.is_dir() else candidate.parent
            else:
                nested_candidate = self.sessions_dir / preferred_path
                if nested_candidate.exists():
                    candidate_dir = nested_candidate if nested_candidate.is_dir() else nested_candidate.parent

        if candidate_dir is None:
            session_dirs = [path for path in self.sessions_dir.iterdir() if path.is_dir()] if self.sessions_dir.exists() else []
            candidate_dir = max(session_dirs, key=lambda path: path.stat().st_mtime, default=None)

        if candidate_dir is None:
            return None

        ground_truth_csv = candidate_dir / "ground_truth.csv"
        network_summary_csv = candidate_dir / "network" / "network_flow_buckets.csv"
        raw_capture_root = candidate_dir / "network" / "raw"
        manifest_json = candidate_dir / "manifest.json"
        if not ground_truth_csv.exists():
            return None

        manifest_data = {}
        if manifest_json.exists():
            try:
                manifest_data = json.loads(manifest_json.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest_data = {}

        return SessionBundle(
            session_id=manifest_data.get("session_id", candidate_dir.name.split("_")[-1]),
            session_dir=candidate_dir,
            ground_truth_csv=ground_truth_csv,
            network_summary_csv=network_summary_csv,
            raw_capture_root=raw_capture_root,
            manifest_json=manifest_json,
            started_at_ms=int(manifest_data.get("started_at_ms", 0)),
            ended_at_ms=int(manifest_data["ended_at_ms"]) if manifest_data.get("ended_at_ms") is not None else None,
        )

    def resolve_exported_session_bundle(self, preferred_path: str | None = None) -> SessionBundle | None:
        export_store = SessionBundleStore(self.export_dir, self.export_dir)
        return export_store.resolve_session_bundle(preferred_path)

    def _ensure_csv(self, csv_path: Path, header: str) -> None:
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        if not csv_path.exists():
            csv_path.write_text(header, encoding="utf-8", newline="")


def count_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", newline="", encoding="utf-8") as handle:
        return max(0, sum(1 for _row in csv.reader(handle)) - 1)
