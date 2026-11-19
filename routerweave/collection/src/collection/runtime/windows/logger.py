from __future__ import annotations

import time
from collections.abc import Callable
from threading import Event

from .config import LoggerConfig
from .csv_store import SessionBundleStore
from .models import DesktopLogRecord, LoggerRunResult, SessionBundle
from .platforms.base import PlatformSnapshotter


class DesktopLogger:
    def __init__(self, config: LoggerConfig, snapshotter: PlatformSnapshotter) -> None:
        self.config = config
        self.snapshotter = snapshotter
        self.config.ensure_directories()
        self.store = SessionBundleStore(self.config.sessions_dir, self.config.export_root)

    def run(
        self,
        *,
        session_bundle: SessionBundle,
        behavior_label: str,
        duration_seconds: float | None = None,
        max_samples: int | None = None,
        stop_event: Event | None = None,
        on_record: Callable[[DesktopLogRecord, int, SessionBundle], None] | None = None,
    ) -> LoggerRunResult:
        if duration_seconds is not None and duration_seconds <= 0:
            raise ValueError("duration_seconds must be > 0")
        if max_samples is not None and max_samples <= 0:
            raise ValueError("max_samples must be > 0")

        sample_count = 0
        deadline_monotonic = time.monotonic() + duration_seconds if duration_seconds is not None else None

        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break

                now_ms = int(time.time() * 1000)
                record = self.snapshotter.create_record(
                    session_id=session_bundle.session_id,
                    now_ms=now_ms,
                    behavior_label=behavior_label,
                )
                self.store.append_ground_truth_record(session_bundle.ground_truth_csv, record)
                sample_count += 1
                if on_record is not None:
                    on_record(record, sample_count, session_bundle)

                if max_samples is not None and sample_count >= max_samples:
                    break
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    break
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(self._aligned_delay_seconds())
        except KeyboardInterrupt:
            pass

        return LoggerRunResult(
            session_id=session_bundle.session_id,
            session_bundle=session_bundle,
            sample_count=sample_count,
        )

    def _aligned_delay_seconds(self) -> float:
        interval_ms = self.config.sample_interval_ms
        remainder = int(time.time() * 1000) % interval_ms
        delay_ms = min(interval_ms, max(200, interval_ms - remainder))
        return delay_ms / 1000
