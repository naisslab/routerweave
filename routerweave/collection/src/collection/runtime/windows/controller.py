from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable

from .config import LoggerConfig
from .csv_store import SessionBundleStore
from .logger import DesktopLogger
from .models import (
    DesktopLogRecord,
    LoggerRunResult,
    NetworkCaptureConfig,
    NetworkCaptureResult,
    NetworkRuntimeStatus,
    SessionBundle,
    SessionManifestData,
    SessionRunResult,
)
from .network_capture import RouterTcpdumpCaptureSession
from .platforms.base import PlatformSnapshotter
from .time_utils import format_local_timestamp_ms


class SessionController:
    def __init__(self, config: LoggerConfig, snapshotter: PlatformSnapshotter,
                 network_capture_factory=RouterTcpdumpCaptureSession) -> None:
        self.config = config
        self.snapshotter = snapshotter
        self.network_capture_factory = network_capture_factory
        self.config.ensure_directories()
        self.store = SessionBundleStore(self.config.sessions_dir, self.config.export_root)
        self.logger = DesktopLogger(config=self.config, snapshotter=self.snapshotter)

    def run(
        self,
        *,
        network_config: NetworkCaptureConfig,
        behavior_label: str,
        session_id: str | None = None,
        stop_event: threading.Event | None = None,
        duration_seconds: float | None = None,
        max_samples: int | None = None,
        export_on_stop: bool = True,
        on_started: Callable[[SessionBundle], None] | None = None,
        on_record: Callable[[DesktopLogRecord, int, SessionBundle], None] | None = None,
        on_network_status: Callable[[NetworkRuntimeStatus], None] | None = None,
    ) -> SessionRunResult:
        shared_stop_event = stop_event or threading.Event()
        started_at_ms = int(time.time() * 1000)
        run_session_id = session_id or uuid.uuid4().hex[:8]
        session_bundle = self.store.create_session_bundle(run_session_id, started_at_ms)

        network_session: RouterTcpdumpCaptureSession | None = None
        network_result: NetworkCaptureResult | None = None
        logger_result: LoggerRunResult | None = None

        try:
            if network_config.enabled:
                network_session = self.network_capture_factory(
                    config=network_config,
                    session_bundle=session_bundle,
                    store=self.store,
                    stop_event=shared_stop_event,
                    on_status=on_network_status,
                )
                network_session.start()

            if on_started is not None:
                on_started(session_bundle)

            logger_result = self.logger.run(
                session_bundle=session_bundle,
                behavior_label=behavior_label,
                duration_seconds=duration_seconds,
                max_samples=max_samples,
                stop_event=shared_stop_event,
                on_record=on_record,
            )
        except Exception:
            if network_session is not None:
                shared_stop_event.set()
                try:
                    network_session.stop()
                except Exception:
                    pass
            # Preserve partial artifacts for diagnosis. The outer capture
            # manifest records the failure and the validator rejects it.
            raise

        shared_stop_event.set()
        if network_session is not None:
            network_result = network_session.stop()

        ended_at_ms = int(time.time() * 1000)
        finalized_bundle = self.store.finalize_session_bundle(session_bundle, ended_at_ms)
        manifest = SessionManifestData(
            session_id=finalized_bundle.session_id,
            started_at_ms=finalized_bundle.started_at_ms,
            started_at_local=format_local_timestamp_ms(finalized_bundle.started_at_ms),
            ended_at_ms=ended_at_ms,
            ended_at_local=format_local_timestamp_ms(ended_at_ms),
            behavior_label=behavior_label,
            logger_interval_ms=self.config.sample_interval_ms,
            selected_interfaces=[network_config.router_interface] if network_config.enabled else [],
            network_capture_enabled=network_config.enabled,
            network_backend=network_config.backend,
            snaplen_bytes=network_config.snaplen_bytes if network_config.enabled else None,
            rotation_size_mb=network_config.rotation_size_mb if network_config.enabled else None,
            router_host=network_config.router_host if network_config.enabled else None,
            router_port=network_config.router_port if network_config.enabled else None,
            router_user=network_config.router_user if network_config.enabled else None,
            router_interface=network_config.router_interface if network_config.enabled else None,
            device_ip=network_config.device_ip if network_config.enabled else None,
            bpf_filter=network_config.bpf_filter if network_config.enabled else None,
            ssh_key_path=network_config.ssh_key_path if network_config.enabled and network_config.ssh_key_path else None,
            raw_capture_files=[
                str(path.relative_to(finalized_bundle.session_dir))
                for path in (network_result.raw_capture_files if network_result else ())
            ],
            warnings=list(network_result.warnings) if network_result else [],
            screen_sample_count=logger_result.sample_count if logger_result else 0,
            network_total_packets=network_result.total_packets if network_result else 0,
            network_total_bytes=network_result.total_bytes if network_result else 0,
            backend_status=network_result.backend_status if network_result else "disabled",
            raw_packet_status=network_result.raw_packet_status if network_result else "disabled",
        )
        self.store.write_manifest(finalized_bundle, manifest)

        exported_bundle_dir = self.store.export_session_bundle(finalized_bundle) if export_on_stop else None
        result = SessionRunResult(
            session_bundle=finalized_bundle,
            exported_bundle_dir=exported_bundle_dir,
            screen_sample_count=logger_result.sample_count if logger_result else 0,
            network_result=network_result,
        )

        if network_session is not None and network_session.runtime_error:
            raise RuntimeError(
                f"Network capture stopped unexpectedly. Partial data was saved to {finalized_bundle.session_dir}.\n"
                f"{network_session.runtime_error}"
            )

        return result
