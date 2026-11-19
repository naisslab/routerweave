from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


GROUND_TRUTH_CSV_HEADER = (
    "timestamp_ms,"
    "timestamp_local,"
    "session_id,"
    "behavior_label,"
    "foreground_app,"
    "recent_user_input,"
    "recent_user_input_local,"
    "screen_or_session_active\n"
)

NETWORK_FLOW_BUCKETS_CSV_HEADER = (
    "bucket_start_ms,"
    "bucket_start_local,"
    "bucket_end_ms,"
    "bucket_end_local,"
    "session_id,"
    "interface_name,"
    "direction,"
    "ip_version,"
    "transport,"
    "local_ip,"
    "local_port,"
    "remote_ip,"
    "remote_port,"
    "packet_count,"
    "byte_count,"
    "min_packet_bytes,"
    "max_packet_bytes,"
    "avg_packet_bytes\n"
)

GROUND_TRUTH_SUMMARY_CSV_HEADER = (
    "scope,"
    "session_id,"
    "foreground_app,"
    "screen_time_ms,"
    "engaged_use_time_ms,"
    "samples\n"
)


@dataclass(frozen=True, slots=True)
class DesktopLogRecord:
    timestamp_ms: int
    session_id: str
    behavior_label: str
    foreground_app: str
    recent_user_input: str
    screen_or_session_active: bool


@dataclass(frozen=True, slots=True)
class SessionBundle:
    session_id: str
    session_dir: Path
    ground_truth_csv: Path
    network_summary_csv: Path
    raw_capture_root: Path
    manifest_json: Path
    started_at_ms: int
    ended_at_ms: int | None = None


@dataclass(frozen=True, slots=True)
class LoggerRunResult:
    session_id: str
    session_bundle: SessionBundle
    sample_count: int


@dataclass(frozen=True, slots=True)
class PostprocessSummary:
    session_id: str
    total_samples: int
    active_samples: int
    engaged_samples: int
    screen_time_ms: int
    engaged_use_time_ms: int


@dataclass(frozen=True, slots=True)
class NetworkCaptureConfig:
    enabled: bool = True
    backend: str = "router_tcpdump"
    snaplen_bytes: int = 262144
    rotation_size_mb: int = 256
    bucket_interval_ms: int = 1_000
    router_host: str = ""
    router_port: int = 22
    router_user: str = "root"
    router_interface: str = "br-lan"
    device_ip: str = ""
    bpf_filter: str = ""
    ssh_key_path: str = ""


@dataclass(frozen=True, slots=True)
class NetworkFlowBucketRecord:
    bucket_start_ms: int
    bucket_end_ms: int
    session_id: str
    interface_name: str
    direction: str
    ip_version: str
    transport: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    packet_count: int
    byte_count: int
    min_packet_bytes: int
    max_packet_bytes: int
    avg_packet_bytes: float


@dataclass(frozen=True, slots=True)
class NetworkCaptureTarget:
    interface_name: str
    raw_slug: str
    local_ip_addresses: tuple[str, ...]

    @property
    def slug(self) -> str:
        return "".join(char.lower() if char.isalnum() else "_" for char in self.raw_slug).strip("_")


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    ip_version: str
    transport: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    timestamp_ms: int = 0
    length: int = 0
    direction_hint: str | None = None


@dataclass(frozen=True, slots=True)
class NetworkRuntimeStatus:
    backend_status: str
    raw_packet_status: str
    total_packets: int
    total_bytes: int
    active_interface_count: int


@dataclass(frozen=True, slots=True)
class NetworkCaptureResult:
    raw_capture_files: tuple[Path, ...]
    warnings: tuple[str, ...]
    total_packets: int
    total_bytes: int
    backend_status: str
    raw_packet_status: str
    interface_stats: dict[str, dict[str, int]]


@dataclass(frozen=True, slots=True)
class SessionRunResult:
    session_bundle: SessionBundle
    exported_bundle_dir: Path | None
    screen_sample_count: int
    network_result: NetworkCaptureResult | None


@dataclass(frozen=True, slots=True)
class NetworkSummary:
    total_flows: int
    total_packets: int
    total_bytes: int


@dataclass(frozen=True, slots=True)
class LoadedNetworkBucket:
    bucket_start_ms: int
    bucket_end_ms: int
    session_id: str
    interface_name: str
    direction: str
    ip_version: str
    transport: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    packet_count: int
    byte_count: int


@dataclass(slots=True)
class SessionManifestData:
    session_id: str
    started_at_ms: int
    started_at_local: str
    ended_at_ms: int
    ended_at_local: str
    behavior_label: str
    logger_interval_ms: int
    selected_interfaces: list[str]
    network_capture_enabled: bool
    network_backend: str
    snaplen_bytes: int | None = None
    rotation_size_mb: int | None = None
    router_host: str | None = None
    router_port: int | None = None
    router_user: str | None = None
    router_interface: str | None = None
    device_ip: str | None = None
    bpf_filter: str | None = None
    ssh_key_path: str | None = None
    raw_capture_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    screen_sample_count: int = 0
    network_total_packets: int = 0
    network_total_bytes: int = 0
    backend_status: str = "disabled"
    raw_packet_status: str = "disabled"
