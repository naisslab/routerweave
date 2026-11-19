from __future__ import annotations

import os

import ipaddress
import json
import shlex
import shutil
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Callable, Final

from .csv_store import SessionBundleStore
from .models import (
    NetworkCaptureConfig,
    NetworkCaptureResult,
    NetworkCaptureTarget,
    NetworkFlowBucketRecord,
    NetworkRuntimeStatus,
    ParsedPacket,
    SessionBundle,
)
from .packet_parser import parse_packet


PCAP_GLOBAL_HEADER_LEN: Final[int] = 24
PCAP_PACKET_HEADER_LEN: Final[int] = 16
SSH_CONNECT_TIMEOUT_SECONDS: Final[int] = 8
CAPTURE_START_TIMEOUT_SECONDS: Final[int] = 12

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


class RouterCaptureRuntimeError(RuntimeError):
    pass


def probe_router_capture() -> tuple[bool, str]:
    if shutil.which("ssh") is None:
        return False, "OpenSSH client was not found. Install Windows OpenSSH Client or add ssh.exe to PATH."
    return True, "Router backend ready. SSH/tcpdump access is checked when recording starts."


def guess_default_device_ip(expected_gateway: str = "") -> str:
    if expected_gateway:
        routed_ip = _source_ip_for_destination(expected_gateway)
        if routed_ip:
            return routed_ip
    route = _select_default_route(expected_gateway=expected_gateway)
    if route:
        return route[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return str(probe.getsockname()[0])
    except OSError:
        return ""


def _source_ip_for_destination(destination: str) -> str:
    try:
        target = ipaddress.ip_address(destination)
    except ValueError:
        return ""
    if target.version != 4:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            # UDP connect selects a route without sending application data.
            probe.connect((str(target), 9))
            selected = str(probe.getsockname()[0])
        local = ipaddress.ip_address(selected)
        if local.version == 4 and not local.is_unspecified and not local.is_loopback and not local.is_link_local:
            return selected
    except (OSError, ValueError):
        pass
    return ""


def guess_default_router_host() -> str:
    route = _select_default_route()
    return route[1] if route else ""


def _select_default_route(*, expected_gateway: str = "") -> tuple[str, str] | None:
    script = (
        "Get-NetIPConfiguration | "
        "Where-Object { $_.IPv4DefaultGateway -ne $null } | "
        "Select-Object InterfaceAlias,"
        "@{Name='IPv4';Expression={$_.IPv4Address.IPAddress}},"
        "@{Name='Gateway';Expression={$_.IPv4DefaultGateway.NextHop}},"
        "@{Name='Status';Expression={$_.NetAdapter.Status}} | "
        "ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=5,
            startupinfo=_subprocess_startupinfo(),
            creationflags=_creation_flags(),
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return None
        data = json.loads(completed.stdout)
        rows = data if isinstance(data, list) else [data]
        candidates = [_normalize_route_row(row) for row in rows if isinstance(row, dict)]
        candidates = [candidate for candidate in candidates if candidate is not None]
        if not candidates:
            return None
        candidates.sort(key=lambda route: _route_score(route, expected_gateway=expected_gateway))
        _alias, ipv4, gateway = candidates[0]
        return ipv4, gateway
    except Exception:
        return None


def _normalize_route_row(row: dict[str, object]) -> tuple[str, str, str] | None:
    alias = str(row.get("InterfaceAlias") or "")
    ipv4_values = row.get("IPv4")
    gateway_values = row.get("Gateway")
    ipv4 = _first_scalar(ipv4_values)
    gateway = _first_scalar(gateway_values)
    if not ipv4 or not gateway:
        return None
    try:
        ip = ipaddress.ip_address(ipv4)
        gw = ipaddress.ip_address(gateway)
    except ValueError:
        return None
    if ip.is_link_local or ip.is_loopback or gw.is_link_local or gw.is_loopback:
        return None
    return alias, ipv4, gateway


def _first_scalar(value: object) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _route_score(route: tuple[str, str, str], *, expected_gateway: str = "") -> tuple[int, int, int, int, str]:
    alias, ipv4, gateway = route
    alias_l = alias.lower()
    excluded = (
        "zerotier",
        "tailscale",
        "vpn",
        "hyper-v",
        "wsl",
        "vethernet",
        "default switch",
        "docker",
        "vmware",
        "loopback",
        "bluetooth",
        "virtual",
    )
    preferred = ("wi-fi", "wifi", "ethernet")
    ip = ipaddress.ip_address(ipv4)
    gw = ipaddress.ip_address(gateway)
    return (
        0 if expected_gateway and gateway == expected_gateway else 20,
        100 if any(token in alias_l for token in excluded) else 0,
        0 if any(token in alias_l for token in preferred) else 10,
        0 if ip.is_private and gw.is_private else 20,
        alias_l,
    )


def find_default_router_key_path() -> str:
    return os.environ.get("ROUTERWEAVE_SSH_KEY", "")


def effective_bpf_filter(config: NetworkCaptureConfig) -> str:
    custom_filter = config.bpf_filter.strip()
    if custom_filter:
        return custom_filter
    device_ips = _parse_ip_list(config.device_ip)
    return " or ".join(f"host {ip}" for ip in device_ips)


def _bucket_start(timestamp_ms: int, interval_ms: int) -> int:
    return timestamp_ms - (timestamp_ms % interval_ms)


def _status_from_totals(total_packets: int, total_bytes: int) -> NetworkRuntimeStatus:
    return NetworkRuntimeStatus(
        backend_status="Router tcpdump capturing",
        raw_packet_status=f"parsed_tcp_udp_packets={total_packets}, bytes={total_bytes}",
        total_packets=total_packets,
        total_bytes=total_bytes,
        active_interface_count=1,
    )


def _parse_ip_list(value: str) -> tuple[str, ...]:
    ips: list[str] = []
    for raw in value.replace(";", ",").split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        ipaddress.ip_address(candidate)
        ips.append(candidate)
    return tuple(dict.fromkeys(ips))


def _safe_slug(*parts: str) -> str:
    unsafe = "_".join(part for part in parts if part)
    return "".join(char.lower() if char.isalnum() else "_" for char in unsafe).strip("_") or "router"


def _build_ssh_base_args(config: NetworkCaptureConfig) -> list[str]:
    if shutil.which("ssh") is None:
        raise RouterCaptureRuntimeError("OpenSSH client was not found. Install Windows OpenSSH Client or add ssh.exe to PATH.")
    if not config.router_host.strip():
        raise RouterCaptureRuntimeError("Router host is required.")
    if not config.router_user.strip():
        raise RouterCaptureRuntimeError("Router SSH user is required.")
    if not 1 <= int(config.router_port) <= 65535:
        raise RouterCaptureRuntimeError("Router SSH port must be between 1 and 65535.")

    args = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
        "-p",
        str(config.router_port),
    ]
    if config.ssh_key_path.strip():
        args.extend(["-i", config.ssh_key_path.strip()])
    args.append(f"{config.router_user.strip()}@{config.router_host.strip()}")
    return args


def _remote_command(args: Iterable[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in args)


def _remote_filter_tokens(filter_text: str) -> list[str]:
    if not filter_text.strip():
        return []
    try:
        return shlex.split(filter_text, posix=True)
    except ValueError as exc:
        raise RouterCaptureRuntimeError(f"Invalid BPF filter: {exc}") from exc


def _subprocess_startupinfo() -> subprocess.STARTUPINFO | None:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return startupinfo


def _creation_flags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _format_process_error(prefix: str, completed: subprocess.CompletedProcess[str]) -> str:
    details = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part and part.strip())
    if not details:
        details = f"exit_code={completed.returncode}"
    return f"{prefix}\n{details}\nUse key-based SSH or an SSH agent; password prompts are disabled for reproducible logging."


def validate_router_access(config: NetworkCaptureConfig, *, synchronize_clock: bool = False,
                           evidence: dict | None = None,
                           _clock_probes_remaining: int = 3) -> tuple[bool, str]:
    try:
        _validate_capture_config(config)
        check_command = (
            "command -v tcpdump >/dev/null 2>&1 && echo tcpdump_ready && "
            "if command -v ucode >/dev/null 2>&1; then "
            "ucode -e 'printf(\"clock_ns=%J\\n\", clock());'; "
            "else date +clock_epoch=%s; fi"
        )
        host_before = time.time()
        completed = subprocess.run(
            [*_build_ssh_base_args(config), check_command],
            capture_output=True,
            text=True,
            timeout=SSH_CONNECT_TIMEOUT_SECONDS + 4,
            startupinfo=_subprocess_startupinfo(),
            creationflags=_creation_flags(),
        )
        host_after = time.time()
    except Exception as exc:
        return False, str(exc)
    if completed.returncode != 0 or "tcpdump_ready" not in completed.stdout:
        return False, _format_process_error("Router SSH/tcpdump check failed.", completed)
    clock_rows = [line.removeprefix("clock_epoch=") for line in completed.stdout.splitlines()
                  if line.startswith("clock_epoch=")]
    precise_rows = [line.removeprefix("clock_ns=") for line in completed.stdout.splitlines()
                    if line.startswith("clock_ns=")]
    try:
        if len(precise_rows) == 1 and not clock_rows:
            parts = json.loads(precise_rows[0])
            if (not isinstance(parts, list) or len(parts) != 2
                    or any(type(value) is not int for value in parts)
                    or parts[0] < 0 or not 0 <= parts[1] < 1_000_000_000):
                raise ValueError("invalid realtime clock")
            router_epoch = parts[0] + parts[1] / 1_000_000_000
            # A conservative microsecond margin covers float epoch rounding.
            router_low, router_high = router_epoch - 0.000001, router_epoch + 0.000001
            clock_source = 'ucode_realtime_nanoseconds'
        elif len(clock_rows) == 1 and not precise_rows:
            router_epoch = int(clock_rows[0])
            router_low, router_high = router_epoch, router_epoch + 1
            clock_source = 'date_integer_seconds'
        else:
            raise ValueError("missing or ambiguous router clock")
    except (ValueError, TypeError):
        return False, "Router clock could not be verified; capture was not started."
    # Include the precision of the selected read-only clock. Bound offset using
    # the entire SSH round trip rather than assuming symmetric network delay.
    offset_low = router_low - host_after
    offset_high = router_high - host_before
    if evidence is not None:
        probe = dict(host_before_epoch=host_before, host_after_epoch=host_after,
                     router_epoch=router_epoch, offset_low_seconds=offset_low,
                     offset_high_seconds=offset_high, calibration_attempted=False,
                     router_clock_source=clock_source)
        evidence.setdefault('clock_probes', []).append(probe)
        evidence.update(probe)
    if host_after < host_before or max(abs(offset_low), abs(offset_high)) > 2:
        if (0 <= host_after - host_before <= 2 and _clock_probes_remaining > 1
                and offset_low <= 2 and offset_high >= -2):
            # Integer date quantization can straddle the gate for an otherwise
            # usable offset. Re-measure read-only, at most three times; accept
            # only one complete fresh interval within the unchanged +/-2 gate.
            # Never intersect intervals, average offsets, or step either clock.
            return validate_router_access(config, evidence=evidence,
                _clock_probes_remaining=_clock_probes_remaining - 1)
        if (synchronize_clock and host_after >= host_before and host_after - host_before <= 1
                and (offset_low > 2 or offset_high < -2)):
            # One bounded correction, before any capture. Check real processes,
            # not stale PID files; never step the router clock under tcpdump.
            epoch = int(time.time())
            command = (
                'for c in /proc/[0-9]*/comm; do '
                'read -r name < "$c" 2>/dev/null || continue; '
                '[ "$name" != tcpdump ] || { echo active_capture_clock_unchanged; exit 75; }; '
                f'done; date -u -s @{epoch} >/dev/null && echo clock_calibrated'
            )
            if evidence is not None:
                evidence.update(calibration_attempted=True, reference='windows_host',
                                requested_router_epoch=epoch)
            try:
                repair = subprocess.run([*_build_ssh_base_args(config), command],
                    capture_output=True, text=True, timeout=SSH_CONNECT_TIMEOUT_SECONDS + 4,
                    startupinfo=_subprocess_startupinfo(), creationflags=_creation_flags())
            except Exception as exc:
                return False, f'Router clock calibration failed: {exc}'
            if repair.returncode != 0 or 'clock_calibrated' not in repair.stdout:
                return False, _format_process_error('Router clock calibration refused or failed.', repair)
            after = {}
            ready, message = validate_router_access(config, evidence=after)
            if evidence is not None:
                evidence.update(calibration_applied=True, after=after)
            return ready, f'Router clock calibrated once; {message}'
        return False, (
            f"Router/host clock offset cannot be bounded within 2 seconds "
            f"([{offset_low:.3f}, {offset_high:.3f}] seconds). "
            "Synchronize clocks with no active captures, then repeat the smoke."
        )
    return True, "Router SSH, tcpdump, and host/router clock alignment are ready."


def _validate_capture_config(config: NetworkCaptureConfig) -> None:
    if config.backend != "router_tcpdump":
        raise RouterCaptureRuntimeError(f"Unsupported network backend: {config.backend}")
    if not config.router_interface.strip():
        raise RouterCaptureRuntimeError("Router capture interface is required, for example br-lan.")
    if config.snaplen_bytes <= 0:
        raise RouterCaptureRuntimeError("Snaplen must be positive.")
    if config.rotation_size_mb <= 0:
        raise RouterCaptureRuntimeError("Rotation size must be positive.")
    if config.bucket_interval_ms <= 0:
        raise RouterCaptureRuntimeError("Bucket interval must be positive.")
    if not effective_bpf_filter(config):
        raise RouterCaptureRuntimeError("Device IP or custom BPF filter is required to avoid capturing unrelated router traffic.")


class NetworkBucketAggregator:
    def __init__(
        self,
        *,
        session_bundle: SessionBundle,
        config: NetworkCaptureConfig,
        store: SessionBundleStore,
        target_lookup: dict[str, NetworkCaptureTarget],
    ) -> None:
        self.session_bundle = session_bundle
        self.config = config
        self.store = store
        self.target_lookup = target_lookup
        self.lock = threading.Lock()
        self.buckets: dict[tuple[object, ...], list[int]] = {}
        self.total_packets = 0
        self.total_bytes = 0

    def add_packet(
        self,
        *,
        interface_name: str,
        timestamp_ms: int,
        parsed_packet: ParsedPacket,
        packet_length: int,
    ) -> tuple[tuple[NetworkFlowBucketRecord, ...], NetworkRuntimeStatus]:
        target = self.target_lookup[interface_name]
        direction = self._resolve_direction(target, parsed_packet)
        local_ip, local_port, remote_ip, remote_port = self._resolve_endpoints(direction, parsed_packet)
        bucket_start_ms = _bucket_start(timestamp_ms, self.config.bucket_interval_ms)
        key = (
            bucket_start_ms,
            interface_name,
            direction,
            parsed_packet.ip_version,
            parsed_packet.transport,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        )
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet_length
            bucket = self.buckets.setdefault(key, [0, 0, packet_length, packet_length])
            bucket[0] += 1
            bucket[1] += packet_length
            bucket[2] = min(bucket[2], packet_length)
            bucket[3] = max(bucket[3], packet_length)
            flushed = self._flush_ready_locked(bucket_start_ms - self.config.bucket_interval_ms)
            status = _status_from_totals(self.total_packets, self.total_bytes)
        return flushed, status

    def flush_all(self) -> tuple[NetworkFlowBucketRecord, ...]:
        with self.lock:
            records = self._materialize_records_locked(list(self.buckets.keys()))
            self.buckets.clear()
        return records

    def _resolve_direction(self, target: NetworkCaptureTarget, parsed_packet: ParsedPacket) -> str:
        local_ips = set(target.local_ip_addresses)
        if parsed_packet.src_ip in local_ips:
            return "outbound"
        if parsed_packet.dst_ip in local_ips:
            return "inbound"
        return parsed_packet.direction_hint or "unknown"

    def _resolve_endpoints(self, direction: str, parsed_packet: ParsedPacket) -> tuple[str, int | None, str, int | None]:
        if direction == "outbound":
            return parsed_packet.src_ip, parsed_packet.src_port, parsed_packet.dst_ip, parsed_packet.dst_port
        if direction == "inbound":
            return parsed_packet.dst_ip, parsed_packet.dst_port, parsed_packet.src_ip, parsed_packet.src_port
        return parsed_packet.src_ip, parsed_packet.src_port, parsed_packet.dst_ip, parsed_packet.dst_port

    def _flush_ready_locked(self, max_bucket_start_ms: int) -> tuple[NetworkFlowBucketRecord, ...]:
        ready_keys = [key for key in self.buckets if int(key[0]) <= max_bucket_start_ms]
        records = self._materialize_records_locked(ready_keys)
        for key in ready_keys:
            self.buckets.pop(key, None)
        return records

    def _materialize_records_locked(self, keys: list[tuple[object, ...]]) -> tuple[NetworkFlowBucketRecord, ...]:
        records: list[NetworkFlowBucketRecord] = []
        for key in sorted(keys):
            packet_count, byte_count, min_packet_bytes, max_packet_bytes = self.buckets[key]
            bucket_start_ms = int(key[0])
            records.append(
                NetworkFlowBucketRecord(
                    bucket_start_ms=bucket_start_ms,
                    bucket_end_ms=bucket_start_ms + self.config.bucket_interval_ms,
                    session_id=self.session_bundle.session_id,
                    interface_name=str(key[1]),
                    direction=str(key[2]),
                    ip_version=str(key[3]),
                    transport=str(key[4]),
                    local_ip=str(key[5]),
                    local_port=int(key[6]) if key[6] is not None else None,
                    remote_ip=str(key[7]),
                    remote_port=int(key[8]) if key[8] is not None else None,
                    packet_count=packet_count,
                    byte_count=byte_count,
                    min_packet_bytes=min_packet_bytes,
                    max_packet_bytes=max_packet_bytes,
                    avg_packet_bytes=byte_count / packet_count if packet_count else 0.0,
                )
            )
        return tuple(records)


class _RotatingPcapWriter:
    def __init__(self, *, raw_dir: Path, global_header: bytes, rotation_limit_bytes: int) -> None:
        self.raw_dir = raw_dir
        self.global_header = global_header
        self.rotation_limit_bytes = rotation_limit_bytes
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.raw_files: list[Path] = []
        self.capture_index = 0
        self.current_size = 0
        self.handle = None
        self._rotate()

    def write_packet(self, record_header: bytes, packet: bytes) -> None:
        packet_size = len(record_header) + len(packet)
        if self.current_size > PCAP_GLOBAL_HEADER_LEN and self.current_size + packet_size > self.rotation_limit_bytes:
            self._rotate()
        assert self.handle is not None
        self.handle.write(record_header)
        self.handle.write(packet)
        self.current_size += packet_size

    def close(self) -> None:
        if self.handle is not None:
            self.handle.flush()
            self.handle.close()
            self.handle = None

    def _rotate(self) -> None:
        self.close()
        self.capture_index += 1
        file_path = self.raw_dir / f"capture_{self.capture_index:04d}.pcap"
        self.handle = file_path.open("wb")
        self.handle.write(self.global_header)
        self.handle.flush()
        self.current_size = PCAP_GLOBAL_HEADER_LEN
        self.raw_files.append(file_path)


class _RouterTcpdumpWorker(threading.Thread):
    def __init__(
        self,
        *,
        config: NetworkCaptureConfig,
        session_bundle: SessionBundle,
        store: SessionBundleStore,
        aggregator: NetworkBucketAggregator,
        target: NetworkCaptureTarget,
        stop_event: threading.Event,
        status_callback,
        packet_callback: Callable[[ParsedPacket, int], None] | None = None,
    ) -> None:
        super().__init__(daemon=True, name=f"router-tcpdump-{target.interface_name}")
        self.config = config
        self.session_bundle = session_bundle
        self.store = store
        self.aggregator = aggregator
        self.target = target
        self.stop_event = stop_event
        self.status_callback = status_callback
        self.packet_callback = packet_callback
        self.process: subprocess.Popen[bytes] | None = None
        self.started_event = threading.Event()
        self.failed_event = threading.Event()
        self.stderr_lines: list[str] = []
        self.stderr_thread: threading.Thread | None = None
        self.runtime_error: str | None = None
        self.writer: _RotatingPcapWriter | None = None
        self.raw_packets = 0
        self.raw_bytes = 0
        self.parsed_packets = 0
        self.last_status_emit_monotonic = 0.0

    @property
    def raw_files(self) -> tuple[Path, ...]:
        return tuple(self.writer.raw_files) if self.writer is not None else ()

    def launch(self) -> None:
        filter_text = effective_bpf_filter(self.config)
        remote_args = [
            "tcpdump",
            "-i",
            self.config.router_interface.strip(),
            "-s",
            str(self.config.snaplen_bytes),
            "-U",
            "-w",
            "-",
            *_remote_filter_tokens(filter_text),
        ]
        command = [*_build_ssh_base_args(self.config), _remote_command(remote_args)]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=_subprocess_startupinfo(),
            creationflags=_creation_flags(),
        )
        self.stderr_thread = threading.Thread(target=self._read_stderr, name="router-tcpdump-stderr", daemon=True)
        self.stderr_thread.start()
        self.start()

    def run(self) -> None:
        try:
            if self.process is None or self.process.stdout is None:
                raise RouterCaptureRuntimeError("Router capture process was not launched.")
            global_header = self._read_exact(PCAP_GLOBAL_HEADER_LEN)
            if len(global_header) != PCAP_GLOBAL_HEADER_LEN:
                raise RouterCaptureRuntimeError(self._startup_error("Router tcpdump did not produce a pcap header."))
            endian, timestamp_is_ns, link_type = self._parse_global_header(global_header)
            raw_dir = self.session_bundle.raw_capture_root / self.target.slug
            self.writer = _RotatingPcapWriter(
                raw_dir=raw_dir,
                global_header=global_header,
                rotation_limit_bytes=self.config.rotation_size_mb * 1024 * 1024,
            )
            self.started_event.set()
            self.status_callback(_status_from_totals(0, 0))

            while not self.stop_event.is_set():
                record_header = self._read_exact(PCAP_PACKET_HEADER_LEN)
                if not record_header:
                    if not self.stop_event.is_set():
                        raise RouterCaptureRuntimeError(self._startup_error("Router tcpdump stream ended unexpectedly."))
                    break
                if len(record_header) != PCAP_PACKET_HEADER_LEN:
                    raise RouterCaptureRuntimeError("Router tcpdump stream ended mid-packet header.")
                ts_sec, ts_frac, captured_len, original_len = struct.unpack(f"{endian}IIII", record_header)
                packet = self._read_exact(captured_len)
                if len(packet) != captured_len:
                    raise RouterCaptureRuntimeError("Router tcpdump stream ended mid-packet payload.")

                assert self.writer is not None
                self.writer.write_packet(record_header, packet)
                timestamp_ms = int(ts_sec * 1000 + (ts_frac / 1_000_000 if timestamp_is_ns else ts_frac / 1000))
                self.raw_packets += 1
                self.raw_bytes += int(original_len)
                parsed = parse_packet(link_type, timestamp_ms, int(captured_len), packet)
                if parsed is None:
                    continue

                if self.packet_callback is not None:
                    self.packet_callback(parsed, int(original_len))

                flushed, status = self.aggregator.add_packet(
                    interface_name=self.target.interface_name,
                    timestamp_ms=timestamp_ms,
                    parsed_packet=parsed,
                    packet_length=int(original_len),
                )
                self.parsed_packets += 1
                if flushed:
                    self.store.append_network_bucket_records(self.session_bundle.network_summary_csv, flushed)
                if time.monotonic() - self.last_status_emit_monotonic >= 0.5:
                    self.status_callback(status)
                    self.last_status_emit_monotonic = time.monotonic()
        except Exception as exc:
            self.runtime_error = str(exc)
            self.failed_event.set()
            self.stop_event.set()
        finally:
            self._terminate_process()
            if self.writer is not None:
                self.writer.close()

    def stop(self) -> None:
        self.stop_event.set()
        self._terminate_process()

    def _parse_global_header(self, header: bytes) -> tuple[str, bool, int]:
        magic = header[:4]
        if magic not in _PCAP_MAGIC:
            raise RouterCaptureRuntimeError("Router tcpdump produced an unsupported pcap stream.")
        endian, timestamp_is_ns = _PCAP_MAGIC[magic]
        _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, link_type = struct.unpack(f"{endian}HHIIII", header[4:])
        return endian, timestamp_is_ns, int(link_type)

    def _read_exact(self, size: int) -> bytes:
        assert self.process is not None and self.process.stdout is not None
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = self.process.stdout.read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        for raw_line in iter(self.process.stderr.readline, b""):
            line = raw_line.decode(errors="replace").strip()
            if line:
                self.stderr_lines.append(line)

    def _startup_error(self, fallback: str) -> str:
        if self.process is not None:
            self.process.poll()
        details = "\n".join(self.stderr_lines[-8:])
        return f"{fallback}\n{details}" if details else fallback

    def _terminate_process(self) -> None:
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


class RouterTcpdumpCaptureSession:
    def __init__(
        self,
        *,
        config: NetworkCaptureConfig,
        session_bundle: SessionBundle,
        store: SessionBundleStore,
        stop_event: threading.Event,
        on_status=None,
        on_packet: Callable[[ParsedPacket, int], None] | None = None,
    ) -> None:
        _validate_capture_config(config)
        self.config = config
        self.session_bundle = session_bundle
        self.store = store
        self.stop_event = stop_event
        self.on_status = on_status or (lambda status: None)
        self.warnings: list[str] = []
        self.runtime_error: str | None = None

        target = NetworkCaptureTarget(
            interface_name=f"router:{config.router_interface.strip()}",
            raw_slug=_safe_slug("router", config.router_host, config.router_interface),
            local_ip_addresses=_parse_ip_list(config.device_ip),
        )
        self.target = target
        self.aggregator = NetworkBucketAggregator(
            session_bundle=self.session_bundle,
            config=self.config,
            store=self.store,
            target_lookup={target.interface_name: target},
        )
        self.worker = _RouterTcpdumpWorker(
            config=self.config,
            session_bundle=self.session_bundle,
            store=self.store,
            aggregator=self.aggregator,
            target=self.target,
            stop_event=self.stop_event,
            status_callback=self.on_status,
            packet_callback=on_packet,
        )

    def start(self) -> None:
        clock_evidence = {}
        ready, message = validate_router_access(self.config, synchronize_clock=False, evidence=clock_evidence)
        clock_evidence.update(ready=ready, message=message)
        evidence_path = self.session_bundle.session_dir / 'network' / 'router_clock_preflight.json'
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(clock_evidence, indent=2) + '\n', encoding='utf-8')
        if not ready:
            raise RouterCaptureRuntimeError(message)
        self.worker.launch()
        deadline = time.monotonic() + CAPTURE_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.worker.started_event.is_set():
                return
            if self.worker.failed_event.is_set():
                raise RouterCaptureRuntimeError(self.worker.runtime_error or "Router capture failed to start.")
            time.sleep(0.05)
        self.worker.stop()
        raise RouterCaptureRuntimeError("Timed out waiting for router tcpdump to start streaming pcap data.")

    def stop(self) -> NetworkCaptureResult:
        self.stop_event.set()
        self.worker.stop()
        self.worker.join(timeout=5)

        flushed = self.aggregator.flush_all()
        self.store.append_network_bucket_records(self.session_bundle.network_summary_csv, flushed)

        if self.worker.runtime_error:
            self.runtime_error = self.worker.runtime_error
            self.warnings.append(self.worker.runtime_error)

        stderr_warnings = _filter_tcpdump_stderr(self.worker.stderr_lines)
        self.warnings.extend(stderr_warnings)
        status = _status_from_totals(self.aggregator.total_packets, self.aggregator.total_bytes)
        return NetworkCaptureResult(
            raw_capture_files=self.worker.raw_files,
            warnings=tuple(dict.fromkeys(self.warnings)),
            total_packets=self.aggregator.total_packets,
            total_bytes=self.aggregator.total_bytes,
            backend_status=status.backend_status,
            raw_packet_status=(
                f"raw_packets={self.worker.raw_packets}, parsed_tcp_udp_packets={self.aggregator.total_packets}, "
                f"bytes={self.aggregator.total_bytes}"
            ),
            interface_stats={
                self.target.interface_name: {
                    "raw_packets": self.worker.raw_packets,
                    "raw_bytes": self.worker.raw_bytes,
                    "parsed_packets": self.aggregator.total_packets,
                    "parsed_bytes": self.aggregator.total_bytes,
                }
            },
        )


def _filter_tcpdump_stderr(lines: list[str]) -> list[str]:
    ignored_prefixes = (
        "tcpdump: listening on ",
        "tcpdump: data link type ",
    )
    ignored_suffixes = (
        " packets captured",
        " packets received by filter",
        " packets dropped by kernel",
    )
    warnings: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(prefix) for prefix in ignored_prefixes):
            continue
        if any(stripped.endswith(suffix) for suffix in ignored_suffixes):
            continue
        warnings.append(stripped)
    return warnings
