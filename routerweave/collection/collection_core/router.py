"""Managed router tcpdump streaming shared by every mobile platform."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
from typing import Any, Protocol
import uuid


class EventWriter(Protocol):
    def write(self, event: str, **fields: Any) -> None: ...


class RouterCaptureError(RuntimeError):
    pass


CAPTURE_READY_TIMEOUT_SECONDS = 15.0
_PCAP_GLOBAL_HEADER_BYTES = 24
_TRAILER_PATTERNS = {
    "captured": re.compile(r"(\d+) packets? captured"),
    "received_by_filter": re.compile(r"(\d+) packets? received by filter"),
    "kernel_dropped": re.compile(r"(\d+) packets? dropped by kernel"),
}


def parse_tcpdump_trailer(text: str) -> dict[str, int | None]:
    """Return tcpdump's final capture statistics, or None for missing counters."""

    result: dict[str, int | None] = {}
    for key, pattern in _TRAILER_PATTERNS.items():
        matches = pattern.findall(text)
        result[key] = int(matches[-1]) if matches else None
    return result


def _ssh_identity_args(identity_file: str | None) -> list[str]:
    args = ["-n", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no"]
    if identity_file:
        args.extend(("-i", identity_file, "-o", "IdentitiesOnly=yes"))
    return args


def _ssh_process_options() -> dict[str, Any]:
    # GUI-launched collectors must not inherit a hidden PowerShell console or
    # its input handle. Router commands and tcpdump only use stdout/stderr.
    return {"stdin": subprocess.DEVNULL,
            "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _router_ssh(
    user: str,
    host: str,
    command: str,
    *,
    identity_file: str | None,
    timeout: float = 20,
) -> subprocess.CompletedProcess[str]:
    _validate_endpoint(user, host)
    if shutil.which("ssh") is None:
        raise RouterCaptureError("Required tool not found on PATH: ssh")
    return subprocess.run(
        [
            "ssh",
            *_ssh_identity_args(identity_file),
            f"{user}@{host}",
            command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        **_ssh_process_options(),
    )


def _validate_endpoint(user: str, host: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", user):
        raise ValueError("invalid SSH username")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]*", host):
        raise ValueError("invalid SSH hostname")


class RouterStreamCapture:
    """Stream one filtered router pcap to local disk with owned PID cleanup."""

    def __init__(
        self,
        *,
        user: str,
        host: str,
        interface: str,
        phone_ip: str | None,
        local_pcap: Path,
        log: EventWriter,
        identity_file: str | None = None,
        capture_filter: str | None = None,
        ssh_keepalive_seconds: int = 0,
    ) -> None:
        if type(ssh_keepalive_seconds) is not int or ssh_keepalive_seconds < 0:
            raise ValueError("ssh_keepalive_seconds must be a nonnegative integer")
        _validate_endpoint(user, host)
        if phone_ip:
            ipaddress.ip_address(phone_ip)
        if not phone_ip and not (capture_filter or "").strip():
            raise ValueError("supply a device address or an explicit capture filter")
        self.user = user
        self.host = host
        self.interface = interface
        self.phone_ip = phone_ip
        self.local_pcap = local_pcap
        self.log = log
        self.identity_file = identity_file
        if capture_filter is not None and not capture_filter.strip():
            raise ValueError("an explicit capture filter cannot be empty")
        self.capture_filter = capture_filter
        self.ssh_keepalive_seconds = ssh_keepalive_seconds
        self.capture_id = uuid.uuid4().hex
        self.remote_pidfile = f"/tmp/mobile-control-stream-{self.capture_id}.pid"
        self.proc: subprocess.Popen[bytes] | None = None
        self.stdout_file: Any = None
        self.stderr_file: Any = None
        self.stderr_path = local_pcap.with_suffix(local_pcap.suffix + ".tcpdump.stderr.log")

    def start(self) -> None:
        self.local_pcap.parent.mkdir(parents=True, exist_ok=True)
        capture_filter = self.capture_filter
        if capture_filter is None:
            capture_filter = f"host {self.phone_ip}" if self.phone_ip else ""
        normalized_filter = capture_filter.strip()
        remote_cmd = (
            "command -v tcpdump >/dev/null 2>&1 || "
            "{ echo 'tcpdump not installed on router' >&2; exit 127; }; "
            f"echo $$ > {shlex.quote(self.remote_pidfile)}; "
            f"exec tcpdump -i {shlex.quote(self.interface)} -s 0 -U -w -"
            f"{' ' + shlex.quote(normalized_filter) if normalized_filter else ''}"
        )
        cmd = [
            "ssh",
            *_ssh_identity_args(self.identity_file),
            *(["-o", f"ServerAliveInterval={self.ssh_keepalive_seconds}",
               "-o", "ServerAliveCountMax=3"] if self.ssh_keepalive_seconds else []),
            f"{self.user}@{self.host}",
            remote_cmd,
        ]
        if self.proc is not None:
            raise RouterCaptureError("capture already started")
        try:
            self.stdout_file = self.local_pcap.open("xb")
            self.stderr_file = self.stderr_path.open("xb")
            self.proc = subprocess.Popen(
                cmd, stdout=self.stdout_file, stderr=self.stderr_file, **_ssh_process_options()
            )
            ready_signal = self._wait_until_streaming()
        except BaseException:
            if self.proc is not None:
                self.stop()
            else:
                self.close_files()
            raise
        self.log.write(
            "router_stream_capture_started",
            host=self.host,
            interface=self.interface,
            phone_ip=self.phone_ip,
            capture_filter=normalized_filter or None,
            local_pcap=str(self.local_pcap),
            stderr=str(self.stderr_path),
            pid=self.proc.pid,
            capture_id=self.capture_id,
            remote_pidfile=self.remote_pidfile,
            ready_signal=ready_signal,
        )

    def _stderr_text(self) -> str:
        if not self.stderr_path.exists():
            return ""
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")

    def _wait_until_streaming(self) -> str:
        """Block until tcpdump is capturing, so task traffic is not lost at startup."""

        assert self.proc is not None
        deadline = time.monotonic() + CAPTURE_READY_TIMEOUT_SECONDS
        while True:
            if self.proc.poll() is not None:
                self.close_files()
                raise RouterCaptureError(
                    f"Router tcpdump stream failed to start with exit code "
                    f"{self.proc.returncode}: {self._stderr_text()}"
                )
            if "listening on" in self._stderr_text():
                return "tcpdump_listening"
            if (
                self.local_pcap.exists()
                and self.local_pcap.stat().st_size >= _PCAP_GLOBAL_HEADER_BYTES
            ):
                return "pcap_header_received"
            if time.monotonic() >= deadline:
                raise RouterCaptureError(
                    "Timed out waiting for router tcpdump to start streaming: "
                    f"{self._stderr_text()}"
                )
            time.sleep(0.1)

    def _terminate_local_process(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def _remove_remote_marker(self) -> str:
        try:
            return _router_ssh(
                self.user,
                self.host,
                f"rm -f {shlex.quote(self.remote_pidfile)}",
                identity_file=self.identity_file,
            ).stderr.strip()
        except (OSError, subprocess.SubprocessError, RouterCaptureError) as exc:
            return f"{type(exc).__name__}: {exc}"

    def close_files(self) -> None:
        for handle_name in ("stdout_file", "stderr_file"):
            handle = getattr(self, handle_name)
            if handle:
                try:
                    handle.close()
                finally:
                    setattr(self, handle_name, None)

    def stop(self) -> None:
        if not self.proc:
            return
        stop_error: str | None = None
        try:
            if self.proc.poll() is None:
                try:
                    remote_stop = _router_ssh(
                        self.user,
                        self.host,
                        (
                            f"if [ -f {shlex.quote(self.remote_pidfile)} ]; then "
                            f"pid=$(cat {shlex.quote(self.remote_pidfile)} 2>/dev/null || true); "
                            "if [ -n \"$pid\" ]; then kill -INT \"$pid\" 2>/dev/null || true; fi; "
                            "fi"
                        ),
                        identity_file=self.identity_file,
                    )
                    if remote_stop.returncode:
                        raise RouterCaptureError(remote_stop.stderr.strip() or "router stop failed")
                    self.log.write(
                        "router_stream_capture_stop_requested",
                        capture_id=self.capture_id,
                        remote_pidfile=self.remote_pidfile,
                        stdout=remote_stop.stdout.strip(),
                        stderr=remote_stop.stderr.strip(),
                    )
                except (OSError, subprocess.SubprocessError, RouterCaptureError) as exc:
                    # Still end the local stream; an unreachable router must not
                    # leave this process or its file handles open.
                    stop_error = f"{type(exc).__name__}: {exc}"
                    self.log.write(
                        "router_stream_capture_stop_request_failed",
                        capture_id=self.capture_id,
                        error=stop_error,
                    )
                try:
                    self.proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    stop_error = stop_error or "tcpdump did not exit after the stop request"
                    self._terminate_local_process()
        finally:
            try:
                self._terminate_local_process()
            finally:
                self.close_files()
            returncode = self.proc.returncode
            self.proc = None
            marker_cleanup_stderr = self._remove_remote_marker()
            stderr_size = self.stderr_path.stat().st_size if self.stderr_path.exists() else 0
            self.log.write(
                "router_stream_capture_stopped",
                returncode=returncode,
                pcap=str(self.local_pcap),
                bytes=self.local_pcap.stat().st_size if self.local_pcap.exists() else 0,
                stderr=str(self.stderr_path),
                stderr_bytes=stderr_size,
                capture_id=self.capture_id,
                remote_pidfile=self.remote_pidfile,
                marker_cleanup_stderr=marker_cleanup_stderr,
                tcpdump_statistics=parse_tcpdump_trailer(self._stderr_text()),
            )
        if stop_error is not None:
            raise RouterCaptureError(f"router stop request failed: {stop_error}")
