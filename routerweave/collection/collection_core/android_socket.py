"""Android UID/package and socket evidence independent of task behavior."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

from .android_attribution import attribute_android_capture
from .evidence import PlatformEvidenceResult


PROC_NET_FILES = (
    ("/proc/net/tcp", "tcp", False),
    ("/proc/net/tcp6", "tcp", True),
    ("/proc/net/udp", "udp", False),
    ("/proc/net/udp6", "udp", True),
)


def parse_package_uid_map(text: str) -> dict[int, list[str]]:
    mapping: dict[int, list[str]] = {}
    pattern = re.compile(r"^package:(?P<package>\S+)\s+uid:(?P<uid>\d+)\s*$")
    for raw in text.splitlines():
        match = pattern.match(raw.strip())
        if match:
            mapping.setdefault(int(match.group("uid")), []).append(match.group("package"))
    return {uid: sorted(set(packages)) for uid, packages in mapping.items()}


def decode_ipv4(hex_addr: str) -> str:
    return str(ipaddress.IPv4Address(bytes.fromhex(hex_addr)[::-1]))


def decode_ipv6_or_mapped(hex_addr: str) -> str:
    upper = hex_addr.upper()
    if len(upper) == 32 and upper[16:24] == "FFFF0000":
        return decode_ipv4(upper[24:])
    raw = bytes.fromhex(upper)
    normalized = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return str(ipaddress.IPv6Address(normalized))


def decode_endpoint(token: str, *, ipv6: bool) -> tuple[str, int]:
    address, port = token.split(":", 1)
    return (
        decode_ipv6_or_mapped(address) if ipv6 else decode_ipv4(address),
        int(port, 16),
    )


def parse_proc_net(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: tuple[str, bool] | None = None
    for raw in text.splitlines():
        if raw.startswith("__FILE__"):
            path = raw.split(":", 1)[1].strip()
            current = next(
                ((protocol, ipv6) for item, protocol, ipv6 in PROC_NET_FILES if item == path),
                None,
            )
            continue
        if current is None:
            continue
        parts = raw.strip().split()
        if len(parts) < 8 or not parts[0].endswith(":") or parts[0] == "sl":
            continue
        protocol, ipv6 = current
        try:
            local_ip, local_port = decode_endpoint(parts[1], ipv6=ipv6)
            remote_ip, remote_port = decode_endpoint(parts[2], ipv6=ipv6)
            uid = int(parts[7])
        except (IndexError, ValueError):
            continue
        entries.append(
            {
                "proto": protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": parts[3],
                "uid": uid,
                "inode": parts[9] if len(parts) > 9 else None,
            }
        )
    return entries


class AndroidSocketEvidence:
    def __init__(
        self,
        *,
        serial: str,
        target_package: str,
        out_dir: str | Path,
        interval_seconds: float = 0.5,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if not serial:
            raise ValueError("Android socket evidence requires a device serial")
        if interval_seconds <= 0:
            raise ValueError("Android socket evidence interval must be positive")
        self.serial = serial
        self.target_package = target_package
        self.out_dir = Path(out_dir)
        self.interval_seconds = interval_seconds
        self._run_command = command_runner
        self.uid_packages: dict[int, list[str]] = {}
        self.target_uid: int | None = None
        self.sample_count = 0
        self.errors: list[str] = []
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._write_lock = threading.Lock()
        self.samples_path = self.out_dir / "socket_samples.jsonl"
        self.mapping_path = self.out_dir / "uid_packages.json"
        self.result_path = self.out_dir / "android_socket_evidence.json"

    def prepare(self) -> None:
        if shutil.which("adb") is None and self._run_command is subprocess.run:
            raise RuntimeError("Required tool not found on PATH: adb")
        self.out_dir.mkdir(parents=True, exist_ok=False)
        result = self._adb("shell", "pm", "list", "packages", "-U")
        if result.returncode != 0:
            raise RuntimeError(f"cannot read Android package UID map: {result.stderr.strip()}")
        self.uid_packages = parse_package_uid_map(result.stdout)
        uids = [uid for uid, packages in self.uid_packages.items() if self.target_package in packages]
        if len(uids) != 1 or self.uid_packages[uids[0]] != [self.target_package]:
            raise RuntimeError("target package requires a unique UID and package mapping")
        self.target_uid = uids[0]
        self.mapping_path.write_text(
            json.dumps(
                {str(uid): packages for uid, packages in sorted(self.uid_packages.items())},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def start(self) -> None:
        if self.target_uid is None:
            raise RuntimeError("Android socket evidence must be prepared before start")
        self._append_sample(self._snapshot())
        self._thread.start()

    def stop(self) -> PlatformEvidenceResult:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=16)
            if self._thread.is_alive():
                raise RuntimeError("socket sampler did not stop before finalization")
        ready = self.target_uid is not None and self.sample_count > 0
        result = PlatformEvidenceResult(
            "android",
            "uid_socket_samples",
            ready,
            {
                "uid_packages": str(self.mapping_path),
                "socket_samples": str(self.samples_path),
                "result": str(self.result_path),
            },
            {
                "target_package": self.target_package,
                "target_uid": self.target_uid,
                "sample_count": self.sample_count,
                "sampling_interval_seconds": self.interval_seconds,
            },
            tuple(self.errors),
        )
        self._write_result(result)
        return result

    def finalize(
        self,
        *,
        capture_path: Path,
        network_windows: list[dict[str, Any]],
        phone_ip: str,
    ) -> PlatformEvidenceResult:
        if self.target_uid is None:
            raise RuntimeError("Android socket evidence was not prepared")
        attribution = attribute_android_capture(
            pcap_path=capture_path,
            samples_path=self.samples_path,
            uid_packages=self.uid_packages,
            target_package=self.target_package,
            target_uid=self.target_uid,
            phone_ip=phone_ip,
            network_windows=network_windows,
            out_dir=self.out_dir,
            max_sample_distance_seconds=max(3.0, self.interval_seconds * 4),
        )
        artifacts = {
            "uid_packages": str(self.mapping_path),
            "socket_samples": str(self.samples_path),
            "result": str(self.result_path),
            **attribution.artifacts,
        }
        metrics = {
            "target_package": self.target_package,
            "target_uid": self.target_uid,
            "sample_count": self.sample_count,
            "sampling_interval_seconds": self.interval_seconds,
            **attribution.metrics,
        }
        errors = tuple(self.errors) + attribution.errors
        result = PlatformEvidenceResult(
            "android",
            "uid_socket_packet_attribution",
            attribution.ready and self.sample_count > 0,
            artifacts,
            metrics,
            errors,
            attribution.formal_ready and not errors,
        )
        self._write_result(result)
        return result

    def _write_result(self, result: PlatformEvidenceResult) -> None:
        self.result_path.write_text(
            json.dumps(
                {
                    "platform": result.platform,
                    "evidence_type": result.evidence_type,
                    "ready": result.ready,
                    "formal_ready": result.formal_ready,
                    "artifacts": dict(result.artifacts),
                    "metrics": dict(result.metrics),
                    "errors": list(result.errors),
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def _adb(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self._run_command(
            ["adb", "-s", self.serial, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )

    def _snapshot(self) -> list[dict[str, Any]]:
        commands: list[str] = []
        for path, _, _ in PROC_NET_FILES:
            commands.append(f"echo __FILE__:{shlex.quote(path)}")
            commands.append(f"cat {shlex.quote(path)} 2>/dev/null")
        result = self._adb("shell", "; ".join(commands))
        if result.returncode != 0:
            raise RuntimeError(f"Android socket snapshot failed: {result.stderr.strip()}")
        entries = parse_proc_net(result.stdout)
        for entry in entries:
            entry["packages"] = self.uid_packages.get(int(entry["uid"]), [])
        return entries

    def _append_sample(self, entries: list[dict[str, Any]]) -> None:
        payload = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "monotonic": time.monotonic(),
            "entries": entries,
        }
        with self._write_lock, self.samples_path.open(
            "a", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(json.dumps(payload, ensure_ascii=False))
            handle.write("\n")
        self.sample_count += 1

    def _sample_loop(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self._append_sample(self._snapshot())
            except Exception as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")
