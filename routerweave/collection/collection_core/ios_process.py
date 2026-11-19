"""Lifecycle-managed iOS process pcap evidence for semantic mobile tasks."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Callable, Mapping

from .evidence import PlatformEvidenceResult
from .ios_attribution import attribute_ios_process_capture


def safe_capture_label(value: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return label.strip("._-") or "process"


class IosProcessEvidence:
    """Start go-ios process capture only after the app launch step succeeds."""

    def __init__(
        self,
        *,
        bundle_id: str,
        process_name: str,
        out_dir: str | Path,
        udid: str = "",
        ios_command: str = "ios",
        startup_probe_seconds: float = 1.0,
        popen_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
        pid_resolver: Callable[[], int] | None = None,
    ) -> None:
        if not udid and popen_factory is subprocess.Popen:
            raise ValueError("select the iOS device by UDID")
        if not bundle_id.strip():
            raise ValueError("iOS process evidence requires a bundle ID")
        if not process_name.strip():
            raise ValueError("iOS process evidence requires a registered process name")
        if startup_probe_seconds < 0:
            raise ValueError("startup_probe_seconds cannot be negative")
        self.bundle_id = bundle_id
        self.process_name = process_name
        self.out_dir = Path(out_dir)
        self.udid = udid
        self.ios_command = ios_command
        self.startup_probe_seconds = startup_probe_seconds
        self._popen = popen_factory
        self._pid_resolver = pid_resolver
        self._process_pid: int | None = None
        self._armed = False
        self._capture_started = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._stdout_handle: Any = None
        self._stderr_handle: Any = None
        self._pcap_path: Path | None = None
        self.errors: list[str] = []
        label = safe_capture_label(f"process-{process_name}")
        self.stdout_path = self.out_dir / f"{label}.stdout.bin"
        self.stderr_path = self.out_dir / f"{label}.stderr.log"
        self.final_pcap_path = self.out_dir / f"{label}.pcap"
        self.result_path = self.out_dir / "ios_process_evidence.json"
        self._last_result: PlatformEvidenceResult | None = None

    def prepare(self) -> None:
        if self._popen is subprocess.Popen and shutil.which(self.ios_command) is None:
            raise RuntimeError(f"required tool not found on PATH: {self.ios_command}")
        self.out_dir.mkdir(parents=True, exist_ok=False)

    def start(self) -> None:
        self._armed = True

    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        if not self._armed or self._capture_started or event_type != "step_finished":
            return
        result = payload.get("result")
        step_id = getattr(result, "step_id", None)
        outcome = getattr(result, "outcome", None)
        successful = getattr(outcome, "value", outcome) == "success"
        if isinstance(result, Mapping):
            step_id = result.get("step_id")
            outcome = result.get("outcome")
            successful = str(getattr(outcome, "value", outcome)) == "success"
        if step_id == "launch-app" and successful:
            self._start_capture()

    def stop(self) -> PlatformEvidenceResult:
        self._armed = False
        if self._proc is not None and self._capture_started and self._proc.poll() is not None:
            self.errors.append("process capture exited before the stop request")
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        self._close_files()
        try:
            self._pcap_path = self._resolve_created_pcap()
        except Exception as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        if not self._capture_started:
            self.errors.append("iOS process capture never started after launch-app")
        elif self._pcap_path is None:
            self.errors.append("go-ios process capture produced no pcap")
        pcap_bytes = (
            self._pcap_path.stat().st_size
            if self._pcap_path is not None and self._pcap_path.is_file()
            else 0
        )
        result = PlatformEvidenceResult(
            "ios",
            "process_pcap",
            pcap_bytes > 24,
            self._artifacts(),
            {
                "bundle_id": self.bundle_id,
                "process_name": self.process_name,
                "process_pid": self._process_pid,
                "capture_started": self._capture_started,
                "process_pcap_bytes": pcap_bytes,
            },
            tuple(self.errors),
        )
        self._last_result = result
        self._write_result(result)
        return result

    def finalize(
        self,
        *,
        capture_path: Path,
        network_windows: list[dict[str, Any]],
        phone_ip: str,
    ) -> PlatformEvidenceResult:
        del capture_path  # Router pcap validity is enforced by the collection lifecycle.
        if self._pcap_path is None or not self._pcap_path.is_file():
            if self._last_result is None:
                raise RuntimeError("iOS process evidence must be stopped before finalize")
            return self._last_result
        attribution = attribute_ios_process_capture(
            pcap_path=self._pcap_path,
            bundle_id=self.bundle_id,
            process_name=self.process_name,
            phone_ip=phone_ip,
            network_windows=network_windows,
            out_dir=self.out_dir,
        )
        artifacts = {**self._artifacts(), **attribution.artifacts}
        metrics = {
            "bundle_id": self.bundle_id,
            "process_name": self.process_name,
            "process_pid": self._process_pid,
            "capture_started": self._capture_started,
            "process_pcap_bytes": self._pcap_path.stat().st_size,
            **attribution.metrics,
        }
        errors = tuple(self.errors) + attribution.errors
        result = PlatformEvidenceResult(
            "ios",
            "process_pcap_packet_attribution",
            attribution.ready,
            artifacts,
            metrics,
            errors,
            attribution.formal_ready and self._capture_started and bool(self._process_pid) and not errors,
        )
        self._last_result = result
        self._write_result(result)
        return result

    def _start_capture(self) -> None:
        command = [self.ios_command]
        if self.udid:
            command.append(f"--udid={self.udid}")
        self._process_pid = (
            self._pid_resolver()
            if self._pid_resolver is not None
            else self._resolve_process_pid()
        )
        command.extend(("pcap", f"--pid={self._process_pid}"))
        if type(self._process_pid) is not int or self._process_pid <= 0:
            raise ValueError("invalid process PID")
        try:
            self._stdout_handle = self.stdout_path.open("xb")
            self._stderr_handle = self.stderr_path.open("xb")
            self._proc = self._popen(
                command,
                cwd=str(self.out_dir),
                stdout=self._stdout_handle,
                stderr=self._stderr_handle,
            )
            if self.startup_probe_seconds:
                time.sleep(self.startup_probe_seconds)
            if self._proc.poll() is not None:
                self._close_files()
                stderr = (
                    self.stderr_path.read_text(encoding="utf-8", errors="replace")
                    if self.stderr_path.is_file()
                    else ""
                )
                raise RuntimeError(
                    f"iOS process pcap exited during startup for {self.process_name}: {stderr.strip()}"
                )
            self._capture_started = True
        except Exception:
            self._close_files()
            raise

    def _resolve_process_pid(self) -> int:
        command = [self.ios_command]
        if self.udid:
            command.append(f"--udid={self.udid}")
        command.append("ps")
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(5.0, self.startup_probe_seconds + 5.0),
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "failed to resolve iOS process PID for "
                f"{self.process_name}: {completed.stderr.strip()}"
            )
        try:
            rows = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"ios ps returned invalid JSON while resolving {self.process_name}"
            ) from exc
        matches = [
            int(row["Pid"])
            for row in rows
            if isinstance(row, Mapping)
            and str(row.get("Name") or "") == self.process_name
            and row.get("IsApplication") is True
            and isinstance(row.get("Pid"), int)
            and int(row["Pid"]) > 0
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one running iOS application process named {self.process_name}, "
                f"found {len(matches)}"
            )
        return matches[0]

    def _resolve_created_pcap(self) -> Path | None:
        if not self._capture_started:
            return None
        created = list(self.out_dir.glob("dump-*.pcap"))
        if not created:
            return None
        if len(created) != 1:
            raise RuntimeError("ambiguous process capture output")
        source = created[0]
        if source.is_symlink() or source.resolve().parent != self.out_dir.resolve():
            raise RuntimeError("process capture is outside its output directory")
        if self.final_pcap_path.exists():
            raise FileExistsError(self.final_pcap_path)
        return source.rename(self.final_pcap_path)

    def _close_files(self) -> None:
        for name in ("_stdout_handle", "_stderr_handle"):
            handle = getattr(self, name)
            if handle is not None:
                try:
                    handle.close()
                finally:
                    setattr(self, name, None)

    def _artifacts(self) -> dict[str, str]:
        artifacts = {
            "result": str(self.result_path),
            "stdout": str(self.stdout_path),
            "stderr": str(self.stderr_path),
        }
        if self._pcap_path is not None:
            artifacts["process_pcap"] = str(self._pcap_path)
        return artifacts

    def _write_result(self, result: PlatformEvidenceResult) -> None:
        self.result_path.write_text(
            json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
