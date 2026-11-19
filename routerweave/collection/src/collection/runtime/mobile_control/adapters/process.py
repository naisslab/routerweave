"""Injectable subprocess boundary used by platform transports."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class BinaryProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessExecutor(Protocol):
    def run(self, args: Sequence[str], timeout_seconds: float) -> ProcessResult: ...

    def run_bytes(
        self,
        args: Sequence[str],
        timeout_seconds: float,
    ) -> BinaryProcessResult: ...


class SubprocessExecutor:
    def run(self, args: Sequence[str], timeout_seconds: float) -> ProcessResult:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
        return ProcessResult(completed.returncode, completed.stdout or "", completed.stderr or "")

    def run_bytes(
        self,
        args: Sequence[str],
        timeout_seconds: float,
    ) -> BinaryProcessResult:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return BinaryProcessResult(
            completed.returncode,
            completed.stdout or b"",
            completed.stderr or b"",
        )
