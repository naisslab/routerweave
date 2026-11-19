from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SAMPLE_INTERVAL_MS = 1_000
DEFAULT_ENGAGED_IDLE_THRESHOLD_MS = 5_000


def get_runtime_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class LoggerConfig:
    sample_interval_ms: int = DEFAULT_SAMPLE_INTERVAL_MS
    output_root: Path = get_runtime_base_dir() / "desktop_logger_data"
    export_root: Path = get_runtime_base_dir() / "exports" / "desktop_logger"

    @property
    def sessions_dir(self) -> Path:
        return self.output_root / "sessions"

    def ensure_directories(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.export_root.mkdir(parents=True, exist_ok=True)
