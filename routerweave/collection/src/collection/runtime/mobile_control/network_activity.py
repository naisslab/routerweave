"""Lightweight live activity evidence from the current router PCAP file."""

from __future__ import annotations

from collections import deque
from pathlib import Path
import time
from typing import Callable


class CaptureGrowthProbe:
    """Classify sustained host traffic without decoding or reopening the PCAP.

    Router capture already writes a host-filtered local file.  File growth is a
    cheap independent signal that can distinguish a genuinely quiet stream from
    a game scene whose pixels happen not to move.  A short hold absorbs normal
    tcpdump/stdout flush jitter.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        window_seconds: float = 10.0,
        active_hold_seconds: float = 15.0,
        minimum_bytes_per_second: float = 4 * 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if window_seconds <= 0 or active_hold_seconds < 0:
            raise ValueError("network activity windows must be positive")
        if minimum_bytes_per_second < 0:
            raise ValueError("minimum network activity rate cannot be negative")
        self.path = Path(path)
        self.window_seconds = float(window_seconds)
        self.active_hold_seconds = float(active_hold_seconds)
        self.minimum_bytes_per_second = float(minimum_bytes_per_second)
        self._clock = clock
        self._samples: deque[tuple[float, int]] = deque()
        self._last_active_at: float | None = None

    def observe(self) -> dict[str, object]:
        now = self._clock()
        try:
            size = self.path.stat().st_size
        except OSError:
            return {
                "capture_activity": "unknown",
                "capture_bytes": 0,
                "bytes_per_second": None,
                "sample_seconds": 0.0,
            }

        self._samples.append((now, size))
        while len(self._samples) > 2 and now - self._samples[0][0] > self.window_seconds:
            self._samples.popleft()
        first_at, first_size = self._samples[0]
        elapsed = max(0.0, now - first_at)
        rate = max(0.0, size - first_size) / elapsed if elapsed > 0 else None
        if rate is not None and rate >= self.minimum_bytes_per_second:
            self._last_active_at = now

        if (
            self._last_active_at is not None
            and now - self._last_active_at <= self.active_hold_seconds
        ):
            activity = "active"
        elif elapsed >= min(5.0, self.window_seconds):
            activity = "inactive"
        else:
            activity = "unknown"
        return {
            "capture_activity": activity,
            "capture_bytes": size,
            "bytes_per_second": round(rate, 3) if rate is not None else None,
            "sample_seconds": round(elapsed, 3),
        }
