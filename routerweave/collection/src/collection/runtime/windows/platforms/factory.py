from __future__ import annotations

import platform

from .base import PlatformSnapshotter
from .windows import WindowsSnapshotter


def create_snapshotter(platform_name: str | None = None) -> PlatformSnapshotter:
    resolved = (platform_name or platform.system()).strip().lower()
    if resolved in {"windows", "win32"}:
        return WindowsSnapshotter()
    raise NotImplementedError(f"Unsupported platform: {resolved}")
