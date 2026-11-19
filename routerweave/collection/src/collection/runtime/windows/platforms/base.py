from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import DesktopLogRecord


class PlatformSnapshotter(ABC):
    @abstractmethod
    def create_record(self, session_id: str, now_ms: int, behavior_label: str) -> DesktopLogRecord:
        raise NotImplementedError
