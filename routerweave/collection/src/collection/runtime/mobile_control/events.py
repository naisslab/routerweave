"""Execution event sinks for auditability without coupling to capture code."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol


class EventSink(Protocol):
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None: ...


class NullEventSink:
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        return None


class CompositeEventSink:
    """Deliver one engine event to durable logging and lifecycle observers."""

    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = tuple(sinks)

    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        errors: list[str] = []
        for sink in self.sinks:
            try:
                sink.emit(event_type, payload)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
        if errors:
            raise RuntimeError("; ".join(errors))


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


class JsonlEventSink:
    """Append-only task evidence that capture runners can timestamp-align later."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        row = {
            "event_type": event_type,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "payload": _json_value(payload),
        }
        line = json.dumps(row, ensure_ascii=False, sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.write("\n")
