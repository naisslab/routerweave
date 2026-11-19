"""Low-rate screen evidence aligned with semantic task events."""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


def _value(value: Any, key: str, default: Any = "") -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    if is_dataclass(value):
        return getattr(value, key, default)
    return getattr(value, key, default)


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return cleaned[:80] or "event"


class ScreenshotEvidenceSink:
    """Capture sparse PNG evidence without making screenshots a task dependency."""

    def __init__(
        self,
        root: str | Path,
        capture: Callable[[], bytes],
        *,
        top_level_steps: frozenset[str] = frozenset(),
        max_key_steps: int = 5,
        max_midrun: int = 3,
        midrun_cooldown_seconds: float = 300.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.root = Path(root)
        self.images = self.root / "screenshots"
        self.index_path = self.root / "screen_evidence.jsonl"
        self._capture = capture
        self._top_level_steps = top_level_steps
        self._max_key_steps = max_key_steps
        self._max_midrun = max_midrun
        self._midrun_cooldown_seconds = midrun_cooldown_seconds
        self._monotonic = monotonic
        self._sequence = 0
        self._key_steps = 0
        self._midrun = 0
        self._last_midrun_at: float | None = None
        self._lock = threading.Lock()

    def emit(self, event_type: str, payload: Mapping[str, Any]) -> None:
        selection = self._select(event_type, payload)
        if selection is None:
            return
        step_id, label, outcome = selection
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
            captured_at = datetime.now(timezone.utc).isoformat()
            stem = _safe_name(step_id or label or event_type)
            image_name = f"{sequence:04d}_{_safe_name(event_type)}_{stem}.png"
            image_path = self.images / image_name
            row: dict[str, Any] = {
                "schema_version": 1,
                "sequence": sequence,
                "captured_at": captured_at,
                "source_event": event_type,
                "step_id": step_id,
                "label": label,
                "outcome": outcome,
                "image": f"screenshots/{image_name}",
            }
            try:
                png = self._capture()
                if not png:
                    raise RuntimeError("screen capture returned no bytes")
                self.images.mkdir(parents=True, exist_ok=True)
                image_path.write_bytes(png)
            except Exception as exc:
                row["image"] = ""
                row["error"] = f"{type(exc).__name__}: {exc}"
            self.root.mkdir(parents=True, exist_ok=True)
            with self.index_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
                handle.write("\n")

    def _select(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> tuple[str, str, str] | None:
        if event_type == "step_finished":
            result = payload.get("result")
            step_id = str(_value(result, "step_id"))
            outcome = str(_value(_value(result, "outcome"), "value", _value(result, "outcome")))
            failed = outcome not in {"success", "skipped"}
            key_step = (
                step_id in self._top_level_steps
                and step_id not in {"monitor-active-state", "terminate-app"}
                and self._key_steps < self._max_key_steps
            )
            if not failed and not key_step:
                return None
            if key_step:
                self._key_steps += 1
            return step_id, "", outcome

        if event_type == "activity_finished":
            result = payload.get("result")
            now = self._monotonic()
            if self._midrun >= self._max_midrun or (
                self._last_midrun_at is not None
                and now - self._last_midrun_at < self._midrun_cooldown_seconds
            ):
                return None
            self._midrun += 1
            self._last_midrun_at = now
            return (
                str(payload.get("step_id") or ""),
                str(_value(result, "label")),
                str(_value(_value(result, "outcome"), "value", _value(result, "outcome"))),
            )

        if event_type == "interruption_finished":
            result = payload.get("result")
            return (
                str(payload.get("step_id") or ""),
                str(_value(result, "interruption_id", "interruption")),
                str(_value(_value(result, "outcome"), "value", _value(result, "outcome"))),
            )

        if event_type == "playbook_finished":
            result = payload.get("result")
            return (
                "playbook-finished",
                str(_value(result, "playbook_id")),
                str(_value(_value(result, "outcome"), "value", _value(result, "outcome"))),
            )
        return None
