"""Packet evidence fields shared by both mobile platforms."""

import json
from pathlib import Path
from typing import Any


PACKET_COLUMNS = (
    "time", "stream_id", "protocol", "source_address", "source_port",
    "destination_address", "destination_port", "length", "certificate",
    "app", "network_window_id", "attribution_confidence",
)


def write_json(path: Path, payload: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
