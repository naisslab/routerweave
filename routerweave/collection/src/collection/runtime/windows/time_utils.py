from __future__ import annotations

from datetime import datetime


def format_local_timestamp_ms(timestamp_ms: int) -> str:
    return datetime.fromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def filename_timestamp(timestamp_ms: int) -> str:
    return datetime.fromtimestamp(timestamp_ms / 1000).strftime("%Y%m%d_%H%M%S")


def parse_recent_user_input_timestamp_ms(value: str) -> int | None:
    if "@" not in value:
        return None
    _, _, raw_timestamp = value.partition("@")
    try:
        return int(raw_timestamp)
    except ValueError:
        return None


def format_recent_user_input_local(value: str) -> str:
    timestamp_ms = parse_recent_user_input_timestamp_ms(value)
    if timestamp_ms is None:
        return value
    prefix, _, _ = value.partition("@")
    return f"{prefix}@{format_local_timestamp_ms(timestamp_ms)}"
