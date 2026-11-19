"""Fast router-visible phone IP discovery for the unified collector."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from typing import Any, Callable
from urllib import request as urllib_request

from .status import Platform
from .task_runtime import MobileTaskRequest


def resolve_phone_ip(
    request: MobileTaskRequest,
    *,
    explicit: str = "",
    serial: str = "",
    wda_url: str = "http://127.0.0.1:8100",
) -> str:
    candidate = explicit.strip()
    if not candidate:
        if Platform(request.platform) is Platform.ANDROID:
            candidate = detect_android_wifi_ip(serial) or ""
        else:
            candidate = detect_ios_wifi_ip(wda_url) or ""
    if not candidate:
        raise RuntimeError(
            f"cannot detect router-visible {request.platform} Wi-Fi IP; pass it explicitly"
        )
    return validate_router_visible_ip(candidate)


def validate_router_visible_ip(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("phone_ip must be a valid IP address") from exc
    if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("phone_ip must be a router-visible unicast address")
    return str(parsed)


def detect_android_wifi_ip(
    serial: str,
    *,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str | None:
    if not serial:
        raise ValueError("serial is required to detect Android Wi-Fi IP")
    for shell_args in (
        ("ip", "-4", "addr", "show", "wlan0"),
        ("ip", "route"),
    ):
        result = command_runner(
            ["adb", "-s", serial, "shell", *shell_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            continue
        match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/", result.stdout)
        if match is None:
            match = re.search(r"\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b", result.stdout)
        if match is not None:
            try:
                return validate_router_visible_ip(match.group(1))
            except ValueError:
                continue
    return None


def detect_ios_wifi_ip(
    wda_url: str,
    *,
    opener: Callable[..., Any] = urllib_request.urlopen,
) -> str | None:
    status_url = wda_url.rstrip("/") + "/status"
    request = urllib_request.Request(status_url, method="GET")
    try:
        with opener(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None
    value = payload.get("value") if isinstance(payload, dict) else None
    ios = value.get("ios") if isinstance(value, dict) else None
    candidate = ios.get("ip") if isinstance(ios, dict) else None
    if not isinstance(candidate, str) or not candidate.strip():
        return None
    try:
        return validate_router_visible_ip(candidate)
    except ValueError:
        return None
