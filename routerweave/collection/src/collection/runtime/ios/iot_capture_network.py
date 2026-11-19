"""Resolve the addresses a plan needs for router capture.

A plan used to carry `capture_transport_host` (the collection workstation) and
`controller.phone_ip` as fixed values.  Both belong to machines that move
between networks, and a stale value silently changes which traffic the capture
excludes.  This module fills a missing value at run time from the current
network state, records what it resolved beside the run, and leaves an explicit
plan value untouched.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable

from collection.runtime.artifacts import EventLog, now_iso, write_json
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.device_ip import detect_ios_wifi_ip

ARTIFACT_NAME = "capture_network.json"
DEFAULT_PROBE_PORT = 80


def detect_routed_local_ip(destination: str, *, port: int = DEFAULT_PROBE_PORT) -> str:
    """Return the local address used to reach ``destination``, or an empty string.

    A UDP socket connection performs no traffic; it only asks the routing table
    which local address would be used, which is exactly the address the router
    sees for this workstation.
    """
    target = str(destination or "").strip()
    if not target:
        return ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(2.0)
            probe.connect((target, port))
            return str(probe.getsockname()[0])
    except OSError:
        return ""


def resolve_capture_addresses(
    plan: dict[str, Any],
    run_root: Path,
    *,
    log: EventLog | None = None,
    local_ip_detector: Callable[[str], str] = detect_routed_local_ip,
    phone_ip_detector: Callable[[str], str | None] = detect_ios_wifi_ip,
) -> dict[str, Any]:
    """Fill missing capture addresses on ``plan`` and record their origin.

    An explicit plan value always wins.  ``capture_transport_host`` is required
    for the capture exclusion, so an unresolvable host raises instead of
    building a filter that silently excludes nothing.
    """
    router = plan.setdefault("router", {})
    controller = plan.get("controller") or {}
    root = Path(run_root)
    root.mkdir(parents=True, exist_ok=True)
    artifact: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": now_iso(),
        "router_host": router.get("host"),
        "capture_transport_host": "",
        "capture_transport_host_source": "plan",
        "phone_ip": "",
        "phone_ip_source": "unavailable",
    }

    declared_host = str(router.get("capture_transport_host") or "").strip()
    if declared_host:
        artifact["capture_transport_host"] = declared_host
    else:
        detected_host = str(local_ip_detector(str(router.get("host") or "")) or "").strip()
        if not detected_host:
            raise DemoError(
                "Cannot determine the capture transport host: the plan has no "
                "router.capture_transport_host and the routed local address could "
                "not be detected. Add the value to the plan or run on the collection "
                "workstation that reaches the router."
            )
        router["capture_transport_host"] = detected_host
        artifact["capture_transport_host"] = detected_host
        artifact["capture_transport_host_source"] = "detected_routed_address"

    declared_phone = str(controller.get("phone_ip") or "").strip()
    if declared_phone:
        artifact["phone_ip"] = declared_phone
        artifact["phone_ip_source"] = "plan"
    else:
        wda_url = str(controller.get("wda_url") or "").strip()
        detected_phone = str(
            (phone_ip_detector(wda_url) if wda_url else None) or ""
        ).strip()
        artifact["phone_ip"] = detected_phone
        if detected_phone:
            controller["phone_ip"] = detected_phone
            if plan.get("controller"):
                plan["controller"]["phone_ip"] = detected_phone
            artifact["phone_ip_source"] = "detected_wda_status"

    write_json(root / ARTIFACT_NAME, artifact)
    if log is not None:
        log.write(
            "capture_network",
            capture_transport_host=artifact["capture_transport_host"],
            source=artifact["capture_transport_host_source"],
            phone_ip=artifact["phone_ip"],
            phone_ip_source=artifact["phone_ip_source"],
        )
    return artifact
