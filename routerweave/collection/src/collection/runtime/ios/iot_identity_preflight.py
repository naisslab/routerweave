"""Resolve and verify IoT device endpoint identity before capture starts.

Plans and ``configs/iot_device_network_identities.json`` record the MAC (and
IP) each IoT device had when its dataset was collected.  A DHCP reassignment,
a device moved to another network segment, or replaced hardware makes that
record stale.  Until now the mismatch only surfaced after a finished batch as
an empty device-related capture, which reads like "the device did not react".

This preflight resolves every planned device through the router client list by
MAC before capture starts, writes the result beside the run, and fails closed
when a device that has a recorded identity is not uniquely reachable on the
capture segment.
"""

from __future__ import annotations

import json
import hashlib
import ipaddress
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from collection.runtime.artifacts import EventLog, now_iso, write_json
from collection.runtime.errors import DemoError
from collection.runtime.mobile_control.capture.router import _router_ssh
from collection.runtime.mobile_control.manual_network import match_router_client

ARTIFACT_NAME = "identity_preflight.json"
MODES = ("enforce", "advisory", "off")
DEFAULT_MODE = "enforce"
ROUTER_CLIENT_COMMAND = "ubus call gl-clients list"
ROUTER_LEASE_COMMAND = "cat /tmp/dhcp.leases"

STATUS_MATCHED = "matched"
STATUS_IP_CHANGED = "ip_changed"
STATUS_NOT_ONLINE = "mac_not_online"
STATUS_NO_IDENTITY = "no_identity"
STATUS_ROUTER_UNAVAILABLE = "router_unavailable"
STATUS_ADDRESS_OWNER_CONFLICT = "address_owner_conflict"

# A device without a recorded MAC (for example a Thread accessory that is only
# reachable through its home hub) cannot be resolved from the plan alone.
FATAL_STATUSES = (STATUS_NOT_ONLINE, STATUS_ADDRESS_OWNER_CONFLICT)


def reconcile_dhcp_ownership(
    clients: dict[str, Any], lease_text: str, *, now_epoch: float | None = None,
) -> dict[str, Any]:
    """Keep an ARP/sleep-proxy alias from becoming a device's own address."""
    now = time.time() if now_epoch is None else now_epoch
    by_mac: dict[str, set[str]] = {}
    owners: dict[str, set[str]] = {}
    for line in lease_text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        try:
            expiry = int(fields[0])
            mac = fields[1].lower()
            address = str(ipaddress.IPv4Address(fields[2]))
            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                raise ValueError("invalid MAC")
        except (IndexError, ValueError) as exc:
            raise DemoError("Router DHCP lease snapshot is malformed") from exc
        if expiry and expiry <= now:
            continue
        by_mac.setdefault(mac, set()).add(address)
        owners.setdefault(address, set()).add(mac)
    result: dict[str, Any] = {}
    for key, original in clients.items():
        row = dict(original)
        mac = str(row.get("mac") or "").lower()
        reported = str(row.get("ip") or "")
        leased = sorted(by_mac.get(mac, set()))
        evidence: dict[str, Any] = {
            "router_reported_ip": reported,
            "leased_ipv4_addresses": leased,
            "reported_ip_lease_owners": sorted(owners.get(reported, set())),
            "method": "router_client_no_active_lease",
            "error": None,
        }
        if len(leased) > 1:
            evidence["error"] = "MAC has multiple active DHCP IPv4 addresses"
        elif leased:
            address = leased[0]
            if owners[address] != {mac}:
                evidence["error"] = "DHCP IPv4 address has multiple MAC owners"
            else:
                row["ip"] = address
                evidence["method"] = "active_dhcp_lease_mac"
        elif owners.get(reported) and owners[reported] != {mac}:
            evidence["error"] = "Router-reported IPv4 is leased to a different MAC"
        row["address_identity"] = evidence
        result[key] = row
    return result


def materialize_endpoint_evidence(root: Path, device: dict[str, Any]) -> dict[str, Any] | None:
    """Archive explicit address-ownership proof before starting control/capture."""
    if device.get("verified_ips") is None:
        return None
    source = Path(str(device.get("verified_ip_evidence") or ""))
    if not source.is_file():
        raise DemoError(f"Missing endpoint evidence for {device['id']}")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != device.get("verified_ip_evidence_sha256"):
        raise DemoError(f"Endpoint evidence hash mismatch for {device['id']}")
    proof = json.loads(data.decode("utf-8-sig"))
    if proof.get("device_id") != device["id"] or set(proof.get("verified_ips") or []) != set(device["verified_ips"]):
        raise DemoError(f"Endpoint evidence identity/address mismatch for {device['id']}")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", str(device["id"])):
        raise DemoError("Unsafe device ID in endpoint evidence destination")
    folder = Path(root).resolve() / "network_identity_evidence" / device["id"]
    folder.mkdir(parents=True, exist_ok=True)

    def copy_verified(path: Path, content: bytes) -> None:
        if path.exists() and path.read_bytes() != content:
            raise DemoError(f"Conflicting run-local endpoint evidence: {path}")
        path.write_bytes(content)

    local = folder / "evidence.json"
    copy_verified(local, data)
    artifacts: dict[str, str] = {}
    hashes = proof.get("artifacts_sha256") or {}
    if not proof.get("artifacts"):
        raise DemoError("Endpoint evidence has no source artifacts")
    for key, original in proof["artifacts"].items():
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise DemoError("Unsafe endpoint artifact name")
        artifact = Path(original)
        content = artifact.read_bytes()
        if hashlib.sha256(content).hexdigest() != hashes.get(key):
            raise DemoError(f"Endpoint artifact hash mismatch: {key}")
        target = folder / (key + artifact.suffix)
        copy_verified(target, content)
        artifacts[key] = str(target)
    return {"evidence_file": str(local), "evidence_sha256": digest,
            "source_evidence_file": str(source.resolve()), "verified_ips": proof["verified_ips"],
            "artifacts": artifacts, "artifacts_sha256": hashes}


class _RouterBinding:
    """Adapt a plan ``router`` mapping to the attribute access used upstream."""

    def __init__(self, value: dict[str, Any]) -> None:
        self.user = value["user"]
        self.host = value["host"]
        self.identity_file = value.get("identity_file")


def _router_binding(value: Any) -> Any:
    if hasattr(value, "user"):
        return value
    return _RouterBinding(value)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").strip()
    return str(value or "").strip()


def fetch_router_clients(router: Any) -> dict[str, Any]:
    """Return the router's current client table, keyed by router client id."""
    binding = _router_binding(router)
    response = _router_ssh(
        binding.user,
        binding.host,
        ROUTER_CLIENT_COMMAND,
        identity_file=binding.identity_file,
        timeout=8,
    )
    if response.returncode:
        raise DemoError(
            f"router {binding.host} did not return its client list: "
            f"{_text(getattr(response, 'stderr', '')) or 'no diagnostic output'}"
        )
    try:
        clients = json.loads(_text(response.stdout))["clients"]
    except (KeyError, TypeError, ValueError) as exc:
        raise DemoError(
            f"router {binding.host} returned an unexpected client list: {exc}"
        ) from exc
    lease_response = _router_ssh(
        binding.user, binding.host, ROUTER_LEASE_COMMAND,
        identity_file=binding.identity_file, timeout=8,
    )
    if lease_response.returncode:
        raise DemoError(f"router {binding.host} DHCP ownership snapshot unavailable")
    return reconcile_dhcp_ownership(clients, _text(lease_response.stdout))


def configured_identity(device: dict[str, Any]) -> dict[str, Any] | None:
    mac = str(device.get("mac") or "").strip()
    if not mac:
        return None
    return {
        "mac": mac,
        "scope": device.get("scope") or "direct_device",
        "proxy_device": device.get("proxy_device"),
        "identity_key": device.get("id"),
    }


def classify_devices(
    devices: list[dict[str, Any]],
    clients: dict[str, Any],
    *,
    checked_at: str | None = None,
) -> list[dict[str, Any]]:
    """Resolve each planned device by MAC and classify the current binding."""
    checked = checked_at or datetime.now(timezone.utc).isoformat()
    results: list[dict[str, Any]] = []
    for device in devices:
        row: dict[str, Any] = {
            "device_id": device.get("id"),
            "device_type": device.get("device_type"),
            "plan_ip": device.get("ip"),
            "plan_mac": device.get("mac"),
            "scope": device.get("scope") or "direct_device",
            "status": STATUS_NO_IDENTITY,
            "resolved_ip": None,
            "router_name": None,
            "wifi_band": None,
            "checked_at_utc": checked,
            "detail": None,
        }
        identity = configured_identity(device)
        if identity is None:
            row["detail"] = (
                "plan records no MAC for this device; it cannot be resolved by "
                "router client lookup"
            )
            results.append(row)
            continue
        active = [client for client in clients.values()
                  if str(client.get("mac") or "").lower() == identity["mac"].lower()
                  and client.get("online") is True]
        if len(active) == 1:
            evidence = active[0].get("address_identity")
            if evidence:
                row["address_identity"] = evidence
                if evidence.get("error"):
                    row["status"] = STATUS_ADDRESS_OWNER_CONFLICT
                    row["detail"] = evidence["error"]
                    results.append(row)
                    continue
        try:
            resolved = match_router_client(identity, clients)
        except ValueError as exc:
            row["status"] = STATUS_NOT_ONLINE
            row["detail"] = str(exc)
        else:
            row["resolved_ip"] = resolved["ip"]
            row["router_name"] = resolved.get("router_name")
            row["wifi_band"] = resolved.get("wifi_band")
            if str(resolved["ip"]) == str(row["plan_ip"] or ""):
                row["status"] = STATUS_MATCHED
            else:
                row["status"] = STATUS_IP_CHANGED
                row["detail"] = (
                    f"router reports {resolved['ip']} for this MAC while the plan "
                    f"records {row['plan_ip']}; the recorded MAC still matches, so "
                    "capture filtering keeps working"
                )
        results.append(row)
    return results


def _write_artifact(
    run_root: Path,
    artifact: dict[str, Any],
    log: EventLog | None,
) -> Path:
    path = run_root / ARTIFACT_NAME
    write_json(path, artifact)
    if log is not None:
        log.write(
            "identity_preflight",
            mode=artifact["mode"],
            status=artifact["status"],
            devices=len(artifact["devices"]),
            artifact=str(path),
            detail=artifact.get("detail"),
        )
    return path


def apply_resolved_identities(
    plan: dict[str, Any],
    artifact: dict[str, Any],
    *,
    log: EventLog | None = None,
) -> list[dict[str, Any]]:
    """Write capture-time addresses back into the planned device entries.

    Every sample row records ``device_ip`` from its plan device, so the resolved
    address has to land there before the first sample. Otherwise a published
    dataset would carry the stale planned address while the capture itself used
    the live one. Devices without a resolved address (a home-hub proxy, or a MAC
    that stayed offline in advisory mode) are left exactly as they are.
    """
    resolved = {
        str(row.get("device_id") or ""): row
        for row in artifact.get("devices") or []
        if row.get("status") in (STATUS_MATCHED, STATUS_IP_CHANGED)
    }
    updates: list[dict[str, Any]] = []
    for device in plan.get("devices") or []:
        row = resolved.get(str(device.get("id") or ""))
        address = str((row or {}).get("resolved_ip") or "").strip()
        if not row or not address:
            continue
        if row.get("address_identity"):
            device["address_identity"] = row["address_identity"]
        verified = device.get("verified_ips")
        if verified is not None and address not in verified:
            raise DemoError(
                f"Resolved address for {device['id']} is not in its verified endpoint set"
            )
        previous = str(device.get("ip") or "").strip()
        if previous == address:
            continue
        device["ip"] = address
        updates.append(
            {
                "device_id": device.get("id"),
                "mac": device.get("mac"),
                "plan_ip": previous,
                "resolved_ip": address,
            }
        )
    if updates and log is not None:
        log.write(
            "identity_applied",
            devices=[str(item["device_id"]) for item in updates],
            updates=updates,
        )
    return updates


def _failure_message(artifact: dict[str, Any], failing: list[dict[str, Any]]) -> str:
    lines = [
        "Identity preflight failed before capture started. These planned devices "
        "are not uniquely reachable on the capture segment:"
    ]
    for row in failing:
        lines.append(f"  - {row['device_id']} (mac {row['plan_mac']}): {row['detail']}")
    lines.append(
        "Recorded identities go stale when DHCP reassigns an address, a device "
        "moves to another network segment, or the hardware is replaced. Confirm "
        "the device is online on the capture interface, then correct the plan or "
        "configs/iot_device_network_identities.json."
    )
    lines.append(
        f"Preflight artifact: {ARTIFACT_NAME}. Re-run with "
        "--identity-preflight advisory to record the mismatch and continue anyway."
    )
    return " ".join(lines)


def run_identity_preflight(
    plan: dict[str, Any],
    run_root: Path,
    *,
    mode: str | None = None,
    clients: dict[str, Any] | None = None,
    log: EventLog | None = None,
    router_query: Callable[[Any], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify planned device identities and record the result beside the run.

    ``clients`` and ``router_query`` exist so the check can run without router
    access in tests.  In ``enforce`` mode a device whose MAC is not uniquely
    online raises before any capture or plan playback starts.
    """
    resolved_mode = str(mode or plan.get("identity_preflight") or DEFAULT_MODE)
    if resolved_mode not in MODES:
        raise DemoError(
            f"Unknown identity preflight mode {resolved_mode!r}; expected one of "
            f"{', '.join(MODES)}"
        )
    root = Path(run_root)
    root.mkdir(parents=True, exist_ok=True)
    router = plan.get("router") or {}
    artifact: dict[str, Any] = {
        "schema_version": 1,
        "mode": resolved_mode,
        "router_host": router.get("host"),
        "method": "registered_mac_online_client_with_dhcp_ownership_check",
        "generated_at": now_iso(),
        "status": "skipped",
        "detail": None,
        "devices": [],
    }
    if resolved_mode == "off":
        artifact["detail"] = "identity preflight disabled for this run"
        _write_artifact(root, artifact, log)
        return artifact
    try:
        live_clients = (
            clients if clients is not None else (router_query or fetch_router_clients)(router)
        )
    except Exception as exc:
        artifact["status"] = "failed"
        artifact["detail"] = f"router client list unavailable: {exc}"
        _write_artifact(root, artifact, log)
        if resolved_mode == "enforce":
            raise DemoError(
                "Identity preflight could not read the router client list before "
                f"capture: {exc}. Fix router access, or re-run with "
                "--identity-preflight advisory to continue without the check."
            ) from exc
        return artifact
    artifact["devices"] = classify_devices(plan.get("devices") or [], live_clients)
    failing = [row for row in artifact["devices"] if row["status"] in FATAL_STATUSES]
    changed = [row for row in artifact["devices"] if row["status"] == STATUS_IP_CHANGED]
    if failing:
        artifact["status"] = "failed"
    elif changed:
        artifact["status"] = "advisory_issues"
    else:
        artifact["status"] = "passed"
    _write_artifact(root, artifact, log)
    if failing and resolved_mode == "enforce":
        raise DemoError(_failure_message(artifact, failing))
    return artifact
