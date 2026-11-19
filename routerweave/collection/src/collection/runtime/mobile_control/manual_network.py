import os
"""Match registered device MACs to current router clients for manual collection."""
from datetime import datetime, timezone
import copy
import ipaddress
import json
import re
from pathlib import Path

from collection.runtime.registry.tasks import DEFAULT_CONFIG_ROOT
from .capture.router import _router_ssh

PHONE_SOURCES = {'participant': 'Participant phone', 'lab': 'Lab phone (auto-assigned)'}


def phone_source(device):
    """Mobile phone source; tablets keep their own explicitly registered identity."""
    if device.get('collection_task_id') not in ('android-manual-screen-time', 'ios-manual-screen-time'):
        return None
    network = device.get('network', {})
    description = (device.get('id', '') + ' ' + device.get('name', '')).lower()
    if network.get('role') == 'tablet' or 'ipad' in description or '平板' in description:
        return None
    return network.get('phone_source') or ('participant' if network.get('method') == 'mac' else 'lab')


def phone_network_for_source(device, source):
    """Switch identity methods without reusing the other source's active binding."""
    if source not in PHONE_SOURCES or phone_source(device) is None:
        raise ValueError('Choose a participant phone or an automatically assigned lab phone.')
    platform = device['collection_task_id'].split('-')[0]
    current = device.get('network', {})
    default_lab = dict(method='android', serial=os.environ.get("ANDROID_SERIAL", "")) if platform == 'android' else \
                  dict(method='ios', wda_url='http://127.0.0.1:8100')
    lab = current if current.get('method') == platform else current.get('lab_network', default_lab)
    if lab.get('method') != platform:
        lab = default_lab
    # Keep custom lab discovery settings, never retain a previous participant's MAC/IP.
    lab = {k: copy.deepcopy(v) for k,v in lab.items() if k in ('method', 'serial', 'wda_url')}
    if source == 'lab':
        return dict(lab, phone_source='lab')
    return dict(method='mac', mac='', phone_source='participant', lab_network=lab)


def read_router_clients(router):
    """Read the same live client inventory used by capture identity resolution."""
    response = _router_ssh(router.user, router.host, "ubus call gl-clients list",
                           identity_file=router.identity_file, timeout=8)
    if response.returncode:
        raise ValueError("Cannot read the online device list. Check the router connection.")
    try:
        clients = json.loads(response.stdout)["clients"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Invalid device list from the router. Refresh and try again.") from exc
    if not isinstance(clients, dict) or any(not isinstance(row, dict) for row in clients.values()):
        raise ValueError("Invalid device list from the router. Refresh and try again.")
    return clients


def registration_candidates(clients, *, baseline_macs=(), excluded_macs=()):
    """Offer only unique online endpoints; a hostname never proves ownership."""
    baseline = {mac.lower() for mac in baseline_macs}
    excluded = {mac.lower() for mac in excluded_macs}
    choices = {}
    for row in clients.values():
        mac = str(row.get('mac', '')).lower()
        if row.get('online') is not True or mac in excluded or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
            continue
        try:
            identity = match_router_client(dict(mac=mac, scope='direct_device', identity_key='registration'), clients)
        except ValueError:
            continue
        choices[mac] = dict(identity, new_connection=mac not in baseline)
    return sorted(choices.values(), key=lambda row: (not row['new_connection'], row['router_name'], row['mac']))


def registered_network(participant_id, device_id, mac, clients):
    participant_id = participant_id.strip()
    if not participant_id or len(participant_id) > 64:
        raise ValueError('Enter a participant or device identifier of up to 64 characters.')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac.lower()):
        raise ValueError('Invalid device MAC address. Select the device again.')
    identity = match_router_client(dict(mac=mac.lower(), scope='direct_device', identity_key=device_id), clients)
    return dict(method='mac', mac=identity['mac'], participant_id=participant_id,
                registration=identity)


def configured_identity(task, identities):
    metadata = task.get("metadata", {})
    device_id = metadata.get("dataset_device_id") or metadata.get("device_id")
    catalog_device = metadata.get("device_catalog")
    if catalog_device:
        reviewed = catalog_device.get("network_identity", {})
        direct_keys = [key for key in reviewed.get("identity_keys", [])
                       if key in identities and identities[key].get("scope") == "direct_device"]
        if not reviewed.get("mac") or not direct_keys:
            raise ValueError(f"Confirm the device MAC for {task['title']}. A proxy address cannot identify the device.")
        if any(str(identities[key].get("mac", "")).lower() != reviewed["mac"] for key in direct_keys):
            raise ValueError("The device identity has changed. Verify it before using the MAC address.")
        return {**identities[direct_keys[0]], "identity_key": direct_keys[0]}
    matches = []
    for key, value in identities.items():
        platform, category, device = key.split("/", 2)
        explicit = task["id"] in value.get("collection_task_ids", [])
        same_device = device_id in {device, *value.get("device_ids", [])}
        same_scope = platform == task["platform"] or value["scope"] == "direct_device"
        if explicit or (same_device and category == task["category"] and same_scope):
            matches.append({**value, "identity_key": key})
    unique = {(row["mac"].lower(), row["scope"]) for row in matches}
    if not matches:
        raise ValueError(f"Verify the MAC address for {task['title']} before resolving its IP address.")
    if len(unique) != 1:
        raise ValueError("Multiple network identities match this device. Verify its identity before selecting an IP address.")
    return matches[0]


def match_router_client(identity, clients):
    mac = identity["mac"].lower()
    active = [row for row in clients.values() if row.get("mac", "").lower() == mac and row.get("online") is True]
    if len(active) != 1:
        raise ValueError(f"No unique online address for {mac}. Connect the device to the collection Wi-Fi and retry.")
    row = active[0]
    ip = ipaddress.ip_address(row.get("ip", ""))
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        raise ValueError("The router returned no usable IPv4 address for the device.")
    if any(other.get("online") is True and other.get("ip") == str(ip) and
           other.get("mac", "").lower() != mac for other in clients.values()):
        raise ValueError("The router reported an IP conflict. Select a unique address.")
    return dict(identity_key=identity["identity_key"], mac=mac, ip=str(ip), scope=identity["scope"],
                proxy_device=identity.get("proxy_device"), router_name=row.get("name", ""),
                wifi_band=row.get("iface", ""), method="registered_mac_to_online_router_client",
                checked_at_utc=datetime.now(timezone.utc).isoformat())


def resolve_task_identity(task, router, *, identities_path=DEFAULT_CONFIG_ROOT/"iot_device_network_identities.json"):
    variable = task.get("metadata", {}).get("device_mac_env")
    if variable:
        mac = os.environ.get(variable, "").strip().lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise ValueError(f"Set {variable} to the device Wi-Fi MAC address.")
        identity = dict(mac=mac, scope="direct_device", identity_key=task["id"])
    else:
        identities = json.loads(Path(identities_path).read_text(encoding="utf-8"))
        identity = configured_identity(task, identities)
    return match_router_client(identity, read_router_clients(router))
