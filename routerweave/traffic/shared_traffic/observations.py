"""Associate router packet observations with registered devices and connections."""

from dataclasses import dataclass, field
from ipaddress import ip_address
from itertools import count
import re

from .pcap import TCP, UDP, decode, frames
from .service_protocols import StreamPrefix, parse_dns


@dataclass(frozen=True)
class Device:
    name: str
    ips: tuple[str, ...] = ()
    macs: tuple[str, ...] = ()


@dataclass
class Coverage:
    """Counts for one capture, final after the observations iterator is exhausted."""

    input_frames: int = 0
    decoded_ip_frames: int = 0
    matched_frames: int = 0
    truncated_matched_frames: int = 0
    packet_rows: int = 0
    flow_packet_rows: int = 0


def endpoint_index(devices):
    ips, macs, names = {}, {}, set()
    for device in devices:
        if not device.name or device.name in names or not (device.ips or device.macs):
            raise ValueError("Each device needs a unique name and at least one IP or MAC")
        names.add(device.name)
        for value in device.ips:
            parsed = ip_address(value)
            if parsed.is_unspecified or parsed.is_multicast or str(parsed) == "255.255.255.255":
                raise ValueError("Expected a device unicast IP")
            address = str(parsed)
            if address in ips and ips[address] != device.name:
                raise ValueError("IP assigned to multiple devices")
            ips[address] = device.name
        for value in device.macs:
            if not re.fullmatch(r"(?:[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2})", value, re.I):
                raise ValueError("Expected a six-octet Ethernet MAC")
            compact = value.replace(":", "").replace("-", "")
            if not int(compact, 16) or int(compact[:2], 16) & 1:
                raise ValueError("Expected a unicast Ethernet MAC")
            address = bytes.fromhex(compact).hex(":")
            if address in macs and macs[address] != device.name:
                raise ValueError("MAC assigned to multiple devices")
            macs[address] = device.name
    if not names:
        raise ValueError("At least one device is required")
    return ips, macs


@dataclass
class Connection:
    number: int
    opening: int | None
    streams: dict = field(default_factory=dict)
    hosts: dict = field(default_factory=dict)
    media: str | None = None

    def events(self, packet, direction):
        ports = (packet.src_port, packet.dst_port)
        if packet.protocol == UDP:
            if not ({53, 5353} & set(ports)) or len(packet.payload) != packet.payload_bytes:
                return []
            msg = parse_dns(packet.payload)
            return [("mdns" if 5353 in ports else "dns", msg)] if msg else []
        syn = bool(packet.flags & 2)
        if syn and direction not in self.streams:
            self.streams[direction] = StreamPrefix(packet.sequence, 53 in ports)
        prefix = self.streams.get(direction)
        if prefix is None:
            return []
        events = prefix.feed((packet.sequence + int(syn)) % 2**32, packet.payload)
        if prefix.closed or len(packet.payload) < packet.payload_bytes or packet.flags & 5:
            self.streams[direction] = None
        return events


class DeviceState:
    def __init__(self):
        self.connections = {}
        self.ids = count()
        self.addresses = {}
        self.aliases = {}
        self.last_timestamp = -1

    def connection(self, key, packet):
        conn = self.connections.get(key)
        syn = packet.protocol == TCP and packet.flags & 2 and not packet.flags & 16
        if conn is None or (syn and packet.sequence != conn.opening):
            conn = self.connections[key] = Connection(next(self.ids), packet.sequence if syn else None)
        return conn

    def add_answers(self, msg, now):
        for owner, addr, ttl in msg.addresses:
            self.addresses.setdefault(addr, {})[owner] = now + ttl * 10**9
        for alias, target, ttl in msg.aliases:
            self.aliases.setdefault(target, {})[alias] = now + ttl * 10**9

    @staticmethod
    def live(table, key, now):
        entries = table.get(key)
        if not entries:
            return ()
        for name in [name for name, until in entries.items() if until <= now]:
            del entries[name]
        if not entries:
            del table[key]
        return entries

    def dns_candidates(self, peer, now):
        chains = []
        for owner in self.live(self.addresses, peer, now):
            names = {owner}
            frontier = [owner]
            while frontier:
                target = frontier.pop()
                for alias in self.live(self.aliases, target, now):
                    if alias not in names:
                        names.add(alias)
                        frontier.append(alias)
            chains.append(tuple(sorted(names)))
        return tuple(sorted(chains))

    def record(self, number, now, wire, packet, device, direction):
        if now < self.last_timestamp:
            raise ValueError(f"Device timestamps decrease at frame {number}; use chronological input")
        self.last_timestamp = now
        incoming = direction == "in"
        peer = packet.src if incoming else packet.dst
        local = packet.dst if incoming else packet.src
        ports = (packet.dst_port, packet.src_port) if incoming else (packet.src_port, packet.dst_port)
        conn = None
        events = []
        questions = []
        candidates = ()
        if direction != "local" and packet.src_port is not None:
            key = (packet.protocol, local, ports[0], peer, ports[1])
            conn = self.connection(key, packet)
            for kind, value in conn.events(packet, direction):
                events.append(kind)
                if kind in ("dns", "mdns"):
                    questions.extend(value.questions)
                    if kind == "dns" and incoming and packet.src_port == 53 and value.response:
                        self.add_answers(value, now)
                elif kind == "mime":
                    conn.media = value[0]
                else:
                    conn.hosts.setdefault(kind, set()).update(value)
            candidates = self.dns_candidates(peer, now)
        direct = {kind: tuple(sorted(names)) for kind, names in conn.hosts.items()} if conn else {}
        return {
            "device": device, "frame": number, "time_ns": now, "direction": direction,
            "ip_version": 6 if ":" in packet.src else 4,
            "protocol": packet.protocol, "wire_bytes": wire, "ip_bytes": packet.ip_bytes,
            "payload_bytes": packet.payload_bytes, "flow_id": conn.number if conn else None,
            "hop_limit": packet.hop_limit, "local_port": ports[0], "peer_port": ports[1],
            "tcp_flags": packet.flags if packet.tcp_window is not None else None,
            "tcp_window": packet.tcp_window,
            "events": tuple(events), "questions": tuple(questions), "dns_candidates": candidates,
            "direct_hosts": direct,
            "mime_category": conn.media if conn else None,
            "service_source": "direct" if direct else "dns" if candidates else None,
        }


def observations(stream, devices, *, coverage=None):
    """Yield time-ordered records for registered endpoints in a classic PCAP.

    Registered MAC and IP identities must agree if both match. A LAN exchange
    between two registered devices produces one perspective for each. The
    flow ID is scoped to its device and recording. Missing transport evidence
    has a null flow ID. Direct hosts take precedence over DNS candidate chains.
    """
    ips, macs = endpoint_index(devices)
    mac_only = set(macs.values()) - set(ips.values())
    states = {name: DeviceState() for name in set(ips.values()) | set(macs.values())}
    counts = Coverage() if coverage is None else coverage

    def owner(mac, ip, number):
        by_mac, by_ip = macs.get(mac), ips.get(ip)
        if by_mac and by_ip and by_mac != by_ip:
            raise ValueError(f"Registered MAC and IP identify different devices at frame {number}")
        return by_mac or by_ip

    for number, now, wire, link, frame in frames(stream, require_ethernet=bool(mac_only)):
        counts.input_frames += 1
        try:
            packet = decode(frame, link, wire)
        except ValueError as exc:
            raise ValueError(f"Invalid or unsupported IP packet at frame {number}: {exc}") from exc
        if packet is None:
            continue
        counts.decoded_ip_frames += 1
        src = owner(packet.src_mac, packet.src, number)
        dst = owner(packet.dst_mac, packet.dst, number)
        if not (src or dst):
            continue
        counts.matched_frames += 1
        counts.truncated_matched_frames += len(frame) < wire
        endpoints = [(src, "local" if src == dst else "out")] if src else []
        if dst and dst != src:
            endpoints.append((dst, "in"))
        for device, direction in endpoints:
            row = states[device].record(number, now, wire, packet, device, direction)
            row["captured_bytes"] = len(frame)
            row["captured_payload_bytes"] = len(packet.payload) if packet.payload_bytes is not None else None
            counts.packet_rows += 1
            counts.flow_packet_rows += row["flow_id"] is not None
            yield row


def summarize_flows(records):
    """Aggregate reconstructable connections by device and flow instance."""
    flows = {}
    for row in records:
        if row["flow_id"] is None:
            continue
        key = (row["device"], row["flow_id"])
        if key not in flows:
            flows[key] = {
                "device": key[0], "flow_id": key[1], "protocol": row["protocol"],
                "start_ns": row["time_ns"], "end_ns": row["time_ns"],
                "in_packets": 0, "out_packets": 0, "in_wire_bytes": 0, "out_wire_bytes": 0,
            }
        flow = flows[key]
        flow["end_ns"] = row["time_ns"]
        side = row["direction"]
        flow[side + "_packets"] += 1
        flow[side + "_wire_bytes"] += row["wire_bytes"]
    return flows.values()
