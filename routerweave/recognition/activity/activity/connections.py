"""Track connection instances and unexpired DNS associations for one device."""

from dataclasses import dataclass, field
from itertools import count

from .pcap import TCP, UDP
from .service_protocols import StreamPrefix, parse_dns


@dataclass
class Connection:
    number: int
    opening: int | None
    streams: dict = field(default_factory=dict)
    hosts: dict = field(default_factory=dict)
    media: str | None = None
    pending_fin: dict = field(default_factory=dict)

    def events(self, packet, direction):
        ports = (packet.src_port, packet.dst_port)
        if packet.protocol == UDP:
            if 53 not in ports or len(packet.payload) != packet.payload_bytes:
                return []
            msg = parse_dns(packet.payload)
            return [("dns", msg)] if msg else []
        syn = bool(packet.flags & 2)
        if syn and direction not in self.streams:
            self.streams[direction] = StreamPrefix(packet.sequence, 53 in ports)
        prefix = self.streams.get(direction)
        if prefix is None:
            return []
        if packet.flags & 1 and not packet.flags & 4 and not packet.payload_bytes:
            gap = (packet.sequence - prefix.next) % (1 << 32)
            if 0 < gap < (1 << 31):
                # A FIN may arrive before the preceding HTTP or TLS data.
                self.pending_fin[direction] = packet.sequence
                return []
        events = prefix.feed((packet.sequence + int(syn)) % 2**32, packet.payload)
        if (prefix.closed or len(packet.payload) < packet.payload_bytes
                or packet.flags & 5 or prefix.next == self.pending_fin.get(direction)):
            self.streams[direction] = None
            self.pending_fin.pop(direction, None)
        return events


class DeviceState:
    def __init__(self):
        self.connections = {}
        self.ids = count()
        self.addresses = {}
        self.aliases = {}

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
