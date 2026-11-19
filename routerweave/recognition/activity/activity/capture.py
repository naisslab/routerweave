"""Read one device's IPv4 traffic and associate service evidence in capture order."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import csv
from ipaddress import IPv4Address
from itertools import groupby
import math

from .connections import DeviceState
from .pcap import decode, frames
from .services import associate, combined_bits
from .windows import WINDOW, window_features


@dataclass(slots=True)
class Packet:
    time: float
    incoming: int
    size: int
    protocol: int
    ttl: int
    flow: int
    payload: int
    flags: int
    advertised: int
    bits: int
    quality: tuple
    events: tuple


def read_clock(path):
    """Bind labelled packet-table timestamps to physical PCAP frames."""
    clock = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                stamp = float(row["time"])
            except ValueError:
                point = datetime.fromisoformat(row["time"])
                stamp = (point if point.tzinfo else point.replace(tzinfo=timezone.utc)).timestamp()
            number = int(row["stream_id"])
            if number < 1 or number in clock or not math.isfinite(stamp):
                raise ValueError("Invalid or repeated frame in packet table")
            clock[number] = (stamp, int(row["length"]), row["direction"], int(row["ip_protocol"]))
    if not clock:
        raise ValueError("Packet table is empty")
    return clock


def packet_rows(stream, address, clock=None):
    address = str(IPv4Address(address))
    state = DeviceState()
    for stamp, simultaneous in groupby(frames(stream, clock), key=lambda item: item[1]):
        pending = []
        for number, _, wire, link, frame in simultaneous:
            packet = decode(frame, link, wire)
            if packet is None or address not in (packet.src, packet.dst):
                if clock is not None:
                    raise ValueError(f"Selected frame {number} does not match the requested device")
                continue
            incoming = packet.dst == address
            direction = "in" if incoming else "out"
            if clock is not None and clock[number][1:] != (wire, direction, packet.protocol):
                raise ValueError(f"Frame {number} disagrees with the packet table")
            peer = packet.src if incoming else packet.dst
            conn, events = None, []
            if packet.src_port is not None:
                local, remote = ((packet.dst_port, packet.src_port) if incoming else
                                 (packet.src_port, packet.dst_port))
                conn = state.connection((packet.protocol, address, local, peer, remote), packet)
                for kind, value in conn.events(packet, direction):
                    if kind == "dns":
                        events.append((0, combined_bits(value.questions)))
                        if incoming and packet.src_port == 53 and value.response:
                            state.add_answers(value, stamp)
                    elif kind in ("http", "tls"):
                        conn.hosts.setdefault(kind, set()).update(value)
                        events.append((1, combined_bits(value)))
                    elif kind == "mime":
                        conn.media = value[0]
            pending.append((packet, incoming, peer, conn, tuple(events)))
        # The reference association includes all evidence events at the packet timestamp.
        seconds, fraction = divmod(stamp, 10**9)
        time = seconds + fraction / 10**9
        for packet, incoming, peer, conn, events in pending:
            if conn is None:
                flow, bits = -1, 0
                quality = (False, False, False, False, True, False, False, False)
            else:
                flow = conn.number
                bits, quality = associate(conn, state.dns_candidates(peer, stamp))
            yield Packet(time, int(incoming), packet.ip_bytes, packet.protocol, packet.hop_limit,
                         flow, packet.payload_bytes or 0, packet.flags,
                         -1 if packet.tcp_window is None else packet.tcp_window,
                         bits, quality, events)


def observations(capture, address, ends, packet_table=None):
    """Endpoints identify complete observation intervals on the recording clock."""
    history = deque()
    previous = -math.inf
    with capture.open("rb") as stream:
        clock = read_clock(packet_table) if packet_table is not None else None
        rows = iter(packet_rows(stream, address, clock))
        packet = next(rows, None)
        if packet is None:
            raise ValueError("No packets for the requested IPv4 address")
        for end in ends:
            if not math.isfinite(end) or end <= previous:
                raise ValueError("Window endpoints must be finite and increasing")
            start = end - WINDOW
            while history and history[0].time < start:
                history.popleft()
            while packet is not None and packet.time < end:
                if packet.time >= start:
                    history.append(packet)
                packet = next(rows, None)
            yield window_features(history, start)
            previous = end
