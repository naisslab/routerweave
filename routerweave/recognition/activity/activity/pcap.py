"""Read classic PCAP 2.4 and decode IPv4 transport metadata."""

from dataclasses import dataclass
from ipaddress import IPv4Address
import struct


FORMATS = {
    bytes.fromhex("d4c3b2a1"): ("<", 1_000),
    bytes.fromhex("a1b2c3d4"): (">", 1_000),
    bytes.fromhex("4d3cb2a1"): ("<", 1),
    bytes.fromhex("a1b23c4d"): (">", 1),
}
LINK_HEADERS = {1: (14, 12), 113: (16, 14), 276: (20, 0)}
TCP, UDP = 6, 17
MAX_CAPTURED_BYTES = 262144  # Router capture reader's per-frame limit.


def frames(stream, clock=None):
    """Index physical frame offsets; replay selected frames in timestamp order."""
    header = stream.read(24)
    if len(header) != 24 or header[:4] not in FORMATS:
        raise ValueError("Expected a classic PCAP file")
    endian, ns_per_tick = FORMATS[header[:4]]
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", header, 4)
    link = network & 0xffff
    if (major, minor) != (2, 4) or link not in LINK_HEADERS or not snaplen:
        raise ValueError("Expected PCAP 2.4 with Ethernet, SLL or SLL2 framing")
    record = struct.Struct(endian + "4I")
    stream.seek(0, 2)
    end = stream.tell()
    stream.seek(24)
    index = []
    for number, raw in enumerate(iter(lambda: stream.read(record.size), b""), 1):
        if len(raw) != record.size:
            raise ValueError(f"Truncated PCAP record {number}")
        sec, fraction, captured, wire = record.unpack(raw)
        offset = stream.tell()
        if (fraction * ns_per_tick >= 10**9 or captured > min(snaplen, wire, MAX_CAPTURED_BYTES)
                or offset + captured > end):
            raise ValueError(f"Invalid frame {number}")
        if clock is None:
            index.append((sec * 10**9 + fraction * ns_per_tick, number, offset, captured, wire))
        elif number in clock:
            stamp = round(clock[number][0] * (10**9 // ns_per_tick)) * ns_per_tick
            index.append((stamp, number, offset, captured, wire))
        stream.seek(captured, 1)
    if clock is not None and len(index) != len(clock):
        raise ValueError("Packet table references a missing PCAP frame")
    index.sort()
    for stamp, number, offset, captured, wire in index:
        stream.seek(offset)
        frame = stream.read(captured)
        if len(frame) != captured:
            raise ValueError(f"Truncated frame {number}")
        yield number, stamp, wire, link, frame


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


@dataclass
class IpPacket:
    src: str
    dst: str
    protocol: int
    ip_bytes: int
    hop_limit: int
    src_port: int | None = None
    dst_port: int | None = None
    payload_bytes: int | None = None
    flags: int = 0
    sequence: int = 0
    tcp_window: int | None = None
    payload: bytes = b""


def decode(frame, link, wire_bytes):
    offset, type_offset = LINK_HEADERS[link]
    if len(frame) < offset:
        return None
    ether = u16(frame, type_offset)
    while ether in (0x8100, 0x88a8, 0x9100):
        if len(frame) < offset + 4:
            return None
        ether = u16(frame, offset + 2)
        offset += 4
    ip = memoryview(frame)[offset:]
    if ether == 0x0800 and len(ip) >= 20 and ip[0] >> 4 == 4:
        start = (ip[0] & 15) * 4
        size = u16(ip, 2)
        if start < 20 or size < start or len(ip) < start:
            return None
        proto, src, dst = ip[9], ip[12:16], ip[16:20]
        fragmented = bool(u16(ip, 6) & 0x3fff)
    else:
        return None
    if size + offset > wire_bytes:
        raise ValueError("Declared IP length exceeds the original frame length")
    packet = IpPacket(str(IPv4Address(bytes(src))), str(IPv4Address(bytes(dst))), proto, size, ip[8])
    if fragmented or proto not in (TCP, UDP):
        return packet
    ip = ip[:size]
    transport = ip[start:]
    if proto == TCP:
        if len(transport) < 20:
            return packet
        length = (transport[12] >> 4) * 4
        if length < 20 or size < start + length:
            return packet
        packet.sequence = struct.unpack_from("!I", transport, 4)[0]
        packet.flags = transport[13]
        packet.tcp_window = u16(transport, 14)
        data_size = size - start - length
    else:
        length = 8
        if len(transport) < length:
            return packet
        total = u16(transport, 4)
        if not length <= total <= size - start:
            return packet
        data_size = total - length
    packet.src_port, packet.dst_port = struct.unpack_from("!2H", transport)
    packet.payload_bytes = data_size
    packet.payload = bytes(transport[length:length + data_size])
    return packet
