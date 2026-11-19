"""Read classic PCAP 2.4 and decode router-side IP packet metadata."""

from dataclasses import dataclass
from ipaddress import ip_address
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


def frames(stream, *, require_ethernet=False):
    """Read files in stable timestamp order, preserving physical frame numbers.

    For seekable input the index holds offsets, never packet bodies. Pipes
    retain arrival order and must be chronological for each observed device.
    """
    header = stream.read(24)
    if len(header) != 24 or header[:4] not in FORMATS:
        raise ValueError("Expected a classic PCAP header")
    endian, ns_per_tick = FORMATS[header[:4]]
    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHIIII", header, 4)
    link = network & 0xffff
    if (major, minor) != (2, 4) or link not in LINK_HEADERS or not snaplen:
        raise ValueError("Expected PCAP 2.4 with Ethernet, SLL or SLL2 framing")
    if require_ethernet and link != 1:
        raise ValueError("MAC-only device attribution requires Ethernet framing")
    record = struct.Struct(endian + "4I")

    def record_info(raw, number):
        if len(raw) != record.size:
            raise ValueError(f"Truncated PCAP record header at frame {number}")
        sec, fraction, cap, wire = record.unpack(raw)
        if fraction * ns_per_tick >= 10**9 or cap > min(snaplen, wire):
            raise ValueError(f"Invalid timestamp or capture length at frame {number}")
        if cap > MAX_CAPTURED_BYTES:
            raise ValueError(f"Frame {number} exceeds the {MAX_CAPTURED_BYTES}-byte capture limit")
        return sec * 10**9 + fraction * ns_per_tick, wire, cap

    def read_body(number, cap):
        body = stream.read(cap)
        if len(body) != cap:
            raise ValueError(f"Truncated PCAP frame {number}")
        return body

    if not stream.seekable():
        for number, raw in enumerate(iter(lambda: stream.read(record.size), b""), 1):
            stamp, wire, cap = record_info(raw, number)
            yield number, stamp, wire, link, read_body(number, cap)
        return

    start = stream.tell()
    end = stream.seek(0, 2)
    stream.seek(start)
    index = []
    for number, raw in enumerate(iter(lambda: stream.read(record.size), b""), 1):
        stamp, wire, cap = record_info(raw, number)
        offset = stream.tell()
        if offset + cap > end:
            raise ValueError(f"Truncated PCAP frame {number}")
        index.append((stamp, number, offset, cap, wire))
        stream.seek(cap, 1)
    index.sort()
    for stamp, number, offset, cap, wire in index:
        stream.seek(offset)
        yield number, stamp, wire, link, read_body(number, cap)


def u16(data, offset):
    return struct.unpack_from("!H", data, offset)[0]


@dataclass
class IpPacket:
    src: str
    dst: str
    src_mac: str | None
    dst_mac: str | None
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


def decode(frame, link, wire_bytes=None):
    offset, type_offset = LINK_HEADERS[link]
    if len(frame) < offset:
        return None
    ether = u16(frame, type_offset)
    src_mac = frame[6:12].hex(":") if link == 1 else None
    dst_mac = frame[:6].hex(":") if link == 1 else None
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
    elif ether == 0x86dd and len(ip) >= 40 and ip[0] >> 4 == 6:
        start, size = 40, 40 + u16(ip, 4)
        proto, src, dst = ip[6], ip[8:24], ip[24:40]
        if size == 40 and proto == 0:
            raise ValueError("IPv6 jumbogram length requires a Jumbo Payload option")
        fragmented = False
    else:
        return None
    if wire_bytes is not None and size + offset > wire_bytes:
        raise ValueError("Declared IP length exceeds the original frame length")
    packet = IpPacket(str(ip_address(bytes(src))), str(ip_address(bytes(dst))),
                      src_mac, dst_mac, proto, size, ip[8] if ether == 0x0800 else ip[7])
    ip = ip[:size]
    while ether == 0x86dd and proto in (0, 43, 44, 51, 60):
        if start + 2 > len(ip):
            return packet
        if proto == 44:
            if start + 8 > len(ip):
                return packet
            fragmented = bool(u16(ip, start + 2) & 0xfff9)
            length = 8
        elif proto == 51:
            length = (ip[start + 1] + 2) * 4
        else:
            length = (ip[start + 1] + 1) * 8
        if start + length > len(ip):
            return packet
        proto = packet.protocol = ip[start]
        start += length
        if fragmented:
            return packet
    transport = ip[start:]
    if fragmented or proto not in (TCP, UDP):
        return packet
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
