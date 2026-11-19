from __future__ import annotations

import ipaddress
import struct

from .models import ParsedPacket


DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_IEEE802_11_RADIO = 127
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


def parse_packet(*args) -> ParsedPacket | None:
    if len(args) == 1:
        return _parse_link_packet(DLT_EN10MB, 0, len(args[0]), args[0])
    if len(args) == 4:
        link_type, timestamp_ms, captured_len, packet = args
        return _parse_link_packet(link_type, timestamp_ms, captured_len, packet)
    raise TypeError("parse_packet expects either packet_bytes or link_type, timestamp_ms, captured_len, packet_bytes")


def _parse_link_packet(link_type: int, timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if link_type == DLT_EN10MB:
        return _parse_ethernet(timestamp_ms, captured_len, packet)
    if link_type == DLT_LINUX_SLL:
        return _parse_linux_cooked(timestamp_ms, captured_len, packet)
    if link_type == DLT_IEEE802_11_RADIO:
        return _parse_radiotap(timestamp_ms, captured_len, packet)
    return None


def _parse_ethernet(timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if len(packet) < 14:
        return None
    ethertype = int.from_bytes(packet[12:14], "big")
    return _parse_ip_packet(timestamp_ms, captured_len, packet[14:], ethertype)


def _parse_linux_cooked(timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if len(packet) < 16:
        return None
    packet_type = int.from_bytes(packet[0:2], "big")
    ethertype = int.from_bytes(packet[14:16], "big")
    parsed = _parse_ip_packet(timestamp_ms, captured_len, packet[16:], ethertype)
    if parsed is None:
        return None
    return ParsedPacket(
        ip_version=parsed.ip_version,
        transport=parsed.transport,
        src_ip=parsed.src_ip,
        dst_ip=parsed.dst_ip,
        src_port=parsed.src_port,
        dst_port=parsed.dst_port,
        timestamp_ms=timestamp_ms,
        length=captured_len,
        direction_hint="outbound" if packet_type == 4 else "inbound",
    )


def _parse_radiotap(timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if len(packet) < 8:
        return None
    radiotap_len = int.from_bytes(packet[2:4], "little")
    frame = packet[radiotap_len:]
    if len(frame) < 24:
        return None
    frame_control = int.from_bytes(frame[0:2], "little")
    frame_type = (frame_control >> 2) & 0x3
    subtype = (frame_control >> 4) & 0xF
    to_ds = (frame_control >> 8) & 0x1
    from_ds = (frame_control >> 9) & 0x1
    if frame_type != 2:
        return None
    header_len = 24
    if subtype & 0x8:
        header_len += 2
    if to_ds and from_ds:
        header_len += 6
    llc = frame[header_len:]
    if len(llc) < 8 or llc[0:3] != b"\xaa\xaa\x03":
        return None
    ethertype = int.from_bytes(llc[6:8], "big")
    return _parse_ip_packet(timestamp_ms, captured_len, llc[8:], ethertype)


def _parse_ip_packet(timestamp_ms: int, captured_len: int, packet: bytes, ethertype: int) -> ParsedPacket | None:
    if ethertype == ETHERTYPE_IPV4:
        return _parse_ipv4(timestamp_ms, captured_len, packet)
    if ethertype == ETHERTYPE_IPV6:
        return _parse_ipv6(timestamp_ms, captured_len, packet)
    return None


def _parse_ipv4(timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None
    protocol = packet[9]
    src_ip = str(ipaddress.IPv4Address(packet[12:16]))
    dst_ip = str(ipaddress.IPv4Address(packet[16:20]))
    return _with_transport(timestamp_ms, captured_len, packet[ihl:], "ipv4", src_ip, dst_ip, protocol)


def _parse_ipv6(timestamp_ms: int, captured_len: int, packet: bytes) -> ParsedPacket | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    next_header = packet[6]
    src_ip = str(ipaddress.IPv6Address(packet[8:24]))
    dst_ip = str(ipaddress.IPv6Address(packet[24:40]))
    return _with_transport(timestamp_ms, captured_len, packet[40:], "ipv6", src_ip, dst_ip, next_header)


def _with_transport(timestamp_ms: int, captured_len: int, payload: bytes, ip_version: str, src_ip: str, dst_ip: str, protocol: int) -> ParsedPacket | None:
    if protocol == 6 and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        return ParsedPacket(ip_version, "tcp", src_ip, dst_ip, src_port, dst_port, timestamp_ms, captured_len)
    if protocol == 17 and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
        return ParsedPacket(ip_version, "udp", src_ip, dst_ip, src_port, dst_port, timestamp_ms, captured_len)
    return None
