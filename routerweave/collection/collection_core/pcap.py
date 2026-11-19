"""Small streaming decoder for router-side classic PCAP captures."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import struct
from typing import Any, Iterable, Iterator

class PcapFormatError(ValueError):
    """The input is not a supported classic PCAP stream."""


def pcap_format(data: bytes, path: str | Path = "<pcap>") -> tuple[str, bool]:
    """Return struct endianness and nanosecond precision for a PCAP header."""

    if len(data) < 24:
        raise PcapFormatError(f"PCAP file too short: {path}")
    layouts = {
        b"\xd4\xc3\xb2\xa1": ("<", False),
        b"\xa1\xb2\xc3\xd4": (">", False),
        b"\x4d\x3c\xb2\xa1": ("<", True),
        b"\xa1\xb2\x3c\x4d": (">", True),
    }
    try:
        return layouts[data[:4]]
    except KeyError as exc:
        raise PcapFormatError(f"Unsupported PCAP magic in {path}") from exc


def pcap_timestamp(endian: str, nanosecond: bool, record_header: bytes) -> float:
    """Decode one classic PCAP record timestamp."""

    if len(record_header) != 16:
        raise PcapFormatError(
            f"PCAP record header must be 16 bytes, got {len(record_header)}"
        )
    seconds, fraction, _captured_length, _original_length = struct.unpack(
        endian + "IIII", record_header
    )
    divisor = 1_000_000_000 if nanosecond else 1_000_000
    if fraction >= divisor:
        raise PcapFormatError("invalid fractional PCAP timestamp")
    return seconds + fraction / divisor


class PcapDecodeError(RuntimeError):
    """The capture is not a supported or complete classic PCAP file."""


def iter_decoded_packets(
    path: str | Path, *, ip_only: bool = False, include_link_identity: bool = False
) -> Iterator[dict[str, Any]]:
    """Yield TCP/UDP metadata, or all IP headers for device-only validation."""

    source = Path(path)
    with source.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise PcapDecodeError(f"PCAP file is too short: {source}")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise PcapDecodeError("PCAPNG is not supported; router capture must emit classic PCAP")
        try:
            endian, nanosecond = pcap_format(header, source)
        except PcapFormatError as exc:
            raise PcapDecodeError(str(exc)) from exc
        _major, _minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
            endian + "HHIIII", header[4:]
        )
        if snaplen <= 0:
            raise PcapDecodeError(f"invalid PCAP snaplen {snaplen}")
        if linktype not in {1, 113, 276}:
            raise PcapDecodeError(
                f"unsupported PCAP linktype {linktype}; expected Ethernet or Linux cooked"
            )

        file_size = source.stat().st_size
        record_index = 0
        while True:
            record_header = handle.read(16)
            if not record_header:
                return
            if len(record_header) != 16:
                raise PcapDecodeError(
                    f"truncated PCAP record header after packet {record_index}"
                )
            _ts_sec, _ts_fraction, included_length, original_length = struct.unpack(
                endian + "IIII", record_header
            )
            if included_length > min(snaplen, original_length):
                raise PcapDecodeError(
                    f"packet {record_index + 1} length {included_length} exceeds capture or wire length"
                )
            if included_length > file_size - handle.tell():
                raise PcapDecodeError("truncated PCAP packet")
            frame = handle.read(included_length)
            if len(frame) != included_length:
                raise PcapDecodeError(
                    f"truncated PCAP packet {record_index + 1}: expected {included_length} bytes"
                )
            record_index += 1
            decoded = decode_frame(frame, linktype=linktype, ip_only=ip_only)
            if decoded is None:
                continue
            if include_link_identity and linktype == 1 and len(frame) >= 14:
                decoded.update(src_mac=frame[6:12].hex(":"), dst_mac=frame[:6].hex(":"))
            epoch = pcap_timestamp(endian, nanosecond, record_header)
            decoded.update(
                {
                    "index": record_index,
                    "ts_epoch": epoch,
                    "ts": datetime.fromtimestamp(epoch, timezone.utc).isoformat(
                        timespec="milliseconds"
                    ),
                    "captured_length": included_length,
                    "length": original_length,
                }
            )
            yield decoded


def decode_frame(
    frame: bytes, *, linktype: int, ip_only: bool = False
) -> dict[str, Any] | None:
    if linktype == 1:
        if len(frame) < 14:
            return None
        ethertype = int.from_bytes(frame[12:14], "big")
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(frame) < offset + 4:
                return None
            ethertype = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        payload = frame[offset:]
        # go-ios can emit BSD loopback frames under an Ethernet link type for VPN traffic.
        if ethertype not in {0x0800, 0x86DD} and len(frame) >= 5:
            address_family = int.from_bytes(frame[:4], "little")
            ip_version = frame[4] >> 4
            if address_family == 2 and ip_version == 4:
                ethertype = 0x0800
                payload = frame[4:]
            elif address_family in {10, 24, 28, 30} and ip_version == 6:
                ethertype = 0x86DD
                payload = frame[4:]
    elif linktype == 113:
        if len(frame) < 16:
            return None
        ethertype = int.from_bytes(frame[14:16], "big")
        payload = frame[16:]
    else:  # Linux cooked v2, linktype 276
        if len(frame) < 20:
            return None
        ethertype = int.from_bytes(frame[0:2], "big")
        payload = frame[20:]

    if ethertype == 0x0800:
        return _decode_ipv4(payload, ip_only=ip_only)
    if ethertype == 0x86DD:
        return _decode_ipv6(payload, ip_only=ip_only)
    return None


def packet_local_remote(
    packet: dict[str, Any], phone_ip: str
) -> tuple[int, str, int, str] | None:
    if packet.get("src_ip") == phone_ip:
        return int(packet["src_port"]), str(packet["dst_ip"]), int(packet["dst_port"]), "out"
    if packet.get("dst_ip") == phone_ip:
        return int(packet["dst_port"]), str(packet["src_ip"]), int(packet["src_port"]), "in"
    return None


def verified_network_window_id(
    packet_epoch: float, network_windows: Iterable[dict[str, Any]]
) -> str | None:
    for window in network_windows:
        if window.get("task_success") is not True:
            continue
        actual = window.get("actual")
        if not isinstance(actual, dict):
            continue
        try:
            start = float(actual["start_epoch"])
            end = float(actual["end_epoch"])
        except (KeyError, TypeError, ValueError):
            continue
        if start <= packet_epoch <= end:
            return str(window.get("id"))
    return None


def _decode_ipv4(packet: bytes, *, ip_only: bool = False) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or len(packet) < header_length:
        return None
    if ip_only:
        return {
            "src_ip": str(ipaddress.IPv4Address(packet[12:16])),
            "dst_ip": str(ipaddress.IPv4Address(packet[16:20])),
            "ip_protocol": packet[9],
        }
    fragment = int.from_bytes(packet[6:8], "big")
    if fragment & 0x1FFF:
        return None
    return _decode_transport(
        packet[header_length:],
        src=str(ipaddress.IPv4Address(packet[12:16])),
        dst=str(ipaddress.IPv4Address(packet[16:20])),
        protocol=packet[9],
    )


def _decode_ipv6(packet: bytes, *, ip_only: bool = False) -> dict[str, Any] | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    if ip_only:
        return {
            "src_ip": str(ipaddress.IPv6Address(packet[8:24])),
            "dst_ip": str(ipaddress.IPv6Address(packet[24:40])),
            "ip_protocol": packet[6],
        }
    protocol = packet[6]
    offset = 40
    # Follow common extension headers until TCP/UDP. Non-initial fragments cannot
    # be attributed because they do not contain transport ports.
    while protocol in {0, 43, 44, 51, 60}:
        if protocol == 44:
            if len(packet) < offset + 8:
                return None
            fragment = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            if fragment & 0xFFF8:
                return None
            protocol = packet[offset]
            offset += 8
            continue
        if len(packet) < offset + 2:
            return None
        next_protocol = packet[offset]
        if protocol == 51:
            extension_length = (packet[offset + 1] + 2) * 4
        else:
            extension_length = (packet[offset + 1] + 1) * 8
        if extension_length <= 0 or len(packet) < offset + extension_length:
            return None
        protocol = next_protocol
        offset += extension_length
    return _decode_transport(
        packet[offset:],
        src=str(ipaddress.IPv6Address(packet[8:24])),
        dst=str(ipaddress.IPv6Address(packet[24:40])),
        protocol=protocol,
    )


def _decode_transport(
    payload: bytes,
    *,
    src: str,
    dst: str,
    protocol: int,
) -> dict[str, Any] | None:
    if protocol == 6:
        name = "tcp"
    elif protocol == 17:
        name = "udp"
    else:
        return None
    if len(payload) < 4:
        return None
    return {
        "proto": name,
        "src_ip": src,
        "src_port": int.from_bytes(payload[0:2], "big"),
        "dst_ip": dst,
        "dst_port": int.from_bytes(payload[2:4], "big"),
    }
