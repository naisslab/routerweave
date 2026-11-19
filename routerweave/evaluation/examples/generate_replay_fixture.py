"""Generate a synthetic Ethernet trace and two example FlowPrint fingerprints."""

import argparse
import ipaddress
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New fixture directory")
    dest = parser.parse_args().output
    dest.mkdir()
    src = ipaddress.ip_address("192.0.2.10").packed
    ethernet = bytes.fromhex("0200000000020200000000010800")
    records = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for j, second in enumerate((0, 0, 5, 5, 15, 15, 29, 29)):
        dst = ipaddress.ip_address(("198.51.100.9", "198.51.100.10")[j % 2]).packed
        udp = struct.pack("!HHHH", 49000, 443, 12, 0) + b"data"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), second, 0, 64, 17, 0, src, dst)
        words = sum(struct.unpack("!10H", ip))
        while words >> 16:
            words = (words & 65535) + (words >> 16)
        ip = ip[:10] + struct.pack("!H", (~words) & 65535) + ip[12:]
        frame = ethernet + ip + udp
        records.extend(struct.pack("<IIII", second, 0, len(frame), len(frame)) + frame)
    (dest / "sample.pcap").write_bytes(records)
    tokens = [b"D203.0.113.5:443", b"D198.51.100.9:443"]
    model = bytearray(b"RWFP0001" + struct.pack("<I", len(tokens)))
    for token in tokens:
        model.extend(struct.pack("<I", len(token)) + token)
    model.extend(struct.pack("<I", 2))
    for token, flows in enumerate((5, 1)):
        model.extend(struct.pack("<IIiiI", 1, token, flows, token, token))
    (dest / "flowprint.bin").write_bytes(model)


if __name__ == "__main__":
    main()
