from pathlib import Path
from collection_core.pcap import (PcapDecodeError, PcapFormatError, pcap_format, iter_decoded_packets,
                                  decode_frame, packet_local_remote, verified_network_window_id)


def valid_pcap_header(path: str | Path, *, allow_pcapng: bool = False) -> bool:
    source = Path(path)
    if not source.is_file() or source.stat().st_size < 24:
        return False
    with source.open("rb") as handle:
        header = handle.read(24)
    if allow_pcapng and header[:4] == b"\x0a\x0d\x0d\x0a":
        return True
    try:
        pcap_format(header, source)
    except PcapFormatError:
        return False
    return True
