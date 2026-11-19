"""Conservative, sampled Windows socket ownership matched to router packets."""

from __future__ import annotations

import bisect
import csv
import gzip
import hashlib
import ipaddress
import json
import socket
import struct
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

import psutil

from .packet_parser import parse_packet


CLOCK_MARGIN = 2.0  # Router preflight bounds router/host clock error to two seconds.
MAX_SAMPLE_GAP = 1.0
OWNERSHIP_POLICY = "configured_process_exclusion_v1"


def process_names(values):
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(name, str) or not name.strip() or Path(name).name != name
        for name in values
    ):
        raise ValueError("excluded_process_roots must be a list of executable names")
    return frozenset(name.strip().lower() for name in values)
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
         b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}
BUCKET_FIELDS = ["bucket_start_ms", "bucket_end_ms", "direction", "ip_version", "transport",
                 "packet_count", "byte_count", "min_packet_bytes", "max_packet_bytes", "avg_packet_bytes"]


def _ip(value):
    return str(ipaddress.ip_address(value.split("%", 1)[0]))


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for data in iter(lambda: f.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


class SocketOwnershipRecorder:
    def __init__(self, path, *, target_process="msedge.exe", target_pids=None, debug_port=None, interval=0.25, excluded_roots=()):
        self.path = Path(path)
        self.excluded_roots = process_names(excluded_roots)
        self.target_process = target_process.lower()
        self.target_pids = target_pids
        self.debug_port = debug_port
        self.interval = interval
        self.stop_event = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, name="windows-socket-ownership", daemon=True)

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.thread.start()
        if not self.ready.wait(10) or self.error:
            self.stop()
            raise RuntimeError(f"Socket ownership recorder failed: {self.error or 'startup timeout'}")

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("Socket ownership recorder did not stop")
        if self.error:
            raise RuntimeError(self.error)

    def _run(self):
        try:
            with gzip.open(self.path, "wt", encoding="utf-8") as out:
                owner_cache = {}
                while not self.stop_event.is_set():
                    start = time.time()
                    allowed = self.target_pids() if self.target_pids is not None else None
                    connections = psutil.net_connections(kind="inet")
                    local_addresses = sorted({_ip(a.address) for addresses in psutil.net_if_addrs().values()
                                              for a in addresses if a.family in {socket.AF_INET, socket.AF_INET6}})
                    owners = {}
                    process_roots = {}
                    rows = []
                    proxy_possible = False
                    for c in connections:
                        if not c.laddr or c.status == psutil.CONN_LISTEN:
                            continue
                        protocol = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                        if protocol == "tcp" and not c.raddr:
                            continue
                        if c.pid not in owners:
                            try:
                                proc = psutil.Process(c.pid) if c.pid is not None else None
                                born = proc.create_time() if proc else 0
                                cache_key = (c.pid, born)
                                if cache_key not in owner_cache:
                                    name = proc.name().lower() if proc else ""
                                    root_name = name if name in self.excluded_roots else ""
                                    if self.excluded_roots and proc and not root_name:
                                        try:
                                            for parent in proc.parents():
                                                parent_name = parent.name().lower()
                                                if parent_name in self.excluded_roots:
                                                    root_name = parent_name
                                                    break
                                        except (psutil.Error, OSError):
                                            root_name = None
                                    owner_cache[cache_key] = (name, root_name)
                                name, root_name = owner_cache[cache_key]
                                is_target = name == self.target_process and (allowed is None or c.pid in allowed)
                                if root_name:
                                    process_roots[f"{c.pid}:{born}"] = root_name
                                role = ("target" if is_target else "background" if name == self.target_process
                                        else "unknown" if root_name is None
                                        else "excluded" if root_name
                                        else "background" if name else "unknown")
                                owners[c.pid] = (c.pid or 0, born, name, role)
                            except (psutil.Error, OSError):
                                owners[c.pid] = (c.pid or 0, 0, "", "unknown")
                        owner = owners[c.pid]
                        local = _ip(c.laddr.ip)
                        remote = _ip(c.raddr.ip) if c.raddr else ""
                        port = c.raddr.port if c.raddr else 0
                        if (owner[3] == "target" and remote and ipaddress.ip_address(remote).is_loopback
                                and c.laddr.port != self.debug_port):
                            proxy_possible = True
                        rows.append([protocol, local, c.laddr.port, remote, port, *owner])
                    out.write(json.dumps({"policy": OWNERSHIP_POLICY,
                                          "started": start, "ended": time.time(), "connections": rows,
                                          "process_roots": process_roots,
                                          "excluded_process_roots": sorted(self.excluded_roots),
                                          "local_addresses": local_addresses,
                                          "target_proxy_possible": proxy_possible}, separators=(",", ":")) + "\n")
                    out.flush()
                    self.ready.set()
                    self.stop_event.wait(max(0.0, self.interval - (time.time() - start)))
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.ready.set()


class OwnershipIndex:
    def __init__(self, snapshots):
        self.intervals = defaultdict(list)
        active = {}
        self.samples = 0
        self.excluded_roots = frozenset()
        self.healthy_samples = 0
        self.proxy_possible = False
        self.max_gap = 0.0
        self.local_ips = set()
        previous_end = None
        def close(key, value):
            owner, start, end = value
            if end - start >= 2 * CLOCK_MARGIN:
                self.intervals[key].append((start + CLOCK_MARGIN, end - CLOCK_MARGIN, owner))
        with gzip.open(snapshots, "rt", encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                if row.get("policy") != OWNERSHIP_POLICY:
                    raise ValueError("Unsupported socket attribution policy")
                roots = process_names(row["excluded_process_roots"])
                if self.samples and roots != self.excluded_roots:
                    raise ValueError("Process exclusion changed during capture")
                self.excluded_roots = roots
                start, end = float(row["started"]), float(row["ended"])
                if end < start or (previous_end is not None and start < previous_end):
                    raise ValueError("Socket sample clock moved backwards")
                gap = start - previous_end if previous_end is not None else 0
                self.max_gap = max(self.max_gap, gap, end - start)
                self.healthy_samples += gap <= MAX_SAMPLE_GAP and end - start <= MAX_SAMPLE_GAP
                self.proxy_possible |= bool(row.get("target_proxy_possible"))
                current = defaultdict(set)
                self.local_ips.update(_ip(a) for a in row.get("local_addresses", [])
                                      if a not in {"0.0.0.0", "::"})
                for c in row["connections"]:
                    key = tuple(c[:5]) if c[0] == "tcp" else (c[0], c[1], c[2], "", 0)
                    owner = tuple(c[5:])
                    if len(owner) != 4:
                        raise ValueError("Invalid process ownership record")
                    if owner[3] == "excluded" and owner[2] not in roots:
                        root = row.get("process_roots", {}).get(f"{owner[0]}:{owner[1]}")
                        if root not in roots:
                            owner = (*owner[:3], "unknown")
                    current[key].add(owner)
                    if c[1] not in {"0.0.0.0", "::"}:
                        self.local_ips.add(c[1])
                unique = {key: next(iter(owners)) for key, owners in current.items() if len(owners) == 1}
                for key in list(active):
                    if (gap > MAX_SAMPLE_GAP or end - start > MAX_SAMPLE_GAP
                            or key not in unique or unique[key] != active[key][0]):
                        close(key, active.pop(key))
                for key, owner in unique.items():
                    if key in active:
                        active[key] = (owner, active[key][1], start)
                    else:
                        active[key] = (owner, end, start)
                previous_end = end
                self.samples += 1
        for key, value in active.items():
            close(key, value)
        self.starts = {k: [v[0] for v in values] for k, values in self.intervals.items()}

    def resolve(self, packet, epoch):
        candidates = []
        for direction, local, lp, remote, rp in (
                ("outbound", packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port),
                ("inbound", packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)):
            keys = [(packet.transport, local, lp, remote, rp)]
            if packet.transport == "udp":
                # A wildcard binding applies only to this workstation, never to
                # a remote endpoint that happens to use the same port number.
                if local not in self.local_ips:
                    continue
                wildcard = "::" if ":" in local else "0.0.0.0"
                keys = [("udp", addr, lp, "", 0) for addr in (local, wildcard)]
            for key in keys:
                values = self.intervals.get(key, [])
                i = bisect.bisect_right(self.starts.get(key, []), epoch) - 1
                if i >= 0 and values[i][0] <= epoch <= values[i][1]:
                    candidates.append((values[i][2], direction))
        unique = set(candidates)
        if len(unique) != 1:
            local_src, local_dst = packet.src_ip in self.local_ips, packet.dst_ip in self.local_ips
            direction = "outbound" if local_src and not local_dst else "inbound" if local_dst and not local_src else "unknown"
            return (0, 0, "", "unknown"), direction
        return unique.pop()


def attribution_packet(link, epoch, data):
    # Fragment offsets must never be decoded as transport ports.
    offset = 14 if link == 1 else 16 if link == 113 else None
    if offset is None or len(data) < offset + 20:
        return None
    version = data[offset] >> 4
    if version == 4 and int.from_bytes(data[offset + 6:offset + 8], "big") & 0x3fff:
        return None
    return parse_packet(link, int(epoch * 1000), len(data), data)


def export_attribution(pcaps, snapshots, output, *, window=None, materialize_pcaps=False,
                       view_sources=None, reference_base=None):
    """Replay ownership independently; original packet bytes are never rewritten."""
    from ..screen_time_storage import POLICY, write_view
    pcaps = list(pcaps)
    output = Path(output)
    if not materialize_pcaps and output.exists() and any(output.glob('*.pcap')):
        raise ValueError('Legacy PCAP exports require explicit migration before indexed export')
    output.mkdir(parents=True, exist_ok=True)
    index = OwnershipIndex(snapshots)
    counts = Counter()
    sizes = Counter()
    processes = Counter()
    buckets = {}
    handles = {}
    expected = None
    try:
        with (output / "packet_attribution.csv").open("w", encoding="utf-8", newline="") as table:
            writer = csv.writer(table)
            writer.writerow(["source_file", "packet_index", "timestamp", "original_bytes", "classification",
                             "pid", "process_created", "process_name", "direction"])
            for file_index, path in enumerate(pcaps):
                with Path(path).open("rb") as source:
                    header = source.read(24)
                    if len(header) != 24 or header[:4] not in MAGIC:
                        raise ValueError("Invalid source PCAP header")
                    if expected is None:
                        expected = header
                        if materialize_pcaps:
                            for role in ("retained", "excluded", "unknown"):
                                handles[role] = (output / f"{role}.pcap").open("wb")
                                handles[role].write(header)
                    if header != expected:
                        raise ValueError("Source PCAP headers differ")
                    endian, ns = MAGIC[header[:4]]
                    link = struct.unpack(endian + "I", header[20:24])[0]
                    packet_index = 0
                    while record := source.read(16):
                        packet_index += 1
                        if len(record) != 16:
                            raise ValueError("Incomplete source packet header")
                        sec, frac, cap, orig = struct.unpack(endian + "IIII", record)
                        data = source.read(cap)
                        if len(data) != cap or cap != orig:
                            raise ValueError("Incomplete or snaplen-truncated source packet")
                        epoch = sec + frac / (1e9 if ns else 1e6)
                        if window and not window[0] <= epoch <= window[1]:
                            continue
                        packet = attribution_packet(link, epoch, data)
                        owner, direction = index.resolve(packet, epoch) if packet else ((0, 0, "", "unknown"), "unknown")
                        pid, born, name, role = owner
                        if role not in {"target", "background", "excluded", "unknown"}:
                            raise ValueError("Invalid ownership classification")
                        if materialize_pcaps:
                            handles["excluded" if role == "excluded" else "retained"].write(record + data)
                            if role == "unknown":
                                handles["unknown"].write(record + data)
                        counts[role] += 1
                        sizes[role] += orig
                        processes[name or "unknown"] += 1
                        writer.writerow([file_index, packet_index, f"{epoch:.9f}", orig, role, pid, born, name, direction])
                        if role != "excluded":
                            key = (int(epoch) * 1000, direction,
                                   packet.ip_version if packet else 0,
                                   packet.transport if packet else "unknown")
                            b = buckets.setdefault(key, [0, 0, orig, orig])
                            b[0] += 1; b[1] += orig; b[2] = min(b[2], orig); b[3] = max(b[3], orig)
    finally:
        for handle in handles.values():
            handle.close()
    with (output / "traffic_buckets.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(BUCKET_FIELDS)
        for (ms, direction, version, transport), (n, total, smallest, largest) in sorted(buckets.items()):
            writer.writerow([ms, ms + 1000, direction, version, transport, n, total, smallest, largest, total / n])
    total = sum(counts.values())
    unknown_ratio = counts["unknown"] / total if total else 1.0
    unknown_byte_ratio = sizes["unknown"] / sum(sizes.values()) if sum(sizes.values()) else 1.0
    if not materialize_pcaps:
        sources = view_sources or [{"path": str(Path(p).resolve()), "bytes": Path(p).stat().st_size,
                                    "sha256": sha256(p), "source_type": "run_original"} for p in pcaps]
        write_view(output / "retained.capture.json", sources, window=window,
                   attribution=output / "packet_attribution.csv", retained=True,
                   relative_base=reference_base)
    summary = {"schema_version": 2 if materialize_pcaps else 3, "method": "sampled_socket_ownership", "clock_margin_seconds": CLOCK_MARGIN,
               "policy": OWNERSHIP_POLICY, "excluded_process_roots": sorted(index.excluded_roots),
               "unknown_packets_retained": True, "complete_assistant_removal_verified": False,
               "retained_packets": total - counts["excluded"],
               "retained_bytes": sum(sizes.values()) - sizes["excluded"],
               "packet_counts": dict(counts), "packet_bytes": dict(sizes), "packets_by_process": dict(processes),
               "unknown_packet_ratio": unknown_ratio, "unknown_byte_ratio": unknown_byte_ratio, "socket_samples": index.samples,
               "max_socket_sample_gap_seconds": index.max_gap, "target_proxy_possible": index.proxy_possible,
               "healthy_socket_sample_ratio": index.healthy_samples / index.samples if index.samples else 0,
               "ok": bool(total and index.samples > 1 and index.healthy_samples / index.samples >= 0.95),
               "files": {p.name: sha256(p) for p in sorted(output.iterdir()) if p.is_file() and p.name != "summary.json"}}
    if not materialize_pcaps:
        summary.update(storage_policy=POLICY, retained_capture="retained.capture.json")
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
