"""Extract visible DNS records, TLS ClientHello SNI and HTTP/1 Host fields."""

from dataclasses import dataclass
from ipaddress import ip_address
import re
import struct

from .pcap import u16


@dataclass(frozen=True)
class DnsMessage:
    response: bool
    questions: tuple
    addresses: tuple
    aliases: tuple


def dns_name(data, offset):
    labels = []
    visited = set()
    resume = None
    wire_size = 1
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), resume if resume is not None else offset + 1
        if length & 0xc0 == 0xc0:
            target = u16(data, offset) & 0x3fff
            if target >= offset or target in visited:
                break
            visited.add(target)
            if resume is None:
                resume = offset + 2
            offset = target
            continue
        offset += 1
        wire_size += length + 1
        if length > 63 or offset + length > len(data) or wire_size > 255:
            break
        label = data[offset:offset + length]
        if any(c < 32 or c > 126 or c in b".\\" for c in label):
            raise ValueError("Unsupported DNS label")
        labels.append(label.decode("ascii").lower())
        offset += length
    raise ValueError("Invalid DNS name")


def parse_dns(data):
    try:
        _, flags, nq, na, ns, ar = struct.unpack_from("!6H", data)
        if flags & 0x7800 or nq > 32 or na + ns + ar > 512:
            return None
        pos = 12
        questions, addresses, aliases = [], [], []
        for _ in range(nq):
            name, pos = dns_name(data, pos)
            if pos + 4 > len(data):
                return None
            questions.append(name)
            pos += 4
        for index in range(na + ns + ar):
            owner, pos = dns_name(data, pos)
            kind, cls, ttl, size = struct.unpack_from("!HHIH", data, pos)
            pos += 10
            end = pos + size
            if end > len(data):
                return None
            if index < na and cls == 1 and flags & 0x8000 and not flags & 0x020f:
                if (kind, size) in ((1, 4), (28, 16)):
                    addresses.append((owner, str(ip_address(data[pos:end])), ttl))
                elif kind == 5:
                    target, after = dns_name(data, pos)
                    if after != end:
                        return None
                    aliases.append((owner, target, ttl))
            pos = end
        return DnsMessage(bool(flags & 0x8000), tuple(questions), tuple(addresses), tuple(aliases))
    except (ValueError, struct.error):
        return None


class Reader:
    """Read length-prefixed TLS vectors within their enclosing boundary."""

    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def __bool__(self):
        return self.pos < len(self.data)

    def take(self, size):
        end = self.pos + size
        if end > len(self.data):
            raise ValueError("Incomplete TLS field")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def number(self, width):
        return int.from_bytes(self.take(width), "big")

    def vector(self, width):
        return self.take(self.number(width))


def hostname(raw):
    name = bytes(raw).decode("ascii").lower().removesuffix(".")
    if len(name) > 253 or not all(re.fullmatch(r"[a-z0-9_-]{1,63}", label)
                                  for label in name.split(".")):
        raise ValueError("Invalid hostname")
    return name


def client_names(body):
    try:
        hello = Reader(body)
        hello.take(34)
        if len(hello.vector(1)) > 32:
            return ()
        suites = hello.vector(2)
        if not suites or len(suites) % 2 or not hello.vector(1) or not hello:
            return ()
        extensions = Reader(hello.vector(2))
        if hello:
            return ()
        names = []
        while extensions:
            kind = extensions.number(2)
            value = Reader(extensions.vector(2))
            if kind == 0:
                entries = Reader(value.vector(2))
                if value:
                    return ()
                while entries:
                    form = entries.number(1)
                    raw = entries.vector(2)
                    if form == 0:
                        names.append(hostname(raw))
        return tuple(names)
    except ValueError:
        return ()


HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ")
HTTP_PREFIXES = HTTP_METHODS + (b"HTTP/1.0 ", b"HTTP/1.1 ")


def http_evidence(header):
    lines = header.split(b"\r\n")
    request = lines[0].startswith(HTTP_METHODS) and lines[0].endswith((b" HTTP/1.0", b" HTTP/1.1"))
    if not request and not re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2}(?: .*)?", lines[0]):
        return []
    hosts, media = [], set()
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if not sep:
            continue
        if key.lower() == b"host" and request:
            hosts.append(value.strip())
        if key.lower() == b"content-type":
            mime = value.split(b";", 1)[0].strip().lower()
            major = mime.split(b"/", 1)[0]
            if mime == b"application/json":
                media.add("api")
            elif b"/" in mime and major in (b"audio", b"video", b"image", b"text"):
                media.add(major.decode("ascii"))
    events = [("mime", tuple(media))] if len(media) == 1 else []
    if len(hosts) != 1:
        return events
    authority = re.fullmatch(rb"(\[[0-9a-fA-F:._]+\]|[a-zA-Z0-9._-]+)(?::([0-9]{1,5}))?", hosts[0])
    if not authority or (authority[2] and int(authority[2]) > 65535):
        return events
    try:
        host = authority[1]
        if host.startswith(b"["):
            name = str(ip_address(host[1:-1].decode("ascii")))
        else:
            name = hostname(host)
        events.append(("http", (name,)))
    except ValueError:
        pass
    return events


class StreamPrefix:
    """Inspect a contiguous TCP prefix starting at SYN, ignoring retransmissions."""

    MAX_PREFIX = 131072
    MAX_TLS_RECORD = 18432
    MAX_HANDSHAKE = 65536
    MAX_HTTP_HEADER = 32768

    def __init__(self, sequence, dns):
        self.next = (sequence + 1) % 2**32
        self.mode = "dns" if dns else None
        self.total = 0
        self.closed = False
        self.buffer = bytearray()
        self.handshake = bytearray()

    def feed(self, sequence, data):
        if not data or self.closed:
            return []
        delta = (sequence - self.next) % 2**32
        if 0 < delta < 2**31:
            self.closed = True
            return []
        if delta:
            data = data[2**32 - delta:]
        self.next = (self.next + len(data)) % 2**32
        self.total += len(data)
        if self.total > self.MAX_PREFIX:
            self.closed = True
            return []
        self.buffer.extend(data)
        if self.mode is None:
            if not self.buffer:
                return []
            if self.buffer[0] == 22:
                self.mode = "tls"
            elif any(method.startswith(self.buffer) or self.buffer.startswith(method)
                     for method in HTTP_PREFIXES):
                self.mode = "http"
            else:
                self.closed = True
                return []
        if self.mode == "http":
            end = self.buffer.find(b"\r\n\r\n")
            self.closed = end >= 0 or len(self.buffer) > self.MAX_HTTP_HEADER
            if 0 <= end <= self.MAX_HTTP_HEADER:
                return http_evidence(bytes(self.buffer[:end]))
            return []
        if self.mode == "dns":
            events = []
            while len(self.buffer) >= 2:
                length = u16(self.buffer, 0)
                if length < 12:
                    self.closed = True
                    break
                if len(self.buffer) < length + 2:
                    break
                msg = parse_dns(bytes(self.buffer[2:2 + length]))
                del self.buffer[:2 + length]
                if msg:
                    events.append(("dns", msg))
            return events
        return self.read_tls()

    def read_tls(self):
        while len(self.buffer) >= 5:
            size = u16(self.buffer, 3)
            if self.buffer[:2] != b"\x16\x03" or size > self.MAX_TLS_RECORD:
                self.closed = True
                break
            if len(self.buffer) < 5 + size:
                break
            self.handshake.extend(self.buffer[5:5 + size])
            del self.buffer[:5 + size]
            if len(self.handshake) < 4:
                continue
            length = int.from_bytes(self.handshake[1:4], "big")
            if self.handshake[0] != 1 or length > self.MAX_HANDSHAKE:
                self.closed = True
                break
            if len(self.handshake) >= 4 + length:
                self.closed = True
                names = client_names(self.handshake[4:4 + length])
                return [("tls", names)] if names else []
        return []
