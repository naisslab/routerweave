#include "native_baselines.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace rwbase {
namespace {
uint16_t u16(const uint8_t *p) {
  return uint16_t((unsigned(p[0]) << 8) | p[1]);
}
uint32_t u32(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | p[3];
}
uint32_t file32(const uint8_t *p, bool little) {
  return little ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
                      (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
                : u32(p);
}
struct Capture {
  const Bytes &bytes;
  bool little;
  double scale;
  explicit Capture(const Bytes &b) : bytes(b) {
    if (b.size() < 24)
      throw std::runtime_error("short PCAP");
    uint32_t magic = u32(b.data());
    little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    if (!little && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d)
      throw std::runtime_error("classic PCAP required");
    scale = magic == 0x4d3cb2a1 || magic == 0xa1b23c4d ? 1e9 : 1e6;
    if (file32(b.data() + 20, little) != 1)
      throw std::runtime_error("Ethernet PCAP required");
  }
  template <class F> void frames(F callback) const {
    int frame = 0;
    for (size_t at = 24; at < bytes.size();) {
      if (bytes.size() - at < 16)
        throw std::runtime_error("short packet header");
      const uint8_t *h = bytes.data() + at;
      double timestamp =
          double(file32(h, little)) + double(file32(h + 4, little)) / scale;
      uint32_t cap = file32(h + 8, little), wire = file32(h + 12, little);
      at += 16;
      if (size_t(cap) > bytes.size() - at)
        throw std::runtime_error("short packet");
      if (!callback(at, size_t(cap), wire, timestamp, ++frame))
        return;
      at += cap;
    }
  }
};
using Key = std::tuple<int, uint32_t, uint32_t, int, int>;
Key key(const Packet &p) {
  return {p.protocol, p.src, p.dst, p.sport, p.dport};
}
Key reverse(const Key &k) {
  return {std::get<0>(k), std::get<2>(k), std::get<1>(k), std::get<4>(k),
          std::get<3>(k)};
}
struct Segment {
  uint32_t sequence;
  Bytes data;
  double timestamp;
  bool operator<(const Segment &b) const {
    return std::tie(sequence, data, timestamp) <
           std::tie(b.sequence, b.data, b.timestamp);
  }
};
struct Certificate {
  bool present = false;
  std::string serial;
  double available = 0;
};
// DER's definite-length TLV envelope. Reject malformed encodings instead of
// guessing a serial from arbitrary payload bytes.
struct TLV {
  uint8_t tag = 0;
  size_t start = 0, end = 0, next = 0;
};
bool tlv(const Bytes &data, size_t at, size_t limit, TLV &out) {
  if (at >= limit || limit > data.size())
    return false;
  out.tag = data[at++];
  if ((out.tag & 31) == 31 || at >= limit)
    return false;
  uint8_t byte = data[at++];
  size_t n = 0;
  if (!(byte & 128))
    n = byte;
  else {
    size_t count = byte & 127;
    if (!count || count > sizeof(size_t) || count > limit - at || data[at] == 0)
      return false;
    for (size_t i = 0; i < count; ++i) {
      if (n > (std::numeric_limits<size_t>::max() >> 8))
        return false;
      n = (n << 8) | data[at++];
    }
    if (n < 128)
      return false;
  }
  if (n > limit - at)
    return false;
  out.start = at;
  out.end = at + n;
  out.next = at + n;
  return true;
}
bool integer_valid(const Bytes &data, const TLV &value) {
  if (value.tag != 2 || value.start == value.end)
    return false;
  if (value.end - value.start > 1) {
    if (data[value.start] == 0 && !(data[value.start + 1] & 128))
      return false;
    if (data[value.start] == 255 && (data[value.start + 1] & 128))
      return false;
  }
  return true;
}
bool oid_valid(const Bytes &data, const TLV &oid) {
  if (oid.tag != 6 || oid.start == oid.end)
    return false;
  bool initial = true;
  for (size_t i = oid.start; i < oid.end; ++i) {
    if (initial && data[i] == 128)
      return false;
    initial = !(data[i] & 128);
  }
  return initial;
}
bool der_tree(const Bytes &data, size_t begin, size_t end, int depth = 0) {
  if (depth > 32)
    return false;
  while (begin < end) {
    TLV item;
    if (!tlv(data, begin, end, item))
      return false;
    if ((item.tag & 32) && !der_tree(data, item.start, item.end, depth + 1))
      return false;
    if (item.tag == 2 && !integer_valid(data, item))
      return false;
    if (item.tag == 6 && !oid_valid(data, item))
      return false;
    if (item.tag == 5 && item.start != item.end)
      return false;
    if (item.tag == 3 && (item.start == item.end || data[item.start] > 7 ||
                          (item.end - item.start == 1 && data[item.start])))
      return false;
    begin = item.next;
  }
  return begin == end;
}
bool algorithm(const Bytes &data, const TLV &seq) {
  if (seq.tag != 0x30)
    return false;
  TLV oid;
  if (!tlv(data, seq.start, seq.end, oid) || !oid_valid(data, oid))
    return false;
  if (oid.next == seq.end)
    return true;
  TLV parameter;
  return tlv(data, oid.next, seq.end, parameter) && parameter.next == seq.end;
}
std::string hex_integer(const Bytes &data, const TLV &integer) {
  Bytes number(data.begin() + integer.start, data.begin() + integer.end);
  bool negative = number.front() & 128;
  if (negative) {
    for (auto &b : number)
      b = uint8_t(~b);
    for (size_t i = number.size(); i > 0; --i) {
      if (++number[i - 1])
        break;
    }
  }
  static const char *digits = "0123456789abcdef";
  std::string result;
  for (auto b : number) {
    result.push_back(digits[b >> 4]);
    result.push_back(digits[b & 15]);
  }
  size_t first = result.find_first_not_of('0');
  result = first == std::string::npos ? "0" : result.substr(first);
  return negative ? "-" + result : result;
}
bool serial_number(const Bytes &data, std::string &serial) {
  TLV cert, tbs, outer_algorithm, signature;
  if (!tlv(data, 0, data.size(), cert) || cert.tag != 0x30 ||
      cert.next != data.size())
    return false;
  if (!tlv(data, cert.start, cert.end, tbs) || tbs.tag != 0x30)
    return false;
  if (!tlv(data, tbs.next, cert.end, outer_algorithm) ||
      !algorithm(data, outer_algorithm))
    return false;
  if (!tlv(data, outer_algorithm.next, cert.end, signature) ||
      signature.tag != 3 || signature.next != cert.end)
    return false;
  if (!der_tree(data, cert.start, cert.end))
    return false;
  size_t at = tbs.start;
  TLV item;
  if (!tlv(data, at, tbs.end, item))
    return false;
  int version = 0;
  if (item.tag == 0xa0) {
    TLV value;
    if (!tlv(data, item.start, item.end, value) || value.tag != 2 ||
        value.next != item.end || value.end - value.start != 1 ||
        data[value.start] > 2)
      return false;
    version = data[value.start];
    at = item.next;
    if (!tlv(data, at, tbs.end, item))
      return false;
  }
  if (!integer_valid(data, item))
    return false;
  serial = hex_integer(data, item);
  at = item.next;
  TLV inner_algorithm, issuer, validity, subject, spki;
  if (!tlv(data, at, tbs.end, inner_algorithm) ||
      !algorithm(data, inner_algorithm))
    return false;
  if (!tlv(data, inner_algorithm.next, tbs.end, issuer) || issuer.tag != 0x30)
    return false;
  if (!tlv(data, issuer.next, tbs.end, validity) || validity.tag != 0x30)
    return false;
  TLV before, after;
  if (!tlv(data, validity.start, validity.end, before) ||
      !tlv(data, before.next, validity.end, after) ||
      after.next != validity.end)
    return false;
  auto time_valid = [&](const TLV &time) {
    if (time.tag != 23 && time.tag != 24)
      return false;
    size_t expected = time.tag == 23 ? 13 : 15;
    if (time.end - time.start != expected || data[time.end - 1] != 'Z')
      return false;
    for (size_t i = time.start; i + 1 < time.end; ++i)
      if (data[i] < '0' || data[i] > '9')
        return false;
    return true;
  };
  if (!time_valid(before) || !time_valid(after))
    return false;
  if (!tlv(data, validity.next, tbs.end, subject) || subject.tag != 0x30)
    return false;
  if (!tlv(data, subject.next, tbs.end, spki) || spki.tag != 0x30)
    return false;
  TLV public_algorithm, public_key;
  if (!tlv(data, spki.start, spki.end, public_algorithm) ||
      !algorithm(data, public_algorithm))
    return false;
  if (!tlv(data, public_algorithm.next, spki.end, public_key) ||
      public_key.tag != 3 || public_key.next != spki.end)
    return false;
  at = spki.next;
  int previous = 0;
  while (at < tbs.end) {
    if (!tlv(data, at, tbs.end, item))
      return false;
    int optional = item.tag == 0x81   ? 1
                   : item.tag == 0x82 ? 2
                   : item.tag == 0xa3 ? 3
                                      : 0;
    if (!optional || optional <= previous || (optional < 3 && version < 1) ||
        (optional == 3 && version != 2))
      return false;
    previous = optional;
    at = item.next;
  }
  return true;
}
double available_at(const std::vector<std::pair<size_t, double>> &times,
                    size_t end) {
  double seen = times.front().second;
  bool found = false;
  for (auto value : times)
    if (value.first <= end) {
      seen = found ? std::max(seen, value.second) : value.second;
      found = true;
    }
  double crossing = seen;
  for (auto value : times)
    if (value.first >= end) {
      crossing = value.second;
      break;
    }
  return std::max(seen, crossing);
}
Certificate certificate(std::vector<Segment> segments) {
  std::sort(segments.begin(), segments.end());
  segments.erase(std::unique(segments.begin(), segments.end(),
                             [](const Segment &a, const Segment &b) {
                               return a.sequence == b.sequence &&
                                      a.data == b.data &&
                                      a.timestamp == b.timestamp;
                             }),
                 segments.end());
  Bytes data;
  std::vector<std::pair<size_t, double>> byte_times;
  uint64_t next = 0;
  bool has_next = false;
  for (const auto &s : segments) {
    if (!has_next) {
      next = s.sequence;
      has_next = true;
    }
    if (s.sequence > next)
      break;
    size_t skip = size_t(next - s.sequence);
    if (skip < s.data.size()) {
      data.insert(data.end(), s.data.begin() + skip, s.data.end());
      next = uint64_t(s.sequence) + s.data.size();
      byte_times.emplace_back(data.size(), s.timestamp);
    }
    if (data.size() > 262144)
      break;
  }
  Bytes hs;
  std::vector<std::pair<size_t, double>> available;
  for (size_t pos = 0; pos + 5 <= data.size();) {
    size_t size = u16(data.data() + pos + 3);
    if (data[pos + 1] != 3 || size > 18432 || size > data.size() - pos - 5)
      break;
    if (data[pos] == 22) {
      hs.insert(hs.end(), data.begin() + pos + 5,
                data.begin() + pos + 5 + size);
      available.emplace_back(hs.size(),
                             available_at(byte_times, pos + 5 + size));
    }
    pos += 5 + size;
  }
  for (size_t pos = 0; pos + 4 <= hs.size();) {
    size_t size =
        (size_t(hs[pos + 1]) << 16) | (size_t(hs[pos + 2]) << 8) | hs[pos + 3];
    if (size > hs.size() - pos - 4)
      break;
    if (hs[pos] == 11 && size >= 6) {
      size_t start = pos + 4, n = (size_t(hs[start + 3]) << 16) |
                                  (size_t(hs[start + 4]) << 8) | hs[start + 5];
      size_t begin = start + 6, end = std::min(start + size, begin + n);
      Bytes der(hs.begin() + begin, hs.begin() + end);
      std::string serial;
      if (!serial_number(der, serial))
        return {};
      return {true, std::move(serial), available_at(available, pos + 4 + size)};
    }
    pos += 4 + size;
  }
  return {};
}
std::string dotted(uint32_t ip) {
  return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) +
         "." + std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
} // namespace

std::vector<Packet> decode_packets(const Bytes &pcap, const Target &target) {
  Capture capture(pcap);
  std::vector<Packet> packets;
  capture.frames([&](size_t at, size_t cap, uint32_t wire, double timestamp,
                     int frame) {
    const uint8_t *raw = pcap.data() + at;
    if (cap < 14)
      return true;
    size_t base = 14;
    int ether = u16(raw + 12);
    while (ether == 0x8100 || ether == 0x88a8 || ether == 0x9100) {
      if (cap < base + 4)
        return true;
      ether = u16(raw + base + 2);
      base += 4;
    }
    if (ether != 0x0800 || cap < base + 20 || raw[base] >> 4 != 4)
      return true;
    size_t ihl = (raw[base] & 15) * 4;
    int total = u16(raw + base + 2);
    if (ihl < 20 || cap < base + ihl)
      return true;
    int protocol = raw[base + 9];
    if (protocol != 6 && protocol != 17)
      return true;
    if (u16(raw + base + 6) & 0x3fff)
      return true;
    size_t transport = base + ihl;
    if (cap - transport < size_t(protocol == 6 ? 20 : 8))
      return true;
    Packet p;
    p.timestamp = timestamp;
    p.src = u32(raw + base + 12);
    p.dst = u32(raw + base + 16);
    p.protocol = protocol;
    p.sport = u16(raw + transport);
    p.dport = u16(raw + transport + 2);
    p.wire = int(wire);
    p.frame = frame;
    size_t th = 8;
    if (protocol == 6) {
      th = (raw[transport + 12] >> 4) * 4;
      if (th < 20 || total < int(ihl + th))
        return true;
      p.payload = total - int(ihl + th);
      p.flags = raw[transport + 13];
      p.sequence = u32(raw + transport + 4);
    } else {
      int length = u16(raw + transport + 4);
      if (length < 8 || length > total - int(ihl))
        return true;
      p.payload = length - 8;
    }
    if (target.use_mac)
      p.direction = std::equal(target.mac.begin(), target.mac.end(), raw + 6)
                        ? 1
                    : std::equal(target.mac.begin(), target.mac.end(), raw) ? -1
                                                                            : 0;
    else if (target.ip)
      p.direction = p.src == target.ip ? 1 : p.dst == target.ip ? -1 : 0;
    if ((target.use_mac || target.ip) && !p.direction)
      return true;
    size_t payload = transport + th;
    p.payload_offset = at + payload;
    p.payload_captured =
        payload < cap ? std::min(size_t(p.payload), cap - payload) : 0;
    packets.push_back(p);
    return true;
  });
  return packets;
}
double first_timestamp(const Bytes &pcap) {
  Capture capture(pcap);
  double first = 0;
  capture.frames([&](size_t, size_t, uint32_t, double timestamp, int) {
    first = timestamp;
    return false;
  });
  return first;
}
std::vector<std::vector<Flow>> flow_windows(const Bytes &pcap,
                                            const Target &target, int windows) {
  if (windows < 0)
    throw std::runtime_error("Negative observation window count");
  auto packets = decode_packets(pcap, target);
  std::map<Key, std::vector<Segment>> streams;
  for (const auto &p : packets)
    if (p.protocol == 6 && p.payload) {
      auto &stream = streams[key(p)];
      if (stream.size() < 256) {
        Bytes bytes;
        if (p.payload_captured)
          bytes.assign(pcap.begin() + p.payload_offset,
                       pcap.begin() + p.payload_offset + p.payload_captured);
        stream.push_back({p.sequence, std::move(bytes), p.timestamp});
      }
    }
  std::map<Key, Certificate> certs;
  for (auto &stream : streams)
    certs.emplace(stream.first, certificate(std::move(stream.second)));
  std::stable_sort(packets.begin(), packets.end(),
                   [](const Packet &a, const Packet &b) {
                     return a.timestamp < b.timestamp;
                   });
  std::vector<std::vector<Flow>> result(static_cast<size_t>(windows));
  double first = first_timestamp(pcap);
  for (int window = 0; window < windows; ++window) {
    double low = first + 30 * window, high = first + 30 * (window + 1);
    auto begin = std::lower_bound(
        packets.begin(), packets.end(), low,
        [](const Packet &p, double t) { return p.timestamp < t; });
    auto end = std::lower_bound(
        packets.begin(), packets.end(), high,
        [](const Packet &p, double t) { return p.timestamp < t; });
    if (begin == end)
      continue;
    double start = begin->timestamp, last = std::prev(end)->timestamp;
    std::map<Key, size_t> indices;
    for (auto packet = begin; packet != end; ++packet) {
      const auto &p = *packet;
      if (!p.direction)
        continue;
      uint32_t local = p.direction == 1 ? p.src : p.dst,
               remote = p.direction == 1 ? p.dst : p.src;
      int lp = p.direction == 1 ? p.sport : p.dport,
          rp = p.direction == 1 ? p.dport : p.sport;
      Key k = {p.protocol, local, remote, lp, rp};
      auto found = indices.find(k);
      if (found == indices.end()) {
        Flow flow;
        flow.certificate = "N";
        auto cert = certs.find(k);
        // Python's "a or b" chooses an existing (serial,time) tuple,
        // even for a zero-valued serial; unavailable a does not try b.
        if (cert == certs.end() || !cert->second.present)
          cert = certs.find(reverse(k));
        if (cert != certs.end() && cert->second.present &&
            cert->second.available <= last)
          flow.certificate = "C" + cert->second.serial;
        // Flow.add chooses the lower-port endpoint. With equal ports,
        // destination is the first packet's source (direction matters).
        bool destination_local = lp < rp || (lp == rp && p.direction == 1);
        flow.destination = "D" +
                           dotted(destination_local ? 0xc0a80002 : remote) +
                           ":" + std::to_string(destination_local ? lp : rp);
        size_t index = result[size_t(window)].size();
        result[size_t(window)].push_back(std::move(flow));
        indices.emplace(k, index);
        found = indices.find(k);
      }
      auto &flow = result[size_t(window)][found->second];
      double t = p.timestamp - start;
      if (flow.timestamps.empty())
        flow.start = t;
      flow.end = t;
      flow.timestamps.push_back(t);
    }
  }
  return result;
}
} // namespace rwbase
