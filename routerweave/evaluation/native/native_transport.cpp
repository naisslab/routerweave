#include "native_iot.h"
#include <algorithm>
#include <cmath>
#include <deque>
#include <limits>
#include <list>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace rwiot {
namespace {
using Bytes = std::vector<uint8_t>;
using Endpoint = std::pair<std::string, int>;
using DirectionalKey = std::pair<Endpoint, Endpoint>;
using ConnectionKey = std::tuple<bool, Endpoint, Endpoint>;
using Range = std::pair<int, int>; // absolute start, byte count
constexpr uint64_t MOD = uint64_t(1) << 32;
int64_t distance32(uint32_t a, uint32_t b) {
  return int64_t((uint64_t(a) + MOD - uint64_t(b) + (MOD / 2)) % MOD) -
         int64_t(MOD / 2);
}
uint16_t be16(const uint8_t *p) {
  return uint16_t((unsigned(p[0]) << 8) | p[1]);
}
uint32_t be32(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | p[3];
}
uint32_t file32(const uint8_t *p, bool little) {
  return little ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
                      (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
                : be32(p);
}
std::string hex(const uint8_t *p, int n) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size_t(n) * 2);
  for (int i = 0; i < n; ++i) {
    out.push_back(digits[p[i] >> 4]);
    out.push_back(digits[p[i] & 15]);
  }
  return out;
}
struct Packet {
  Endpoint src, dst;
  bool tcp = false, complete = false, conflict = false, control = false;
  uint32_t seq = 0;
  int flags = 0, window = 0, offset = 0, expected = 0, wire = 0, frame = 0,
      flow = 0, direction = 0;
  double timestamp = 0, observed = 0;
  Bytes payload, options;
  std::vector<Range> duplicates;
};
// Bounds and unsupported-packet decisions match decode_transport, including
// Ethernet padding, VLAN stacks, extension limits and fragmented-IP rejection.
bool decode(const uint8_t *raw, size_t length, Packet &p) {
  if (length < 14)
    return false;
  size_t pos = 14, end = 0;
  int eth = be16(raw + 12), protocol;
  while (eth == 0x8100 || eth == 0x88a8) {
    if (length < pos + 4)
      return false;
    eth = be16(raw + pos + 2);
    pos += 4;
  }
  if (eth == 0x0800) {
    if (length < pos + 20 || raw[pos] >> 4 != 4)
      return false;
    size_t size = (raw[pos] & 15) * 4;
    end = pos + be16(raw + pos + 2);
    if (size < 20 || pos + size > std::min(end, length))
      return false;
    if (be16(raw + pos + 6) & 0x3fff)
      return false;
    protocol = raw[pos + 9];
    p.src.first = hex(raw + pos + 12, 4);
    p.dst.first = hex(raw + pos + 16, 4);
    pos += size;
  } else if (eth == 0x86dd) {
    if (length < pos + 40 || raw[pos] >> 4 != 6)
      return false;
    size_t size = be16(raw + pos + 4);
    if (!size)
      return false;
    end = pos + 40 + size;
    protocol = raw[pos + 6];
    p.src.first = hex(raw + pos + 8, 16);
    p.dst.first = hex(raw + pos + 24, 16);
    pos += 40;
    int i = 0;
    for (; i < 16; ++i) {
      if (protocol != 0 && protocol != 43 && protocol != 44 && protocol != 51 &&
          protocol != 60)
        break;
      if (protocol == 44 || pos + 2 > std::min(end, length))
        return false;
      size = (protocol == 51) ? (raw[pos + 1] + 2) * 4 : (raw[pos + 1] + 1) * 8;
      if (pos + size > std::min(end, length))
        return false;
      protocol = raw[pos];
      pos += size;
    }
    if (i == 16)
      return false;
  } else
    return false;
  if (protocol != 6 && protocol != 17)
    return false;
  p.tcp = protocol == 6;
  size_t size = p.tcp ? 20 : 8;
  if (pos + size > std::min(end, length))
    return false;
  p.src.second = be16(raw + pos);
  p.dst.second = be16(raw + pos + 2);
  if (p.tcp) {
    size = (raw[pos + 12] >> 4) * 4;
    if (size < 20 || pos + size > std::min(end, length))
      return false;
    p.seq = be32(raw + pos + 4);
    p.flags = raw[pos + 13];
    p.window = be16(raw + pos + 14);
    p.options.assign(raw + pos + 20, raw + pos + size);
  } else {
    size_t udp_length = be16(raw + pos + 4);
    if (udp_length < 8 || pos + udp_length > end)
      return false;
    end = pos + udp_length;
  }
  const size_t start = pos + size;
  p.offset = int(start);
  p.expected = int(end - start);
  p.complete = end <= length;
  p.wire = int(length);
  p.payload.assign(raw + start, raw + std::min(end, length));
  return true;
}
bool special_options(const Bytes &options) {
  size_t pos = 0;
  while (pos < options.size()) {
    int kind = options[pos];
    if (kind == 0)
      return false;
    if (kind == 1) {
      ++pos;
      continue;
    }
    if (pos + 1 >= options.size())
      return true;
    int n = options[pos + 1];
    if (kind != 8 || n != 10 || pos + size_t(n) > options.size())
      return true;
    pos += n;
  }
  return false;
}
struct HistoryState {
  uint32_t base = 0, syn = 0;
  bool has_syn = false, conflict = false, has_window = false;
  int64_t high = 0;
  double time = 0;
  int window = 0;
  size_t size = 0;
  std::deque<std::pair<int64_t, Bytes>> blocks;
  std::list<DirectionalKey>::iterator lru;
};
class ByteHistory {
  std::map<DirectionalKey, HistoryState> states;
  std::list<DirectionalKey> lru;
  double last = -std::numeric_limits<double>::infinity();
  void erase(const DirectionalKey &key) {
    auto i = states.find(key);
    if (i != states.end()) {
      lru.erase(i->second.lru);
      states.erase(i);
    }
  }
  void oldest() { erase(lru.front()); }

public:
  void feed(Packet &p) {
    double now = std::max(last, p.timestamp);
    last = now;
    while (!lru.empty() && now - states.at(lru.front()).time > 120.)
      oldest();
    DirectionalKey key = {p.src, p.dst}, reverse = {p.dst, p.src};
    auto it = states.find(key);
    bool syn = p.flags & 2;
    if (syn && !(p.flags & 16) &&
        (it == states.end() || !it->second.has_syn ||
         it->second.syn != p.seq)) {
      erase(key);
      erase(reverse);
      it = states.end();
    }
    if (it == states.end()) {
      while (states.size() >= 256)
        oldest();
      HistoryState state;
      state.base = p.seq + uint32_t(syn);
      state.syn = p.seq;
      state.has_syn = syn;
      lru.push_back(key);
      state.lru = std::prev(lru.end());
      it = states.emplace(key, std::move(state)).first;
    }
    auto &s = it->second;
    lru.splice(lru.end(), lru, s.lru);
    s.time = now;
    p.control = special_options(p.options) ||
                (s.has_window && s.window != p.window) || p.window == 0;
    s.window = p.window;
    s.has_window = true;
    uint32_t seq = p.seq + uint32_t(syn), anchor = s.base + uint32_t(s.high);
    int64_t start = s.high + distance32(seq, anchor),
            end = start + int64_t(p.payload.size());
    std::vector<Range> overlaps, merged;
    bool conflict = s.conflict;
    if (!p.payload.empty() && start < s.high) {
      for (const auto &block : s.blocks) {
        int64_t lo = std::max(start, block.first),
                hi = std::min(end, block.first + int64_t(block.second.size()));
        if (lo < hi) {
          if (!std::equal(p.payload.begin() + (lo - start),
                          p.payload.begin() + (hi - start),
                          block.second.begin() + (lo - block.first))) {
            conflict = true;
            break;
          }
          overlaps.emplace_back(int(lo - start), int(hi - start));
        }
      }
    }
    std::sort(overlaps.begin(), overlaps.end());
    for (auto range : overlaps) {
      if (!merged.empty() && range.first <= merged.back().second)
        merged.back().second = std::max(range.second, merged.back().second);
      else
        merged.push_back(range);
    }
    if (conflict) {
      merged.clear();
      s.conflict = true;
    } else if (p.complete && !p.payload.empty()) {
      auto novel = merged;
      novel.emplace_back(int(p.payload.size()), int(p.payload.size()));
      int cursor = 0;
      for (auto range : novel) {
        if (cursor < range.first) {
          Bytes b(p.payload.begin() + cursor, p.payload.begin() + range.first);
          s.size += b.size();
          s.blocks.emplace_back(start + cursor, std::move(b));
        }
        cursor = range.second;
      }
      while (s.size > 65536 || s.blocks.size() > 256) {
        s.size -= s.blocks.front().second.size();
        s.blocks.pop_front();
      }
    }
    if (!p.complete)
      merged.clear();
    s.high = std::max(s.high, end);
    p.conflict = conflict;
    for (auto range : merged)
      p.duplicates.emplace_back(p.offset + range.first,
                                range.second - range.first);
    if (p.flags & 4) {
      erase(key);
      erase(reverse);
    }
  }
};
struct Piece {
  int frame, offset, size;
  double timestamp;
};
struct Record {
  int length = 0, ordinal = 0;
  bool anchored = false;
  double first = 0, available = 0;
  std::vector<Piece> pieces;
};
struct Segment {
  uint32_t seq;
  Bytes data;
  int frame;
  double timestamp;
  int offset;
};
struct Part {
  int size, frame;
  double timestamp;
  int offset;
};
class Stream {
  bool has_next = false, anchored = false, failed = false;
  uint32_t next = 0;
  Bytes buf, history;
  std::deque<Part> parts;
  std::vector<Segment> pending;
  double max_available = -std::numeric_limits<double>::infinity();

public:
  Stream() = default;
  Stream(bool syn, uint32_t seq)
      : has_next(syn), anchored(syn), next(seq + 1) {}
  std::vector<Record> feed(uint32_t seq, Bytes data, int frame,
                           double timestamp, int offset) {
    std::vector<Record> records;
    if (data.empty() || failed)
      return records;
    max_available = std::max(max_available, timestamp);
    if (!has_next) {
      has_next = true;
      next = seq;
    }
    int64_t delta = distance32(seq, next);
    if (delta < 0) {
      size_t overlap = size_t(std::min<int64_t>(-delta, data.size()));
      int64_t hstart = int64_t(history.size()) + delta;
      if (hstart >= 0) {
        // Python's slice comparison also rejects a shorter cached slice.
        if (hstart + int64_t(overlap) > int64_t(history.size()) ||
            !std::equal(data.begin(), data.begin() + overlap,
                        history.begin() + hstart)) {
          failed = true;
          return records;
        }
      }
      data.erase(data.begin(), data.begin() + overlap);
      offset += int(overlap);
      seq += uint32_t(overlap);
      if (data.empty())
        return records;
      delta = distance32(seq, next);
    }
    if (delta > 0) {
      pending.push_back({seq, std::move(data), frame, timestamp, offset});
      size_t bytes = 0;
      for (const auto &p : pending)
        bytes += p.data.size();
      if (pending.size() > 512 || bytes > 1024 * 1024) {
        failed = true;
        pending.clear();
      }
      return records;
    }
    next += uint32_t(data.size());
    history.insert(history.end(), data.begin(), data.end());
    if (history.size() > 65536)
      history.erase(history.begin(), history.end() - 65536);
    buf.insert(buf.end(), data.begin(), data.end());
    parts.push_back({int(data.size()), frame, timestamp, offset});
    while (buf.size() >= 5) {
      int type = buf[0], major = buf[1], minor = buf[2],
          length = be16(buf.data() + 3);
      if (type < 20 || type > 24 || major != 3 || minor > 3 || length > 18432) {
        failed = true;
        buf.clear();
        parts.clear();
        pending.clear();
        return records;
      }
      if (buf.size() < size_t(length + 5))
        break;
      Record r;
      r.length = length + 5;
      r.anchored = anchored;
      r.first = std::numeric_limits<double>::infinity();
      r.available = max_available;
      int remaining = r.length;
      while (remaining) {
        auto &p = parts.front();
        int take = std::min(remaining, p.size);
        r.pieces.push_back({p.frame, p.offset, take, p.timestamp});
        r.first = std::min(r.first, p.timestamp);
        remaining -= take;
        p.size -= take;
        p.offset += take;
        if (!p.size)
          parts.pop_front();
      }
      buf.erase(buf.begin(), buf.begin() + r.length);
      records.push_back(std::move(r));
    }
    while (!pending.empty() && !failed) {
      std::stable_sort(pending.begin(), pending.end(),
                       [this](const Segment &a, const Segment &b) {
                         return distance32(a.seq, next) <
                                distance32(b.seq, next);
                       });
      if (distance32(pending.front().seq, next) > 0)
        break;
      Segment p = std::move(pending.front());
      pending.erase(pending.begin());
      auto more =
          feed(p.seq, std::move(p.data), p.frame, p.timestamp, p.offset);
      records.insert(records.end(), std::make_move_iterator(more.begin()),
                     std::make_move_iterator(more.end()));
    }
    return records;
  }
};
struct Connection {
  int id = 0;
  bool has_syn = false;
  uint32_t syn = 0;
  std::map<int, Stream> streams;
  int ordinals[2] = {0, 0};
};
bool discovery_port(int p) {
  return p == 53 || p == 67 || p == 68 || p == 1900 || p == 5353 || p == 5355;
}
struct OrderedUnit {
  Unit unit;
  int kind;
};
} // namespace

std::vector<Unit> canonical_input(const std::vector<uint8_t> &data,
                                  const std::array<uint8_t, 6> &mac) {
  if (data.size() < 24)
    throw std::runtime_error("short PCAP");
  const uint32_t magic = be32(data.data());
  bool little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
  if (!little && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d)
    throw std::runtime_error("classic PCAP required");
  double scale = (magic == 0x4d3cb2a1 || magic == 0xa1b23c4d) ? 1e9 : 1e6;
  if (file32(data.data() + 20, little) != 1)
    throw std::runtime_error("Ethernet PCAP required");
  ByteHistory history;
  std::map<ConnectionKey, Connection> connections;
  std::vector<Packet> packets;
  std::vector<Record> records;
  std::set<int> discovery;
  int next_id = 0, frame = 0;
  double observed = -std::numeric_limits<double>::infinity();
  for (size_t at = 24; at < data.size();) {
    if (data.size() - at < 16)
      throw std::runtime_error("short packet header");
    uint32_t sec = file32(data.data() + at, little),
             frac = file32(data.data() + at + 4, little),
             cap = file32(data.data() + at + 8, little);
    at += 16;
    if (size_t(cap) > data.size() - at)
      throw std::runtime_error("short packet");
    const uint8_t *raw = data.data() + at;
    at += cap;
    ++frame;
    double stamp = double(sec) + double(frac) / scale;
    observed = std::max(observed, stamp);
    int direction = cap >= 12 && std::equal(mac.begin(), mac.end(), raw + 6) ? 1
                    : cap >= 6 && std::equal(mac.begin(), mac.end(), raw) ? -1
                                                                          : 0;
    if (!direction)
      continue;
    Packet p;
    if (!decode(raw, cap, p))
      continue;
    Endpoint first = std::min(p.src, p.dst), second = std::max(p.src, p.dst);
    ConnectionKey key = {p.tcp, first, second};
    bool syn = p.tcp && (p.flags & 2) && !(p.flags & 16);
    auto it = connections.find(key);
    if (it == connections.end() ||
        (syn && it->second.has_syn && it->second.syn != p.seq)) {
      Connection c;
      c.id = next_id++;
      it = connections.insert_or_assign(key, std::move(c)).first;
    }
    auto &conn = it->second;
    if (syn) {
      conn.has_syn = true;
      conn.syn = p.seq;
    }
    p.frame = frame;
    p.flow = conn.id;
    p.direction = direction;
    p.timestamp = stamp;
    p.observed = observed;
    if (discovery_port(p.src.second) || discovery_port(p.dst.second))
      discovery.insert(p.flow);
    if (p.tcp) {
      history.feed(p);
      int side = p.src != first;
      auto stream = conn.streams.find(side);
      if (stream == conn.streams.end())
        stream =
            conn.streams.emplace(side, Stream(bool(p.flags & 2), p.seq)).first;
      auto more = stream->second.feed(p.seq + uint32_t(bool(p.flags & 2)),
                                      p.payload, frame, stamp, p.offset);
      for (auto &r : more) {
        r.ordinal = ++conn.ordinals[side];
        records.push_back(std::move(r));
      }
    }
    // The Python packet list retains metadata only. Ciphertext belongs to
    // the bounded history/reassembler, never to the all-packet metadata.
    Bytes().swap(p.payload);
    Bytes().swap(p.options);
    bool reset = p.tcp && (p.flags & 4);
    packets.push_back(std::move(p));
    if (reset)
      connections.erase(key);
  }
  std::map<int, size_t> by_frame;
  for (size_t i = 0; i < packets.size(); ++i) {
    auto &p = packets[i];
    p.timestamp = std::max(p.timestamp, p.observed - .5);
    by_frame[p.frame] = i;
    if (!std::isfinite(p.timestamp))
      throw std::runtime_error("Nonfinite packet timestamp");
    if (p.wire < 0 || p.expected < 0 || p.expected > p.wire)
      throw std::runtime_error("Invalid packet lengths");
  }
  std::map<int, std::vector<Range>> used;
  std::vector<OrderedUnit> output;
  for (auto &r : records) {
    bool safe = true;
    r.first = std::numeric_limits<double>::infinity();
    for (auto &piece : r.pieces) {
      auto found = by_frame.find(piece.frame);
      if (found == by_frame.end()) {
        safe = false;
        break;
      }
      const auto &p = packets[found->second];
      piece.timestamp = p.timestamp;
      r.first = std::min(r.first, piece.timestamp);
      r.available = std::max(r.available, p.observed);
      if (p.conflict || !p.complete)
        safe = false;
      for (auto range : p.duplicates)
        if (piece.offset < range.first + range.second &&
            range.first < piece.offset + piece.size)
          safe = false;
    }
    if (!safe)
      continue;
    if (!std::isfinite(r.first) || !std::isfinite(r.available) ||
        r.available < r.first)
      throw std::runtime_error("Invalid TLS timestamp");
    if ((!r.anchored && r.ordinal < 2) || r.available > r.first + .5)
      continue;
    if (r.pieces.empty())
      continue;
    const Packet &first = packets[by_frame.at(r.pieces.front().frame)];
    int total = 0;
    std::set<int> original;
    for (const auto &piece : r.pieces) {
      const auto &p = packets[by_frame.at(piece.frame)];
      if (!p.tcp || p.direction != first.direction || p.flow != first.flow)
        throw std::runtime_error("TLS record crosses directional flows");
      if (piece.offset < p.offset || piece.size <= 0 ||
          piece.offset + piece.size > p.offset + p.expected)
        throw std::runtime_error("TLS byte range outside packet payload/frame");
      for (auto range : used[p.frame])
        if (piece.offset < range.first + range.second &&
            range.first < piece.offset + piece.size)
          throw std::runtime_error("Overlapping TLS byte ownership");
      used[p.frame].emplace_back(piece.offset, piece.size);
      total += piece.size;
      original.insert(piece.frame);
    }
    if (total != r.length)
      throw std::runtime_error("TLS length/mapping mismatch");
    Unit u{r.first,
           r.length,
           first.direction,
           first.flow,
           0,
           first.frame,
           {original.begin(), original.end()}};
    output.push_back(
        {std::move(u), 2}); // packet < residual_packet < tls_record
  }
  for (const auto &p : packets) {
    int consumed = 0;
    for (auto range : used[p.frame])
      consumed += range.second;
    if (consumed > p.expected)
      throw std::runtime_error("TLS bytes exceed original TCP payload");
    if (consumed && consumed == p.expected)
      continue;
    if (p.tcp && p.expected == 0 && p.flags == 0x10 && !p.control)
      continue;
    int payload = p.expected - consumed, duplicate = 0;
    for (auto range : p.duplicates)
      duplicate += range.second;
    if (duplicate > payload)
      throw std::runtime_error(
          "Duplicate accounting overlaps consumed TLS bytes");
    int remaining = payload - duplicate;
    if (duplicate && remaining == 0)
      continue;
    if (p.complete && remaining) {
      std::vector<Range> excluded = used[p.frame];
      excluded.insert(excluded.end(), p.duplicates.begin(), p.duplicates.end());
      std::sort(excluded.begin(), excluded.end(), [](Range a, Range b) {
        return std::make_pair(a.first, a.first + a.second) <
               std::make_pair(b.first, b.first + b.second);
      });
      int cursor = p.offset, end = p.offset + p.expected, sum = 0;
      excluded.emplace_back(end, 0);
      for (auto range : excluded) {
        if (cursor < range.first)
          sum += range.first - cursor;
        cursor = std::max(cursor, range.first + range.second);
      }
      if (sum != remaining)
        throw std::runtime_error("Residual byte provenance mismatch");
    }
    if (p.complete && remaining > 0)
      output.push_back({{p.timestamp,
                         remaining,
                         p.direction,
                         p.flow,
                         int(!p.tcp),
                         p.frame,
                         {p.frame}},
                        consumed ? 1 : 0});
  }
  // normalize_packets sorts by logical time, original frame and unit kind;
  // canonical_input's final stable sort retains this order at equal time/frame.
  std::stable_sort(output.begin(), output.end(),
                   [](const OrderedUnit &a, const OrderedUnit &b) {
                     return std::tie(a.unit.timestamp, a.unit.frame, a.kind) <
                            std::tie(b.unit.timestamp, b.unit.frame, b.kind);
                   });
  std::vector<Unit> result;
  result.reserve(output.size());
  for (auto &item : output)
    if (!discovery.count(item.unit.flow))
      result.push_back(std::move(item.unit));
  return result;
}
} // namespace rwiot
