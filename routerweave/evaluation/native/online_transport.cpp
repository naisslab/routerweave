// Reuse the original decoder, byte-history and TLS reassembler in this TU.
#include "online_transport.h"
#include "native_transport.cpp"

namespace rwiot {
struct OnlineTransport::Impl {
  std::array<uint8_t, 6> mac;
  ByteHistory history;
  std::map<ConnectionKey, Connection> connections;
  std::map<int, Packet> packets;
  std::vector<Record> records;
  std::set<int> discovery;
  std::map<int, std::vector<Range>> used;
  std::vector<OrderedUnit> ready;
  int next_id = 0, frame = 0;
  double observed = -INFINITY;
  explicit Impl(std::array<uint8_t, 6> m) : mac(m) {}
  void feed(const uint8_t *raw, size_t cap, double stamp) {
    ++frame;
    observed = std::max(observed, stamp);
    int direction = cap >= 12 && std::equal(mac.begin(), mac.end(), raw + 6) ? 1
                    : cap >= 6 && std::equal(mac.begin(), mac.end(), raw) ? -1
                                                                          : 0;
    if (!direction)
      return;
    Packet p;
    if (!decode(raw, cap, p))
      return;
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
    if (connections.size() > 8192)
      throw std::runtime_error("IoT connection-state memory guard");
    auto &conn = it->second;
    if (syn) {
      conn.has_syn = true;
      conn.syn = p.seq;
    }
    p.frame = frame;
    p.flow = conn.id;
    p.direction = direction;
    p.timestamp = std::max(stamp, observed - .5);
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
    Bytes().swap(p.payload);
    Bytes().swap(p.options);
    bool reset = p.tcp && (p.flags & 4);
    packets.emplace(frame, std::move(p));
    if (reset)
      connections.erase(key);
  }
  std::vector<Unit> advance(double now) {
    for (auto &r : records) {
      bool safe = true;
      r.first = INFINITY;
      for (auto &piece : r.pieces) {
        auto found = packets.find(piece.frame);
        if (found == packets.end()) {
          safe = false;
          break;
        }
        auto &p = found->second;
        piece.timestamp = p.timestamp;
        r.first = std::min(r.first, p.timestamp);
        r.available = std::max(r.available, p.observed);
        if (p.conflict || !p.complete)
          safe = false;
        for (auto range : p.duplicates)
          if (piece.offset < range.first + range.second &&
              range.first < piece.offset + piece.size)
            safe = false;
      }
      if (!safe || (!r.anchored && r.ordinal < 2) ||
          r.available > r.first + .5 || r.pieces.empty())
        continue;
      auto &first = packets.at(r.pieces.front().frame);
      int total = 0;
      std::set<int> original;
      for (auto &piece : r.pieces) {
        auto &p = packets.at(piece.frame);
        used[p.frame].emplace_back(piece.offset, piece.size);
        total += piece.size;
        original.insert(piece.frame);
      }
      if (total != r.length)
        throw std::runtime_error("Online TLS length mismatch");
      ready.push_back({{r.first,
                        r.length,
                        first.direction,
                        first.flow,
                        0,
                        first.frame,
                        {original.begin(), original.end()}},
                       2});
    }
    records.clear();
    for (auto it = packets.begin(); it != packets.end();) {
      auto &p = it->second;
      if (p.timestamp >= now - .5) {
        ++it;
        continue;
      }
      int consumed = 0;
      for (auto range : used[p.frame])
        consumed += range.second;
      if (consumed > p.expected)
        throw std::runtime_error("Online consumed bytes exceed payload");
      int duplicate = 0;
      for (auto range : p.duplicates)
        duplicate += range.second;
      int remaining = p.expected - consumed - duplicate;
      if (remaining < 0)
        throw std::runtime_error("Online duplicate overlap");
      if (!(consumed && consumed == p.expected) &&
          !(p.tcp && p.expected == 0 && p.flags == 0x10 && !p.control) &&
          !(duplicate && remaining == 0) && p.complete && remaining > 0)
        ready.push_back({{p.timestamp,
                          remaining,
                          p.direction,
                          p.flow,
                          int(!p.tcp),
                          p.frame,
                          {p.frame}},
                         consumed ? 1 : 0});
      used.erase(p.frame);
      it = packets.erase(it);
    }
    std::stable_sort(ready.begin(), ready.end(), [](auto &a, auto &b) {
      return std::tie(a.unit.timestamp, a.unit.frame, a.kind) <
             std::tie(b.unit.timestamp, b.unit.frame, b.kind);
    });
    std::vector<Unit> output;
    auto it = ready.begin();
    while (it != ready.end() && it->unit.timestamp < now - .5) {
      if (!discovery.count(it->unit.flow))
        output.push_back(std::move(it->unit));
      ++it;
    }
    ready.erase(ready.begin(), it);
    return output;
  }
};
OnlineTransport::OnlineTransport(std::array<uint8_t, 6> m)
    : impl(new Impl(m)) {}
OnlineTransport::~OnlineTransport() = default;
void OnlineTransport::feed(const uint8_t *raw, size_t cap, double stamp) {
  impl->feed(raw, cap, stamp);
}
std::vector<Unit> OnlineTransport::advance(double now) {
  return impl->advance(now);
}
size_t OnlineTransport::pending_packets() const { return impl->packets.size(); }
} // namespace rwiot
