// Reuse the native FlowPrint parser, TLS reconstruction and flow equations.
#include "flow_online.h"
#include "native_baseline_raw.cpp"
#include <cstring>
#include <deque>
struct FlowOnline::Impl {
  rwbase::Target target;
  std::deque<rwbase::Packet> packets;
  std::map<rwbase::Key, std::vector<rwbase::Segment>> streams;
  std::map<rwbase::Key, rwbase::Certificate> certs;
  std::set<rwbase::Key> dirty;
  explicit Impl(rwbase::Target t) : target(t) {}
};
FlowOnline::FlowOnline(rwbase::Target t) : impl(new Impl(t)) {}
FlowOnline::~FlowOnline() = default;
void FlowOnline::feed(const unsigned char *raw, unsigned cap, unsigned wire,
                      double stamp) {
  rwbase::Bytes b(40 + cap);
  unsigned header[] = {0xa1b2c3d4, 0x00040002, 0, 0, 262144, 1};
  std::memcpy(b.data(), header, 24);
  unsigned seconds = (unsigned)stamp,
           micro = (unsigned)std::llround((stamp - seconds) * 1e6);
  if (micro == 1000000) {
    seconds++;
    micro = 0;
  }
  unsigned record[] = {seconds, micro, cap, wire};
  std::memcpy(b.data() + 24, record, 16);
  std::memcpy(b.data() + 40, raw, cap);
  for (auto p : rwbase::decode_packets(b, impl->target)) {
    p.timestamp = stamp;
    if (p.protocol == 6 && p.payload) {
      auto k = rwbase::key(p);
      auto &stream = impl->streams[k];
      if (!impl->certs[k].present && stream.size() < 256) {
        rwbase::Bytes bytes;
        if (p.payload_captured)
          bytes.assign(b.begin() + p.payload_offset,
                       b.begin() + p.payload_offset + p.payload_captured);
        stream.push_back({p.sequence, std::move(bytes), p.timestamp});
        impl->dirty.insert(k);
      }
    }
    impl->packets.push_back(p);
  }
}
std::vector<rwbase::Flow> FlowOnline::window(double cutoff) {
  for (auto &k : impl->dirty) {
    impl->certs[k] = rwbase::certificate(impl->streams[k]);
    if (impl->certs[k].present)
      std::vector<rwbase::Segment>().swap(impl->streams[k]);
  }
  impl->dirty.clear();
  auto &packets = impl->packets;
  while (!packets.empty() && packets.front().timestamp < cutoff - 30)
    packets.pop_front();
  std::vector<rwbase::Flow> out;
  std::map<rwbase::Key, size_t> indices;
  if (packets.empty())
    return out;
  double start = packets.front().timestamp, last = packets.back().timestamp;
  for (auto &p : packets) {
    if (p.timestamp >= cutoff)
      throw std::runtime_error("Future FlowPrint packet");
    uint32_t local = p.direction == 1 ? p.src : p.dst,
             remote = p.direction == 1 ? p.dst : p.src;
    int lp = p.direction == 1 ? p.sport : p.dport,
        rp = p.direction == 1 ? p.dport : p.sport;
    rwbase::Key k = {p.protocol, local, remote, lp, rp};
    auto found = indices.find(k);
    if (found == indices.end()) {
      rwbase::Flow flow;
      flow.certificate = "N";
      auto cert = impl->certs.find(k);
      if (cert == impl->certs.end() || !cert->second.present)
        cert = impl->certs.find(rwbase::reverse(k));
      if (cert != impl->certs.end() && cert->second.present &&
          cert->second.available <= last)
        flow.certificate = "C" + cert->second.serial;
      bool dl = lp < rp || (lp == rp && p.direction == 1);
      flow.destination = "D" + rwbase::dotted(dl ? 0xc0a80002 : remote) + ":" +
                         std::to_string(dl ? lp : rp);
      size_t index = out.size();
      out.push_back(std::move(flow));
      found = indices.emplace(k, index).first;
    }
    auto &flow = out[found->second];
    double t = p.timestamp - start;
    if (flow.timestamps.empty())
      flow.start = t;
    flow.end = t;
    flow.timestamps.push_back(t);
  }
  return out;
}
