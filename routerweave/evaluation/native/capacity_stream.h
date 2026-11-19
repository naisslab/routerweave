#pragma once
#include "online_transport.h"
#include "stream_features.h"
// Two-second device-stream silence closes observation context, not an event
// label.
class BStream {
  rwiot::OnlineTransport transport;
  const Model &detector;
  const Model &classifier;
  int device, stream;
  StreamFeatures feature_state;
  std::vector<Unit> &units = feature_state.units;
  int offset = 0, owned = 0, serial = 0;
  double last = -INFINITY;
  struct Pending {
    int id, anchor;
    std::vector<int> ids;
  };
  std::map<int, Pending> pending;
  std::map<int, std::pair<float, int>> winners;
  Features features(double gap) { return feature_state.features(gap); }
  void process_core(int end, int right) {
    int left = std::max(offset, owned - 128), n = right - left;
    auto f = features(.5);
    Vec x((size_t)n * 10), times(n);
    std::vector<int> flows(n), bursts(n);
    auto &mean = detector.at("__mean").values;
    auto &scale = detector.at("__scale").values;
    if (end <= owned || end > owned + 256 || right < end || right > end + 128 ||
        n > 512 || owned < left)
      throw std::runtime_error("Quiet B core/context bound");
    for (int k = 0; k < n; k++) {
      int p = left - offset + k;
      times[k] = float(units[p].timestamp - units[left - offset].timestamp);
      flows[k] = f.flows[p];
      bursts[k] = f.bursts[p];
      for (int j = 0; j < 10; j++)
        x[k * 10 + j] = (f.x[p * 10 + j] - mean[j]) / scale[j];
    }
    auto enc = encode(detector, x, n, flows, bursts);
    std::vector<int> leaders;
    for (int k = owned - left; k < end - left; k++)
      if (sigmoid(enc.starts[k]) >= .5f)
        leaders.push_back(k);
    if (leaders.empty()) {
      owned = end;
      calls++;
      max_context = std::max(max_context, n);
      return;
    }
    auto member = scores(detector, enc, leaders, times, flows, bursts, false),
         ends = scores(detector, enc, leaders, times, flows, bursts, true);
    for (size_t j = 0; j < leaders.size(); j++) {
      int a = leaders[j];
      if (sigmoid(member[j * n + a]) < .5f)
        continue;
      int e = 0;
      for (int k = 1; k < n; k++)
        if (ends[j * n + k] > ends[j * n + e])
          e = k;
      int anchor = a + left;
      float own = member[j * n + a];
      auto prior = winners.find(anchor);
      if (prior != winners.end() && prior->second.first >= own)
        continue;
      Pending p{serial++, anchor, {}};
      for (int k = a; k <= e; k++)
        if (sigmoid(member[j * n + k]) >= .5f) {
          int id = k + left;
          p.ids.push_back(id);
          auto old = winners.find(id);
          if (old == winners.end() || member[j * n + k] > old->second.first)
            winners[id] = {member[j * n + k], p.id};
        }
      if (p.ids.empty() || p.ids.front() != anchor)
        throw std::runtime_error("Online candidate lost anchor");
      pending.emplace(p.id, std::move(p));
    }
    owned = end;
    calls++;
    max_context = std::max(max_context, n);
  }
  void publish(double now, double origin) {
    for (auto it = pending.begin(); it != pending.end();) {
      if (it->second.ids.back() >= owned) {
        ++it;
        continue;
      }
      std::vector<int> ids;
      for (auto &w : winners)
        if (w.second.second == it->first)
          ids.push_back(w.first - offset);
      if (ids.empty() || units.at(ids.front()).frame <= 0)
        throw std::runtime_error("Online candidate provenance");
      auto f = features(1.);
      auto row = make_row(units, f, ids, device);
      auto p = classify(classifier, row);
      int label = int(std::max_element(p.begin(), p.end()) - p.begin());
      double begin = units.at(ids.front()).timestamp,
             end = units.at(ids.back()).timestamp;
      if (end > now - .5 + 1e-7)
        throw std::runtime_error("Future IoT evidence");
      bool accepted = true;
      std::cout << "{\"type\":\""
                << (accepted ? "iot_event" : "iot_rejected_candidate")
                << "\",\"stream\":" << stream << ",\"start\":" << begin
                << ",\"end\":" << end
                << ",\"anchor_unit\":" << it->second.anchor
                << ",\"anchor_frame\":"
                << units.at(it->second.anchor - offset).frame
                << ",\"label\":" << label << ",\"probability\":" << p[label]
                << ",\"confirmed_at\":" << now
                << ",\"published_elapsed\":" << wall_now() - origin
                << ",\"members\":[";
      for (size_t k = 0; k < ids.size(); k++) {
        if (k)
          std::cout << ',';
        std::cout << units.at(ids[k]).frame;
      }
      std::cout << "],\"member_units\":[";
      for (size_t k = 0; k < ids.size(); k++) {
        if (k)
          std::cout << ',';
        std::cout << ids[k] + offset;
      }
      std::cout << "]}\n";
      for (auto w = winners.begin(); w != winners.end();)
        if (w->second.second == it->first)
          w = winners.erase(w);
        else
          ++w;
      it = pending.erase(it);
      if (accepted)
        events++;
    }
  }
  void close_tail(double now, double origin) {
    int total = offset + (int)units.size();
    if (owned >= total)
      return;
    while (owned < total) {
      int end = std::min(owned + 256, total);
      process_core(end, std::min(total, end + 128));
      publish(now, origin);
    }
    quiet_closures++;
  }
  void prune() {
    if (units.empty())
      return;
    int earliest = std::max(offset, owned - 128);
    for (auto &p : pending)
      earliest = std::min(earliest, p.second.anchor);
    if (earliest <= offset)
      return;
    double before =
        units.at(std::min((int)units.size() - 1, earliest - offset)).timestamp -
        10.;
    size_t remove = 0;
    while (remove < units.size() && offset + (int)remove < earliest &&
           units[remove].timestamp < before)
      remove++;
    feature_state.prune(remove);
    offset += (int)remove;
  }

public:
  unsigned long packets = 0, calls = 0, events = 0, quiet_closures = 0,
                packet_closures = 0;
  int max_context = 0;
  size_t peak_units = 0, peak_pending_packets = 0;
  BStream(std::array<uint8_t, 6> mac, const Model &d, const Model &c, int dev,
          int id)
      : transport(mac), detector(d), classifier(c), device(dev), stream(id) {}
  void feed(const uint8_t *raw, size_t cap, double stamp) {
    transport.feed(raw, cap, stamp);
    packets++;
    peak_pending_packets =
        std::max(peak_pending_packets, transport.pending_packets());
    if (transport.pending_packets() > 65536)
      throw std::runtime_error("IoT pending-packet memory guard");
  }
  void tick(double now, double wall_elapsed) {
    double origin = wall_now() - wall_elapsed;
    auto got = transport.advance(now);
    for (auto &u : got) {
      if (std::isfinite(last) && u.timestamp - last > 2.)
        close_tail(now, origin);
      last = u.timestamp;
      feature_state.append(u);
    }
    peak_units = std::max(peak_units, units.size());
    if (units.size() > 65536)
      throw std::runtime_error("IoT history memory guard");
    int stable = offset + (int)feature_state.stable_prefix(now - .5);
    while (stable >= owned + 256 + 128) {
      process_core(owned + 256, owned + 256 + 128);
      packet_closures++;
      publish(now, origin);
    }
    if (offset + (int)units.size() > owned && now - .5 - last > 2.)
      close_tail(now, origin);
    prune();
  }
  void emit_wait_state() const {
    int total = offset + (int)units.size();
    std::cout << "{\"type\":\"iot_wait_state\",\"stream\":" << stream
              << ",\"observed_units\":" << total
              << ",\"processed_anchor_units\":" << owned
              << ",\"unprocessed_anchor_units\":" << total - owned
              << ",\"pending_candidates\":" << pending.size()
              << ",\"next_core_required_units\":" << owned + 384
              << ",\"quiet_closures\":" << quiet_closures
              << ",\"eof_closures\":0}\n";
  }
};
