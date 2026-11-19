#pragma once
#include "native_iot.h"
#include <algorithm>
#include <cmath>
#include <set>
#include <stdexcept>
class StreamFeatures {
  struct Burst {
    double first, last;
    int count = 0;
  };
  struct Meta {
    std::array<float, 5> base;
    int bid, cid, brank, crank;
  };
  std::vector<Meta> metadata;
  std::map<int, double> previous_flow;
  double previous = -INFINITY;
  std::map<int, int> b_current, c_current;
  std::map<int, Burst> b_groups, c_groups;
  int b_serial = 0, c_serial = 0;
  static std::pair<int, int> append_burst(int flow, double time, double gap,
                                          std::map<int, int> &current,
                                          std::map<int, Burst> &groups,
                                          int &serial) {
    auto old = current.find(flow);
    int id = -1;
    if (old != current.end()) {
      auto &b = groups.at(old->second);
      if (time - b.last <= gap && time - b.first < 5.)
        id = old->second;
    }
    if (id < 0) {
      id = serial++;
      groups.emplace(id, Burst{time, time, 0});
      current[flow] = id;
    }
    auto &b = groups.at(id);
    int rank = b.count++;
    b.last = time;
    return {id, rank};
  }

public:
  std::vector<rwiot::Unit> units;
  void append(const rwiot::Unit &u) {
    double prior =
        previous_flow.count(u.flow) ? previous_flow[u.flow] : u.timestamp;
    auto b = append_burst(u.flow, u.timestamp, .5, b_current, b_groups,
                          b_serial),
         c = append_burst(u.flow, u.timestamp, 1., c_current, c_groups,
                          c_serial);
    metadata.push_back(
        {{float(std::log1p(double(u.length))), float(u.direction), float(u.udp),
          float(std::log1p(std::max(0., u.timestamp - (std::isfinite(previous)
                                                           ? previous
                                                           : u.timestamp)) *
                           1000.)),
          float(std::log1p(std::max(0., u.timestamp - prior) * 1000.))},
         b.first,
         c.first,
         b.second,
         c.second});
    previous = u.timestamp;
    previous_flow[u.flow] = u.timestamp;
    units.push_back(u);
    if (previous_flow.size() > 8192)
      throw std::runtime_error("IoT flow-history memory guard");
  }
  void prune(size_t n) {
    units.erase(units.begin(), units.begin() + n);
    metadata.erase(metadata.begin(), metadata.begin() + n);
    std::set<int> b_keep, c_keep;
    for (auto &m : metadata) {
      b_keep.insert(m.bid);
      c_keep.insert(m.cid);
    }
    for (auto &x : b_current)
      b_keep.insert(x.second);
    for (auto &x : c_current)
      c_keep.insert(x.second);
    for (auto it = b_groups.begin(); it != b_groups.end();)
      if (!b_keep.count(it->first))
        it = b_groups.erase(it);
      else
        ++it;
    for (auto it = c_groups.begin(); it != c_groups.end();)
      if (!c_keep.count(it->first))
        it = c_groups.erase(it);
      else
        ++it;
  }
  rwiot::Features features(double gap) const {
    if (gap != .5 && gap != 1.)
      throw std::runtime_error("Frozen burst gaps required");
    rwiot::Features f;
    f.n = (int)units.size();
    f.x.resize(units.size() * 10);
    f.flows.resize(units.size());
    f.bursts.resize(units.size());
    for (size_t k = 0; k < units.size(); k++) {
      auto &m = metadata[k];
      int id = gap == .5 ? m.bid : m.cid, rank = gap == .5 ? m.brank : m.crank;
      auto &group = (gap == .5 ? b_groups : c_groups).at(id);
      float *x = f.x.data() + k * 10;
      std::copy(m.base.begin(), m.base.end(), x);
      f.flows[k] = units[k].flow;
      f.bursts[k] = id;
      x[5] = float(std::log1p(double(group.count)));
      x[6] = float(double(rank) / double(std::max(1, group.count - 1)));
      x[7] = float(
          std::log1p(std::max(0., units[k].timestamp - group.first) * 1000.));
      x[8] = float(std::log1p(std::max(0., group.last - group.first) * 1000.));
      x[9] = rank == 0 ? 1.f : 0.f;
    }
    return f;
  }
  size_t stable_prefix(double watermark) const {
    for (size_t k = 0; k < metadata.size(); k++) {
      auto &b = c_groups.at(metadata[k].cid);
      if (watermark < std::min(b.last + 1., b.first + 5.))
        return k;
    }
    return metadata.size();
  }
};
