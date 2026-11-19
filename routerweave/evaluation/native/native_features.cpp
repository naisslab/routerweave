#include "native_iot.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace rwiot {
namespace {
struct Burst {
  std::vector<int> ids;
};

double mean(const std::vector<double> &values) {
  double sum = 0;
  for (double value : values)
    sum += value;
  return sum / static_cast<double>(values.size());
}

double population_std(const std::vector<double> &values, double average) {
  double sum = 0;
  for (double value : values) {
    double delta = value - average;
    sum += delta * delta;
  }
  return std::sqrt(sum / static_cast<double>(values.size()));
}

double quantile(const std::vector<double> &sorted, double q) {
  const double position = static_cast<double>(sorted.size() - 1) * q;
  const size_t lower = static_cast<size_t>(position);
  const size_t upper = std::min(lower + 1, sorted.size() - 1);
  const double fraction = position - static_cast<double>(lower);
  // NumPy's default linear interpolation uses this form on either side
  // of the midpoint to avoid unnecessary loss of precision.
  const double difference = sorted[upper] - sorted[lower];
  return fraction < 0.5 ? sorted[lower] + difference * fraction
                        : sorted[upper] - difference * (1.0 - fraction);
}

Vec flat_features(const std::vector<Unit> &packets, const Features &source,
                  std::vector<int> ids) {
  if (ids.empty())
    throw std::invalid_argument("An empty group has no features");
  std::sort(ids.begin(), ids.end(), [&](int a, int b) {
    if (packets[a].timestamp != packets[b].timestamp)
      return packets[a].timestamp < packets[b].timestamp;
    return a < b;
  });
  ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
  std::vector<double> sizes, gaps;
  sizes.reserve(ids.size());
  gaps.reserve(ids.size() - 1);
  std::map<int, std::set<int>> directions;
  std::set<int> groups;
  double total = 0, outgoing_bytes = 0;
  size_t outgoing = 0, tcp = 0, udp = 0, direction_changes = 0,
         flow_changes = 0;
  for (size_t k = 0; k < ids.size(); ++k) {
    const Unit &packet = packets[ids[k]];
    const double size = static_cast<double>(packet.length);
    sizes.push_back(size);
    total += size;
    if (packet.direction == 1) {
      ++outgoing;
      outgoing_bytes += size;
    }
    tcp += packet.udp == 0;
    udp += packet.udp == 1;
    directions[packet.flow].insert(packet.direction);
    groups.insert(source.bursts[ids[k]]);
    if (k) {
      const Unit &previous = packets[ids[k - 1]];
      gaps.push_back((packet.timestamp - previous.timestamp) * 1000.0);
      direction_changes += packet.direction != previous.direction;
      flow_changes += packet.flow != previous.flow;
    }
  }
  const double count = static_cast<double>(ids.size());
  const double average = mean(sizes);
  const double stddev = population_std(sizes, average);
  std::sort(sizes.begin(), sizes.end());
  size_t bidirectional = 0;
  for (const auto &entry : directions)
    bidirectional += entry.second.size() == 2;
  const double gap_average = gaps.empty() ? 0 : mean(gaps);
  const double gap_stddev =
      gaps.empty() ? 0 : population_std(gaps, gap_average);
  const double gap_maximum =
      gaps.empty() ? 0 : *std::max_element(gaps.begin(), gaps.end());
  const double pairs = static_cast<double>(ids.size() - 1);
  const Unit &first = packets[ids.front()];
  const Unit &last = packets[ids.back()];
  const double values[] = {
      std::log1p(count),
      std::log1p(total),
      std::log1p((last.timestamp - first.timestamp) * 1000.0),
      static_cast<double>(outgoing) / count,
      outgoing_bytes / std::max(1.0, total),
      std::log1p(static_cast<double>(directions.size())),
      std::log1p(static_cast<double>(groups.size())),
      static_cast<double>(tcp) / count,
      static_cast<double>(udp) / count,
      std::log1p(sizes.front()),
      std::log1p(sizes.back()),
      std::log1p(average),
      std::log1p(stddev),
      std::log1p(quantile(sizes, 0.25)),
      std::log1p(quantile(sizes, 0.5)),
      std::log1p(quantile(sizes, 0.75)),
      gaps.empty() ? 0 : std::log1p(gap_average),
      gaps.empty() ? 0 : std::log1p(gap_stddev),
      gaps.empty() ? 0 : std::log1p(gap_maximum),
      pairs ? static_cast<double>(direction_changes) / pairs : 0,
      pairs ? static_cast<double>(flow_changes) / pairs : 0,
      static_cast<double>(bidirectional) /
          static_cast<double>(directions.size()),
      static_cast<double>(first.direction),
      static_cast<double>(last.direction)};
  Vec result(40, 0);
  for (size_t i = 0; i < 24; ++i)
    result[i] = static_cast<float>(values[i]);
  const size_t edges = std::min<size_t>(8, ids.size());
  for (size_t k = 0; k < edges; ++k) {
    const Unit &a = packets[ids[k]];
    const Unit &b = packets[ids[ids.size() - edges + k]];
    result[24 + k] = static_cast<float>(
        a.direction * std::log1p(static_cast<double>(a.length)));
    result[40 - edges + k] = static_cast<float>(
        b.direction * std::log1p(static_cast<double>(b.length)));
  }
  for (float value : result)
    if (!std::isfinite(value))
      throw std::runtime_error("Non-finite group feature");
  return result;
}
} // namespace

Features make_features(const std::vector<Unit> &packets, double gap) {
  if (!std::isfinite(gap) || gap <= 0)
    throw std::invalid_argument("Positive finite burst gap/span required");
  Features result;
  result.n = static_cast<int>(packets.size());
  result.x.resize(packets.size() * 10, 0);
  result.flows.resize(packets.size(), 0);
  result.bursts.resize(packets.size(), 0);
  std::map<int, int> aliases;
  std::map<int, double> previous;
  std::map<int, std::vector<int>> flow_ids;
  for (size_t i = 0; i < packets.size(); ++i) {
    const Unit &p = packets[i];
    auto alias = aliases.find(p.flow);
    if (alias == aliases.end())
      alias = aliases.emplace(p.flow, static_cast<int>(aliases.size())).first;
    result.flows[i] = alias->second;
    const auto preceding = previous.find(p.flow);
    const double prior =
        preceding == previous.end() ? p.timestamp : preceding->second;
    float *x = result.x.data() + i * 10;
    x[0] = static_cast<float>(std::log1p(static_cast<double>(p.length)));
    x[1] = static_cast<float>(p.direction);
    x[2] = static_cast<float>(p.udp);
    x[3] = static_cast<float>(std::log1p(
        std::max(0.0, p.timestamp - packets[i ? i - 1 : 0].timestamp) *
        1000.0));
    x[4] = static_cast<float>(
        std::log1p(std::max(0.0, p.timestamp - prior) * 1000.0));
    previous[p.flow] = p.timestamp;
    if (p.length > 0 && (p.direction == -1 || p.direction == 1) &&
        (p.udp == 0 || p.udp == 1))
      flow_ids[p.flow].push_back(static_cast<int>(i));
  }
  std::vector<Burst> units;
  for (const auto &flow : flow_ids) {
    std::vector<Burst> groups;
    for (int i : flow.second) {
      bool same = false;
      if (!groups.empty()) {
        const auto &ids = groups.back().ids;
        if (packets[i].timestamp < packets[ids.back()].timestamp)
          throw std::invalid_argument(
              "Packets must be chronological per connection");
        same = packets[i].timestamp - packets[ids.back()].timestamp <= gap &&
               packets[i].timestamp - packets[ids.front()].timestamp < 5.0;
      }
      if (!same)
        groups.push_back(Burst{});
      groups.back().ids.push_back(i);
    }
    for (auto &group : groups)
      units.push_back(std::move(group));
  }
  std::sort(units.begin(), units.end(), [&](const Burst &a, const Burst &b) {
    const double as = packets[a.ids.front()].timestamp,
                 bs = packets[b.ids.front()].timestamp;
    if (as != bs)
      return as < bs;
    const double ae = packets[a.ids.back()].timestamp,
                 be = packets[b.ids.back()].timestamp;
    if (ae != be)
      return ae < be;
    return a.ids.front() < b.ids.front();
  });
  for (size_t j = 0; j < units.size(); ++j) {
    const auto &ids = units[j].ids;
    const double start = packets[ids.front()].timestamp;
    const double duration = packets[ids.back()].timestamp - start;
    for (size_t k = 0; k < ids.size(); ++k) {
      const int i = ids[k];
      result.bursts[i] = static_cast<int>(j);
      float *x = result.x.data() + static_cast<size_t>(i) * 10;
      x[5] = static_cast<float>(std::log1p(static_cast<double>(ids.size())));
      x[6] = static_cast<float>(
          static_cast<double>(k) /
          static_cast<double>(std::max<size_t>(1, ids.size() - 1)));
      x[7] = static_cast<float>(
          std::log1p(std::max(0.0, packets[i].timestamp - start) * 1000.0));
      x[8] = static_cast<float>(std::log1p(std::max(0.0, duration) * 1000.0));
      x[9] = k == 0 ? 1.0f : 0.0f;
    }
  }
  return result;
}

Row make_row(const std::vector<Unit> &packets, const Features &source,
             const std::vector<int> &members, int device) {
  if (source.n != static_cast<int>(packets.size()) ||
      source.x.size() != packets.size() * 10 ||
      source.flows.size() != packets.size() ||
      source.bursts.size() != packets.size())
    throw std::invalid_argument(
        "Source feature dimensions do not match packets");
  std::vector<int> ids = members;
  std::sort(ids.begin(), ids.end());
  ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
  if (ids.empty())
    throw std::invalid_argument("Empty candidate");
  if (ids.front() < 0 || static_cast<size_t>(ids.back()) >= packets.size())
    throw std::out_of_range("Candidate member outside packet sequence");
  Row result;
  result.n = static_cast<int>(ids.size());
  result.device = device;
  result.tokens.resize(ids.size() * 12, 0);
  std::set<int> directions, flows;
  for (size_t k = 0; k < ids.size(); ++k) {
    const int i = ids[k];
    std::copy_n(source.x.data() + static_cast<size_t>(i) * 10, 10,
                result.tokens.data() + k * 12);
    if (k) {
      result.tokens[k * 12 + 10] =
          source.flows[i] == source.flows[ids[k - 1]] ? 1.0f : 0.0f;
      result.tokens[k * 12 + 11] =
          source.bursts[i] == source.bursts[ids[k - 1]] ? 1.0f : 0.0f;
    }
    directions.insert(packets[i].direction);
    flows.insert(packets[i].flow);
  }
  result.flat = flat_features(packets, source, ids);
  const double start = packets[ids.front()].timestamp;
  auto history_start = std::lower_bound(
      packets.begin(), packets.end(), start - 5.0,
      [](const Unit &packet, double time) { return packet.timestamp < time; });
  std::vector<int> history;
  const int begin = static_cast<int>(history_start - packets.begin());
  for (int i = begin; i < ids.front(); ++i)
    history.push_back(i);
  result.context =
      history.empty() ? Vec(40, 0) : flat_features(packets, source, history);
  const double available =
      std::min(5.0, std::max(0.0, start - packets.front().timestamp));
  result.context.push_back(static_cast<float>(std::log1p(available * 1000.0)));
  result.context.push_back(history.empty() ? 0.0f : 1.0f);
  const double count = static_cast<double>(ids.size());
  result.quality = {
      static_cast<float>(count / (count + 16.0)),
      directions.size() == 2 ? 1.0f : 0.0f,
      static_cast<float>(static_cast<double>(flows.size()) / count)};
  return result;
}
} // namespace rwiot
