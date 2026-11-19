#include "native_baselines.h"

#include <algorithm>
#include <cmath>
#include <functional>
#include <map>
#include <stdexcept>
#include <tuple>

namespace rwbase {
namespace {
uint32_t read32(const uint8_t *p, bool little) {
  if (little)
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
uint16_t read16(const uint8_t *p, bool little = false) {
  return little
             ? static_cast<uint16_t>(p[0] | (static_cast<unsigned>(p[1]) << 8))
             : static_cast<uint16_t>((static_cast<unsigned>(p[0]) << 8) | p[1]);
}
using FrameVisitor =
    std::function<void(double, uint32_t, const uint8_t *, size_t)>;

void visit_frames(const Bytes &data, const FrameVisitor &visit) {
  if (data.size() < 4)
    throw std::invalid_argument("Unsupported capture format");
  const uint32_t magic = read32(data.data(), false);
  if (magic == 0x0a0d0d0au) {
    size_t offset = 0;
    bool little = true;
    std::vector<double> interfaces;
    while (offset + 12 <= data.size()) {
      const auto *block = data.data() + offset;
      if (read32(block, false) == 0x0a0d0d0au) {
        little = read32(block + 8, false) == 0x4d3c2b1au;
        interfaces.clear();
      }
      const uint32_t kind = read32(block, little),
                     length = read32(block + 4, little);
      if (length < 12 || length > data.size() - offset)
        break;
      if (kind == 1) {
        if (length < 16 || read16(block + 8, little) != 1)
          throw std::invalid_argument("Only Ethernet captures are supported");
        double resolution = 1e6;
        size_t cursor = 16;
        while (cursor + 4 <= length - 4) {
          const uint16_t code = read16(block + cursor, little);
          const uint16_t size = read16(block + cursor + 2, little);
          if (code == 0)
            break;
          if (code == 9) {
            if (cursor + 4 >= length)
              throw std::invalid_argument("Truncated PCAPNG option");
            const uint8_t value = block[cursor + 4];
            resolution = value & 128 ? std::pow(2.0, value & 127)
                                     : std::pow(10.0, value);
          }
          cursor += 4 + size + ((4 - size % 4) % 4);
        }
        interfaces.push_back(resolution);
      } else if (kind == 6) {
        if (length < 28)
          throw std::invalid_argument("Truncated PCAPNG packet header");
        const uint32_t interface = read32(block + 8, little);
        if (interface >= interfaces.size())
          throw std::invalid_argument("Unknown PCAPNG interface");
        const uint64_t ticks =
            (static_cast<uint64_t>(read32(block + 12, little)) << 32) |
            read32(block + 16, little);
        const uint32_t captured = read32(block + 20, little),
                       wire = read32(block + 24, little);
        // Python slicing is bounded by the complete capture, including
        // malformed blocks whose declared capture length extends farther.
        const size_t available = data.size() - offset - 28;
        visit(static_cast<double>(ticks) / interfaces[interface], wire,
              block + 28, std::min<size_t>(captured, available));
      }
      offset += length;
    }
    return;
  }
  const bool little = magic == 0xd4c3b2a1u || magic == 0x4d3cb2a1u;
  if (!little && magic != 0xa1b2c3d4u && magic != 0xa1b23c4du)
    throw std::invalid_argument("Unsupported capture format");
  if (data.size() < 24 || read32(data.data() + 20, little) != 1)
    throw std::invalid_argument("Only Ethernet captures are supported");
  const double fraction =
      magic == 0x4d3cb2a1u || magic == 0xa1b23c4du ? 1e9 : 1e6;
  size_t offset = 24;
  while (offset + 16 <= data.size()) {
    const auto *header = data.data() + offset;
    const double timestamp =
        static_cast<double>(read32(header, little)) +
        static_cast<double>(read32(header + 4, little)) / fraction;
    const uint32_t captured = read32(header + 8, little),
                   wire = read32(header + 12, little);
    offset += 16;
    visit(timestamp, wire, data.data() + offset,
          std::min<size_t>(captured, data.size() - offset));
    if (captured > data.size() - offset)
      break;
    offset += captured;
  }
}

// Frozen to the local Python 3.12 ipaddress.IPv4Address constants used by
// baseline_matrix.read_pcap. In particular, 192.0.0.0/29 is not a /24.
bool private_address(uint32_t ip) {
  struct Network {
    uint32_t address, mask;
  };
  static constexpr Network networks[] = {
      {0x00000000u, 0xff000000u}, {0x0a000000u, 0xff000000u},
      {0x7f000000u, 0xff000000u}, {0xa9fe0000u, 0xffff0000u},
      {0xac100000u, 0xfff00000u}, {0xc0000000u, 0xfffffff8u},
      {0xc00000aau, 0xfffffffeu}, {0xc0000200u, 0xffffff00u},
      {0xc0a80000u, 0xffff0000u}, {0xc6120000u, 0xfffe0000u},
      {0xc6336400u, 0xffffff00u}, {0xcb007100u, 0xffffff00u},
      {0xf0000000u, 0xf0000000u}, {0xffffffffu, 0xffffffffu}};
  for (const auto &network : networks)
    if ((ip & network.mask) == network.address)
      return true;
  return false;
}

// NumPy's contiguous float64 add reduction uses eight accumulators and a
// 128-element pairwise block. Retain that reduction order for the moments.
double pairwise_sum(const double *values, size_t n) {
  if (n < 8) {
    double result = -0.0;
    for (size_t i = 0; i < n; ++i)
      result += values[i];
    return result;
  }
  if (n <= 128) {
    double accumulators[8];
    for (size_t i = 0; i < 8; ++i)
      accumulators[i] = values[i];
    size_t i = 8;
    for (; i < n - n % 8; i += 8)
      for (size_t j = 0; j < 8; ++j)
        accumulators[j] += values[i + j];
    double result = ((accumulators[0] + accumulators[1]) +
                     (accumulators[2] + accumulators[3])) +
                    ((accumulators[4] + accumulators[5]) +
                     (accumulators[6] + accumulators[7]));
    for (; i < n; ++i)
      result += values[i];
    return result;
  }
  size_t half = n / 2;
  half -= half % 8;
  return pairwise_sum(values, half) + pairwise_sum(values + half, n - half);
}

double average(const std::vector<double> &values) {
  return pairwise_sum(values.data(), values.size()) /
         static_cast<double>(values.size());
}

double median(std::vector<double> values) {
  std::sort(values.begin(), values.end());
  const size_t middle = values.size() / 2;
  return values.size() % 2 ? values[middle]
                           : (values[middle - 1] + values[middle]) / 2.0;
}

std::pair<double, double> moments(const std::vector<double> &values) {
  const double mean = average(values);
  std::vector<double> second(values.size()), third(values.size()),
      fourth(values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    const double centered = values[i] - mean;
    second[i] = centered * centered;
    third[i] = std::pow(centered, 3.0);
    fourth[i] = std::pow(centered, 4.0);
  }
  const double variance = average(second);
  if (variance <= 0)
    return {0, 0};
  return {average(third) / std::pow(variance, 1.5),
          average(fourth) / (variance * variance) - 3.0};
}

void append_burst(RFFeatures &result, const RFData &data,
                  const std::vector<size_t> &ids, size_t first, size_t end) {
  const size_t n = end - first;
  if (n < 2)
    return;
  std::vector<double> sizes(n), delta(n, 0);
  double outgoing_external_sum = 0, incoming_external_sum = 0;
  double outgoing_local_sum = 0, incoming_local_sum = 0;
  size_t outgoing_external = 0, incoming_external = 0, outgoing_local = 0,
         incoming_local = 0;
  for (size_t k = 0; k < n; ++k) {
    const size_t i = ids[first + k];
    const double size = static_cast<double>(data.size[i]);
    sizes[k] = size;
    if (k)
      delta[k] = data.t[i] - data.t[ids[first + k - 1]];
    const bool out = data.direction[i] == 1, local = data.local[i] != 0;
    if (out && !local) {
      ++outgoing_external;
      outgoing_external_sum += size;
    } else if (!out && !local) {
      ++incoming_external;
      incoming_external_sum += size;
    } else if (out) {
      ++outgoing_local;
      outgoing_local_sum += size;
    } else {
      ++incoming_local;
      incoming_local_sum += size;
    }
  }
  const double size_mean = average(sizes), size_median = median(sizes);
  std::vector<double> absolute_deviations(n), squared_delta(n);
  const double delta_mean = average(delta);
  for (size_t i = 0; i < n; ++i) {
    absolute_deviations[i] = std::abs(sizes[i] - size_median);
    const double centered = delta[i] - delta_mean;
    squared_delta[i] = centered * centered;
  }
  const auto size_moments = moments(sizes), delta_moments = moments(delta);
  const double values[] = {
      size_mean,
      *std::min_element(sizes.begin(), sizes.end()),
      *std::max_element(sizes.begin(), sizes.end()),
      median(absolute_deviations) / 0.6744897501960817,
      size_moments.first,
      size_moments.second,
      delta_mean,
      pairwise_sum(squared_delta.data(), n) / static_cast<double>(n - 1),
      median(delta),
      delta_moments.second,
      delta_moments.first,
      static_cast<double>(n),
      static_cast<double>(incoming_external),
      static_cast<double>(outgoing_external),
      static_cast<double>(incoming_external + outgoing_external),
      static_cast<double>(incoming_local + outgoing_local),
      static_cast<double>(incoming_local),
      static_cast<double>(outgoing_local),
      outgoing_external
          ? outgoing_external_sum / static_cast<double>(outgoing_external)
          : 0,
      incoming_external
          ? incoming_external_sum / static_cast<double>(incoming_external)
          : 0,
      outgoing_local ? outgoing_local_sum / static_cast<double>(outgoing_local)
                     : 0,
      incoming_local ? incoming_local_sum / static_cast<double>(incoming_local)
                     : 0};
  for (double value : values)
    result.x.push_back(static_cast<float>(value));
  result.intervals.emplace_back(data.t[ids[first]], data.t[ids[end - 1]]);
}
} // namespace

RFData rf_data(const Bytes &pcap, const Target &target) {
  RFData result;
  using Key = std::tuple<int, uint32_t, int, int>;
  std::map<Key, int32_t> flows;
  std::map<uint32_t, uint8_t> private_ips;
  visit_frames(pcap, [&](double timestamp, uint32_t wire, const uint8_t *frame,
                         size_t length) {
    if (length < 34)
      return;
    uint16_t ether = read16(frame + 12);
    size_t base = 14;
    if (ether == 0x8100) {
      ether = read16(frame + 16);
      base = 18;
    }
    if (ether != 0x0800 || frame[base] >> 4 != 4 || length < base + 20)
      return;
    const int protocol = frame[base + 9];
    if (protocol != 6 && protocol != 17)
      return;
    const size_t header = (frame[base] & 15) * 4;
    const uint32_t src = read32(frame + base + 12, false),
                   dst = read32(frame + base + 16, false);
    int direction;
    if (target.use_mac) {
      direction = std::equal(target.mac.begin(), target.mac.end(), frame + 6)
                      ? 1
                  : std::equal(target.mac.begin(), target.mac.end(), frame) ? -1
                                                                            : 0;
    } else
      direction = src == target.ip ? 1 : dst == target.ip ? -1 : 0;
    if (!direction || length < base + header + 4)
      return;
    const int sport = read16(frame + base + header),
              dport = read16(frame + base + header + 2);
    const int total = read16(frame + base + 2);
    int transport = 8;
    if (protocol == 6) {
      if (length < base + header + 13)
        return;
      transport = (frame[base + header + 12] >> 4) * 4;
    }
    const bool out = direction == 1;
    const uint32_t remote = out ? dst : src;
    const Key key{protocol, remote, out ? sport : dport, out ? dport : sport};
    auto flow = flows.find(key);
    if (flow == flows.end())
      flow = flows.emplace(key, static_cast<int32_t>(flows.size())).first;
    auto local = private_ips.find(remote);
    if (local == private_ips.end())
      local =
          private_ips.emplace(remote, private_address(remote) ? 1 : 0).first;
    result.t.push_back(timestamp);
    result.size.push_back(static_cast<int32_t>(wire));
    result.payload.push_back(
        std::max(total - static_cast<int>(header) - transport, 0));
    result.flow.push_back(flow->second);
    result.direction.push_back(static_cast<int8_t>(direction));
    result.local.push_back(local->second);
  });
  return result;
}

RFFeatures rf_features(const RFData &data, double start, double end) {
  const size_t count = data.t.size();
  if (data.size.size() != count || data.payload.size() != count ||
      data.flow.size() != count || data.direction.size() != count ||
      data.local.size() != count)
    throw std::invalid_argument(
        "Inconsistent BehavIoT packet array dimensions");
  std::map<int32_t, std::vector<size_t>> flows;
  // Windowing precedes burst construction, including at the 30-second edges.
  for (size_t i = 0; i < count; ++i)
    if (data.t[i] >= start && data.t[i] < end)
      flows[data.flow[i]].push_back(i);
  RFFeatures result;
  for (auto &entry : flows) {
    auto &ids = entry.second;
    if (ids.size() < 2)
      continue;
    std::stable_sort(ids.begin(), ids.end(),
                     [&](size_t a, size_t b) { return data.t[a] < data.t[b]; });
    size_t first = 0;
    for (size_t i = 1; i < ids.size(); ++i)
      if (data.t[ids[i]] - data.t[ids[i - 1]] > 1.0) {
        append_burst(result, data, ids, first, i);
        first = i;
      }
    append_burst(result, data, ids, first, ids.size());
  }
  return result;
}

int event_vote(const std::vector<int32_t> &labels,
               const std::vector<double> &probability, int fallback) {
  if (labels.size() != probability.size())
    throw std::invalid_argument("Vote dimensions differ");
  if (labels.empty())
    return fallback;
  std::map<int32_t, size_t> frequencies;
  for (int32_t label : labels)
    ++frequencies[label];
  size_t counter = 0;
  int chosen = labels.front();
  double best_probability = 0;
  for (size_t i = 0; i < labels.size(); ++i) {
    const size_t frequency = frequencies[labels[i]];
    if (frequency > counter ||
        (frequency == counter && probability[i] > best_probability)) {
      counter = frequency;
      chosen = labels[i];
      best_probability = probability[i];
    }
  }
  return chosen == -1 ? fallback : chosen;
}
} // namespace rwbase
