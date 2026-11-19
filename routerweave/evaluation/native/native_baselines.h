#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace rwbase {
using Bytes = std::vector<uint8_t>;
struct Target {
  std::array<uint8_t, 6> mac{};
  uint32_t ip = 0;
  bool use_mac = false;
};
struct Packet {
  double timestamp = 0;
  uint32_t src = 0, dst = 0, sequence = 0;
  int sport = 0, dport = 0, protocol = 0, wire = 0, payload = 0, flags = 0,
      frame = 0, direction = 0;
  size_t payload_offset = 0, payload_captured = 0;
};
// Baselines deliberately preserve the original IPv4/wire-packet view;
// they do not use RouterWeave's canonical TLS/deduplicated units.
std::vector<Packet> decode_packets(const Bytes &pcap, const Target &target);
double first_timestamp(const Bytes &pcap);
struct Flow {
  std::string destination, certificate;
  std::vector<double> timestamps;
  double start = 0, end = 0;
};
// Shared token encoding: N=None; D<dotted IPv4>:<port>; C<serial hex, no
// leading zeros>.
std::vector<std::vector<Flow>> flow_windows(const Bytes &pcap,
                                            const Target &target, int windows);
struct Fingerprint {
  std::vector<std::string> tokens;
  int n_flows = 0;
};
using FingerprintRef = std::shared_ptr<const Fingerprint>;
std::vector<FingerprintRef> fingerprints(const std::vector<Flow> &flows);
struct RFData {
  std::vector<double> t;
  std::vector<int32_t> size, payload, flow;
  std::vector<int8_t> direction;
  std::vector<uint8_t> local;
};
RFData rf_data(const Bytes &pcap, const Target &target);
struct RFFeatures {
  std::vector<float> x;
  std::vector<std::pair<double, double>> intervals;
};
// Filter [start,end) before burst construction, matching application windows.
RFFeatures rf_features(const RFData &data, double start, double end);
int event_vote(const std::vector<int32_t> &labels,
               const std::vector<double> &probability, int fallback);
} // namespace rwbase

extern "C" {
void *rf_load_model(const char *);
int rf_predict(void *, int, const float *, int, int32_t *, double *);
void rf_free_model(void *);
}
