#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace rwiot {
using Vec = std::vector<float>;
struct Tensor {
  std::vector<int> dims;
  Vec values;
};
using Model = std::map<std::string, Tensor>;
struct Unit {
  double timestamp;
  int length, direction, flow, udp, frame;
  std::vector<int> original_frames;
};
struct Features {
  int n = 0;
  Vec x;
  std::vector<int> flows, bursts;
};
struct Row {
  int n = 0, device = 0;
  Vec tokens, flat, context, quality;
};
struct Encoded {
  int n = 0, width = 32;
  Vec h, starts;
};
struct Event {
  double start, end;
  int label;
  float probability;
  std::vector<int> members;
};
std::vector<Unit> canonical_input(const std::vector<uint8_t> &pcap,
                                  const std::array<uint8_t, 6> &mac);
Features make_features(const std::vector<Unit> &packets, double gap);
Row make_row(const std::vector<Unit> &packets,
             const Features &one_second_features,
             const std::vector<int> &members, int device);
// x is already normalized, row-major n*10; all saved parameters are float32.
Encoded encode(const Model &model, const Vec &x, int n,
               const std::vector<int> &flows, const std::vector<int> &bursts);
Vec scores(const Model &model, const Encoded &encoded,
           const std::vector<int> &leaders, const Vec &times,
           const std::vector<int> &flows, const std::vector<int> &bursts,
           bool end);
Vec classify(const Model &model, const Row &row);
} // namespace rwiot

extern "C" {
void rw_gelu(const float *, int, float *);
int rw_bigru(const float *, const float *, const float *, const float *,
             const float *, const float *, int, int, float *);
}
