// Native execution of the saved EndMembers and NumericFiLM networks.
// Shapes, parameter values, activations and support masks follow
// numpy_models.py.
#include "native_iot.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace rwiot {
namespace {
const Tensor &tensor(const Model &m, const std::string &name) {
  auto it = m.find(name);
  if (it == m.end())
    throw std::runtime_error("Missing model tensor: " + name);
  return it->second;
}
void require(bool ok, const char *message) {
  if (!ok)
    throw std::runtime_error(message);
}
float dot(const float *a, const float *b, int n) {
#if defined(__aarch64__)
  float32x4_t acc = vdupq_n_f32(0.f);
  int i = 0;
  for (; i + 4 <= n; i += 4)
    acc = vaddq_f32(acc, vmulq_f32(vld1q_f32(a + i), vld1q_f32(b + i)));
  float result = vaddvq_f32(acc);
  for (; i < n; ++i)
    result += a[i] * b[i];
  return result;
#else
  float result = 0.f;
  for (int i = 0; i < n; ++i)
    result += a[i] * b[i];
  return result;
#endif
}

// Reuse each input load across four independent output dots. Each output
// retains the original NEON lane accumulation, reduction and scalar tail.
void four_output_affine_rows(const float *x, const float *w, const float *bias,
                             int rows, int in, int out, float *y) {
  for (int r = 0; r < rows; ++r) {
    int j = 0;
#if defined(__aarch64__)
    for (; j + 4 <= out; j += 4) {
      float32x4_t a = vdupq_n_f32(0.f), b = a, c = a, d = a;
      int k = 0;
      for (; k + 4 <= in; k += 4) {
        float32x4_t v = vld1q_f32(x + (size_t)r * in + k);
        a = vaddq_f32(a, vmulq_f32(v, vld1q_f32(w + (size_t)j * in + k)));
        b = vaddq_f32(b, vmulq_f32(v, vld1q_f32(w + (size_t)(j + 1) * in + k)));
        c = vaddq_f32(c, vmulq_f32(v, vld1q_f32(w + (size_t)(j + 2) * in + k)));
        d = vaddq_f32(d, vmulq_f32(v, vld1q_f32(w + (size_t)(j + 3) * in + k)));
      }
      float value[4] = {vaddvq_f32(a), vaddvq_f32(b), vaddvq_f32(c),
                        vaddvq_f32(d)};
      for (; k < in; ++k)
        for (int q = 0; q < 4; ++q)
          value[q] += x[(size_t)r * in + k] * w[(size_t)(j + q) * in + k];
      for (int q = 0; q < 4; ++q)
        y[(size_t)r * out + j + q] = value[q] + bias[j + q];
    }
#endif
    for (; j < out; ++j)
      y[(size_t)r * out + j] =
          dot(x + (size_t)r * in, w + (size_t)j * in, in) + bias[j];
  }
}

Vec affine(const Model &m, const Vec &x, int rows, const std::string &name) {
  const auto &w = tensor(m, name + ".weight");
  const auto &b = tensor(m, name + ".bias");
  require(w.dims.size() == 2, "Affine weight must be a matrix");
  int out = w.dims[0], in = w.dims[1];
  require(rows >= 0 && x.size() == static_cast<size_t>(rows) * in &&
              w.values.size() == static_cast<size_t>(out) * in &&
              b.values.size() == static_cast<size_t>(out),
          "Affine tensor shape mismatch");
  Vec y(static_cast<size_t>(rows) * out);
  four_output_affine_rows(x.data(), w.values.data(), b.values.data(), rows, in,
                          out, y.data());
  return y;
}
Vec gelu(Vec x) {
  rw_gelu(x.data(), static_cast<int>(x.size()), x.data());
  return x;
}
Vec relu(Vec x) {
  for (float &v : x)
    v = std::max(v, 0.f);
  return x;
}
float sigmoid(float x) {
  return 1.f / (1.f + std::exp(-std::max(-80.f, std::min(80.f, x))));
}
Vec softmax(Vec x) {
  require(!x.empty(), "Empty softmax");
  float largest = *std::max_element(x.begin(), x.end()), total = 0.f;
  for (float &v : x) {
    v = std::exp(v - largest);
    total += v;
  }
  for (float &v : x)
    v /= total;
  return x;
}
Vec concatenate(const Vec &a, const Vec &b) {
  Vec out = a;
  out.insert(out.end(), b.begin(), b.end());
  return out;
}
Vec normalize(const Vec &x, const Model &m, const std::string &prefix) {
  const auto &mean = tensor(m, prefix + "_mean").values;
  const auto &scale = tensor(m, prefix + "_scale").values;
  require(!mean.empty() && mean.size() == scale.size() &&
              x.size() % mean.size() == 0,
          "Normalization shape mismatch");
  Vec out(x.size());
  for (size_t i = 0; i < x.size(); ++i)
    out[i] = (x[i] - mean[i % mean.size()]) / scale[i % mean.size()];
  return out;
}
Vec sequence(const Model &m, const Vec &x, int n) {
  const auto &fw = tensor(m, "sequence.weight_hh_l0");
  const auto &bw = tensor(m, "sequence.weight_hh_l0_reverse");
  require(fw.dims.size() == 2 && fw.dims[0] == 3 * fw.dims[1] &&
              bw.dims == fw.dims,
          "GRU weight shape mismatch");
  // The input matrices use the same affine operation, but their bias names
  // follow PyTorch's recurrent-layer convention rather than '.bias'.
  int h = fw.dims[1];
  auto project = [&](const std::string &suffix) {
    const auto &w = tensor(m, "sequence.weight_ih_l0" + suffix);
    const auto &b = tensor(m, "sequence.bias_ih_l0" + suffix);
    require(w.dims.size() == 2 && w.dims[0] == 3 * h &&
                x.size() == static_cast<size_t>(n) * w.dims[1] &&
                b.values.size() == static_cast<size_t>(3 * h),
            "GRU input shape mismatch");
    int width = w.dims[1];
    Vec out(static_cast<size_t>(n) * 3 * h);
    four_output_affine_rows(x.data(), w.values.data(), b.values.data(), n,
                            width, 3 * h, out.data());
    return out;
  };
  Vec f = project(""), b = project("_reverse"),
      out(static_cast<size_t>(n) * 2 * h);
  int status = rw_bigru(f.data(), b.data(), fw.values.data(), bw.values.data(),
                        tensor(m, "sequence.bias_hh_l0").values.data(),
                        tensor(m, "sequence.bias_hh_l0_reverse").values.data(),
                        n, h, out.data());
  require(status == 0, "Native GRU execution failed");
  return out;
}
Vec group_pool(const Vec &x, int n, int width, const std::vector<int> &ids) {
  require(ids.size() == static_cast<size_t>(n),
          "Group identity shape mismatch");
  struct Group {
    Vec sum;
    int count = 0;
  };
  std::map<int, Group> groups;
  for (int i = 0; i < n; ++i) {
    auto &group = groups[ids[i]];
    if (group.sum.empty())
      group.sum.resize(width, 0.f);
    for (int j = 0; j < width; ++j)
      group.sum[j] += x[static_cast<size_t>(i) * width + j];
    ++group.count;
  }
  Vec out(x.size());
  for (int i = 0; i < n; ++i) {
    const auto &group = groups.at(ids[i]);
    for (int j = 0; j < width; ++j)
      out[static_cast<size_t>(i) * width + j] =
          static_cast<float>(static_cast<double>(group.sum[j]) / group.count);
  }
  return out;
}
Vec numeric_sizes(const Row &row) {
  static const double divisors[] = {2,   4,   8,   16,   32,  64,
                                    128, 256, 512, 1024, 2048};
  constexpr double pi = 3.141592653589793238462643383279502884;
  Vec out(static_cast<size_t>(row.n) * 27);
  std::map<int, double> last;
  double previous = 0;
  auto signed_log = [](double d) {
    return (d > 0 ? 1. : d < 0 ? -1. : 0.) * std::log1p(std::abs(d)) / 4.;
  };
  for (int i = 0; i < row.n; ++i) {
    // NumPy expm1/rint operate on float32 before conversion to float64.
    double size = static_cast<double>(
        std::nearbyint(std::expm1(row.tokens[static_cast<size_t>(i) * 12])));
    float raw_direction = row.tokens[static_cast<size_t>(i) * 12 + 1];
    int direction = raw_direction > 0 ? 1 : raw_direction < 0 ? -1 : 0;
    double same = last.count(direction) ? size - last[direction] : 0.;
    last[direction] = size;
    if (i == 0)
      previous = size;
    float *p = out.data() + static_cast<size_t>(i) * 27;
    for (int j = 0; j < 11; ++j) {
      double angle = (2 * pi * size) / divisors[j];
      p[j] = static_cast<float>(std::sin(angle));
      p[11 + j] = static_cast<float>(std::cos(angle));
    }
    double remainder = std::fmod(size, 16.);
    if (remainder < 0)
      remainder += 16.;
    p[22] = static_cast<float>(size / 1500.);
    p[23] = static_cast<float>(signed_log(size - previous));
    p[24] = static_cast<float>(signed_log(same));
    p[25] = static_cast<float>(remainder / 16.);
    p[26] = static_cast<float>(direction);
    previous = size;
  }
  return out;
}
} // namespace

Encoded encode(const Model &model, const Vec &x, int n,
               const std::vector<int> &flows, const std::vector<int> &bursts) {
  require(n > 0 && x.size() == static_cast<size_t>(n) * 10,
          "Encoder input shape mismatch");
  Vec h = gelu(affine(model, x, n, "encoder.0"));
  int width = tensor(model, "encoder.0.weight").dims[0];
  Vec flow = group_pool(h, n, width, flows),
      burst = group_pool(h, n, width, bursts),
      structure(static_cast<size_t>(n) * 3 * width);
  for (int i = 0; i < n; ++i) {
    std::copy_n(h.data() + static_cast<size_t>(i) * width, width,
                structure.data() + static_cast<size_t>(i) * 3 * width);
    std::copy_n(flow.data() + static_cast<size_t>(i) * width, width,
                structure.data() + static_cast<size_t>(i) * 3 * width + width);
    std::copy_n(burst.data() + static_cast<size_t>(i) * width, width,
                structure.data() + static_cast<size_t>(i) * 3 * width +
                    2 * width);
  }
  h = affine(model, structure, n, "structure");
  h = sequence(model, h, n);
  h = affine(model, h, n, "packet");
  Encoded result;
  result.n = n;
  result.width = tensor(model, "packet.weight").dims[0];
  result.h = std::move(h);
  result.starts = affine(model, result.h, n, "start_head");
  return result;
}

Vec scores(const Model &model, const Encoded &encoded,
           const std::vector<int> &leaders, const Vec &times,
           const std::vector<int> &flows, const std::vector<int> &bursts,
           bool end) {
  int n = encoded.n, width = encoded.width;
  require(n > 0 && encoded.h.size() == static_cast<size_t>(n) * width &&
              times.size() == static_cast<size_t>(n) &&
              flows.size() == static_cast<size_t>(n) &&
              bursts.size() == static_cast<size_t>(n),
          "Score input shape mismatch");
  std::string prefix = end ? "end_" : "";
  Vec selected(static_cast<size_t>(leaders.size()) * width);
  for (size_t i = 0; i < leaders.size(); ++i) {
    require(leaders[i] >= 0 && leaders[i] < n, "Invalid score leader");
    std::copy_n(encoded.h.data() + static_cast<size_t>(leaders[i]) * width,
                width, selected.data() + i * width);
  }
  Vec query = affine(model, selected, static_cast<int>(leaders.size()),
                     prefix + "query");
  Vec key = affine(model, encoded.h, n, prefix + "key");
  int query_width = tensor(model, prefix + "query.weight").dims[0];
  require(key.size() == static_cast<size_t>(n) * query_width,
          "Query/key shape mismatch");
  Vec out(static_cast<size_t>(leaders.size()) * n);
  // Relative MLP batches one leader at a time to bound temporary storage.
  for (size_t i = 0; i < leaders.size(); ++i) {
    int leader = leaders[i];
    Vec relative(static_cast<size_t>(n) * 5);
    for (int j = 0; j < n; ++j) {
      float dt = times[j] - times[leader];
      float *r = relative.data() + static_cast<size_t>(j) * 5;
      r[0] = std::log1p(std::abs(dt) * 1000.f);
      r[1] = dt > 0 ? 1.f : dt < 0 ? -1.f : 0.f;
      r[2] = static_cast<float>(
          std::log1p(static_cast<double>(std::abs(j - leader))));
      r[3] = flows[j] == flows[leader] ? 1.f : 0.f;
      r[4] = bursts[j] == bursts[leader] ? 1.f : 0.f;
    }
    Vec bias =
        affine(model, gelu(affine(model, relative, n, prefix + "relative.0")),
               n, prefix + "relative.2");
    for (int j = 0; j < n; ++j)
      out[i * n + j] =
          j < leader ? (end ? -1e9f : -20.f)
                     : dot(query.data() + i * query_width,
                           key.data() + static_cast<size_t>(j) * query_width,
                           query_width) /
                               std::sqrt(static_cast<float>(width)) +
                           bias[j];
  }
  return out;
}

Vec classify(const Model &model, const Row &row) {
  require(row.n > 0 && row.tokens.size() == static_cast<size_t>(row.n) * 12 &&
              row.flat.size() == 40 && row.context.size() == 42 &&
              row.quality.size() == 3,
          "Classifier row shape mismatch");
  Vec packet = gelu(
      affine(model, normalize(row.tokens, model, "token"), row.n, "packet.0"));
  Vec sizes = gelu(affine(model, numeric_sizes(row), row.n, "size_encoder.0"));
  int packet_width = tensor(model, "packet.0.weight").dims[0],
      size_width = tensor(model, "size_encoder.0.weight").dims[0];
  Vec mixed(static_cast<size_t>(row.n) * (packet_width + size_width));
  for (int i = 0; i < row.n; ++i) {
    float *p =
        mixed.data() + static_cast<size_t>(i) * (packet_width + size_width);
    std::copy_n(packet.data() + static_cast<size_t>(i) * packet_width,
                packet_width, p);
    std::copy_n(sizes.data() + static_cast<size_t>(i) * size_width, size_width,
                p + packet_width);
  }
  Vec encoded =
      sequence(model, gelu(affine(model, mixed, row.n, "mix.0")), row.n);
  int hidden_width = static_cast<int>(encoded.size() / row.n);
  Vec traffic(2 * hidden_width, 0.f);
  std::copy_n(encoded.data(), hidden_width, traffic.data() + hidden_width);
  for (int i = 0; i < row.n; ++i)
    for (int j = 0; j < hidden_width; ++j) {
      float value = encoded[static_cast<size_t>(i) * hidden_width + j];
      traffic[j] += value;
      traffic[hidden_width + j] = std::max(traffic[hidden_width + j], value);
    }
  for (int j = 0; j < hidden_width; ++j)
    traffic[j] /= static_cast<float>(row.n);
  traffic = concatenate(traffic, normalize(row.flat, model, "flat"));
  Vec context = normalize(row.context, model, "context");
  const auto &embedding = tensor(model, "device_embedding.weight");
  require(embedding.dims.size() == 2 && row.device >= 0 &&
              row.device < embedding.dims[0],
          "Classifier device out of range");
  context.insert(context.end(),
                 embedding.values.begin() +
                     static_cast<size_t>(row.device) * embedding.dims[1],
                 embedding.values.begin() +
                     static_cast<size_t>(row.device + 1) * embedding.dims[1]);
  Vec t = relu(affine(model, relu(affine(model, traffic, 1, "film.traffic.0")),
                      1, "film.traffic.2"));
  Vec c = relu(affine(model, relu(affine(model, context, 1, "film.context.0")),
                      1, "film.context.2"));
  Vec quality =
      affine(model, relu(affine(model, row.quality, 1, "film.quality.0")), 1,
             "film.quality.2");
  require(quality.size() == 1, "Classifier reliability must be scalar");
  float reliability = sigmoid(quality[0]);
  Vec modulation = affine(model, c, 1, "film.mod"),
      hidden = affine(model, t, 1, "film.first");
  require(modulation.size() == 2 * hidden.size(),
          "FiLM modulation shape mismatch");
  for (size_t i = 0; i < hidden.size(); ++i)
    hidden[i] = std::max(
        0.f, hidden[i] * (1.f + std::tanh(modulation[i]) * reliability) +
                 modulation[hidden.size() + i] * reliability);
  Vec routing = softmax(affine(model, concatenate(hidden, c), 1, "film.gate"));
  require(routing.size() == 4, "Classifier must contain four experts");
  Vec result;
  for (int i = 0; i < 4; ++i) {
    std::string prefix = "film.experts." + std::to_string(i);
    Vec expert =
        softmax(affine(model, relu(affine(model, hidden, 1, prefix + ".0")), 1,
                       prefix + ".3"));
    if (result.empty())
      result.resize(expert.size(), 0.f);
    require(expert.size() == result.size(), "Expert output shape mismatch");
    for (size_t j = 0; j < result.size(); ++j)
      result[j] += expert[j] * routing[i];
  }
  const auto &support = tensor(model, "support");
  require(support.dims.size() == 2 && row.device < support.dims[0] &&
              support.dims[1] == static_cast<int>(result.size()),
          "Support shape mismatch");
  float total = 0.f;
  for (size_t i = 0; i < result.size(); ++i) {
    if (support.values[static_cast<size_t>(row.device) * result.size() + i] ==
        0.f)
      result[i] = 0.f;
    total += result[i];
  }
  require(total > 0.f && std::isfinite(total),
          "Classifier support has no finite probability mass");
  for (float &value : result)
    value /= total;
  return result;
}
} // namespace rwiot
