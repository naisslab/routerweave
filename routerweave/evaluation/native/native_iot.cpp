#include "native_iot.h"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#ifdef _WIN32
#include <psapi.h>
#include <windows.h>
#else
#include <sys/resource.h>
#include <time.h>
#endif

using namespace rwiot;
using Bytes = std::vector<uint8_t>;
static Bytes read_file(const std::string &path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream)
    throw std::runtime_error("Cannot open " + path);
  stream.seekg(0, std::ios::end);
  auto n = stream.tellg();
  if (n < 0 || n > 2000000000)
    throw std::runtime_error("Invalid input size");
  stream.seekg(0);
  Bytes data((size_t)n);
  if (n && !stream.read((char *)data.data(), n))
    throw std::runtime_error("Short input read");
  return data;
}
struct Reader {
  Bytes bytes;
  size_t at = 0;
  explicit Reader(const std::string &path) : bytes(read_file(path)) {}
  void take(void *target, size_t n) {
    if (n > bytes.size() - at)
      throw std::runtime_error("Truncated native input");
    if (n)
      std::memcpy(target, bytes.data() + at, n);
    at += n;
  }
  template <class T> T number() {
    T value;
    take(&value, sizeof(value));
    return value;
  }
  std::string text() {
    auto n = number<uint32_t>();
    if (n > 1000000)
      throw std::runtime_error("Invalid string length");
    std::string s(n, '\0');
    take(s.data(), n);
    return s;
  }
  void magic(const char *value) {
    char got[8];
    take(got, 8);
    if (std::memcmp(got, value, 8))
      throw std::runtime_error("Native format mismatch");
  }
  void end() {
    if (at != bytes.size())
      throw std::runtime_error("Trailing native input");
  }
};
static std::map<std::string, Model> load_models(const std::string &path) {
  Reader r(path);
  r.magic("RWIM0001");
  auto count = r.number<uint32_t>();
  if (count > 1000)
    throw std::runtime_error("Too many model records");
  std::map<std::string, Model> models;
  for (uint32_t i = 0; i < count; i++) {
    std::string model_name = r.text();
    auto nt = r.number<uint32_t>();
    Model model;
    if (nt > 1000)
      throw std::runtime_error("Too many tensors");
    for (uint32_t j = 0; j < nt; j++) {
      std::string name = r.text();
      auto nd = r.number<uint32_t>();
      Tensor tensor;
      size_t values = 1;
      if (nd > 8)
        throw std::runtime_error("Invalid tensor rank");
      for (uint32_t k = 0; k < nd; k++) {
        auto d = r.number<uint32_t>();
        if (d > 10000000 || values > 10000000 / (d ? d : 1))
          throw std::runtime_error("Invalid tensor dimensions");
        tensor.dims.push_back((int)d);
        values *= d;
      }
      tensor.values.resize(values);
      r.take(tensor.values.data(), values * sizeof(float));
      if (!model.emplace(name, std::move(tensor)).second)
        throw std::runtime_error("Duplicate tensor");
    }
    if (!models.emplace(model_name, std::move(model)).second)
      throw std::runtime_error("Duplicate model");
  }
  r.end();
  return models;
}
static std::array<uint8_t, 6> mac_address(const std::string &text) {
  std::array<uint8_t, 6> result{};
  unsigned value[6];
  if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &value[0], &value[1],
                  &value[2], &value[3], &value[4], &value[5]) != 6)
    throw std::runtime_error("Invalid MAC address");
  for (int i = 0; i < 6; i++) {
    if (value[i] > 255)
      throw std::runtime_error("Invalid MAC byte");
    result[i] = (uint8_t)value[i];
  }
  return result;
}
static float sigmoid(float v) {
  return 1.f / (1.f + std::exp(-std::clamp(v, -80.f, 80.f)));
}
static double wall_now() {
  return std::chrono::duration<double>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
static double cpu_now() {
#ifdef _WIN32
  FILETIME created, exited, kernel, user;
  GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
  ULARGE_INTEGER a, b;
  a.LowPart = kernel.dwLowDateTime;
  a.HighPart = kernel.dwHighDateTime;
  b.LowPart = user.dwLowDateTime;
  b.HighPart = user.dwHighDateTime;
  return (a.QuadPart + b.QuadPart) * 1e-7;
#else
  timespec value{};
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value);
  return value.tv_sec + value.tv_nsec * 1e-9;
#endif
}
static double peak_mib() {
#ifdef _WIN32
  PROCESS_MEMORY_COUNTERS info{};
  GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info));
  return info.PeakWorkingSetSize / 1048576.;
#else
  rusage info{};
  getrusage(RUSAGE_SELF, &info);
  return info.ru_maxrss / 1024.;
#endif
}
struct Proposal {
  int anchor;
  float score;
  std::vector<int> ids;
  Vec logits;
};
