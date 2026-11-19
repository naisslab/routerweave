// Use the same native I/O, clocks and serialization utilities as RouterWeave.
#include "native_iot.cpp"
#include "native_baselines.h"
#include <set>
#include <thread>

namespace {
uint32_t ip_number(const std::string &text) {
  unsigned a, b, c, d;
  if (std::sscanf(text.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
      a > 255 || b > 255 || c > 255 || d > 255)
    throw std::runtime_error("Invalid target IPv4");
  return a << 24 | b << 16 | c << 8 | d;
}
rwbase::Target command_target(const char *text, const char *kind) {
  rwbase::Target target;
  target.use_mac = std::string(kind) == "mac";
  if (target.use_mac)
    target.mac = mac_address(text);
  else
    target.ip = ip_number(text);
  return target;
}
struct StoredFP {
  std::vector<int> tokens;
  int count = 0, label = 0, rank = 0;
};
struct FPModel {
  std::map<std::string, int> tokens;
  std::vector<StoredFP> fingerprints;
  std::vector<std::vector<int>> lookup;
  int fallback = 0;
  explicit FPModel(const std::string &path) {
    Reader reader(path);
    reader.magic("RWFP0001");
    auto nt = reader.number<uint32_t>();
    if (nt > 10000000)
      throw std::runtime_error("Invalid token dictionary");
    lookup.resize(nt);
    for (uint32_t i = 0; i < nt; i++)
      tokens.emplace(reader.text(), (int)i);
    auto nf = reader.number<uint32_t>();
    if (nf > 1000000)
      throw std::runtime_error("Invalid fingerprint count");
    for (uint32_t i = 0; i < nf; i++) {
      StoredFP fp;
      auto n = reader.number<uint32_t>();
      if (n > nt)
        throw std::runtime_error("Invalid stored fingerprint");
      for (uint32_t j = 0; j < n; j++) {
        auto token = reader.number<uint32_t>();
        if (token >= nt)
          throw std::runtime_error("Token outside dictionary");
        fp.tokens.push_back((int)token);
        lookup[token].push_back((int)i);
      }
      fp.count = reader.number<int32_t>();
      fp.label = reader.number<int32_t>();
      fp.rank = reader.number<uint32_t>();
      fingerprints.push_back(std::move(fp));
      if (fingerprints.back().count > fingerprints[fallback].count)
        fallback = (int)i;
    }
    reader.end();
    if (fingerprints.empty())
      throw std::runtime_error("Empty stored fingerprint model");
  }
  int predict(const rwbase::Fingerprint &query) const {
    std::vector<int> intersections(fingerprints.size(), 0);
    bool found = false;
    for (auto &token : query.tokens) {
      auto it = tokens.find(token);
      if (it == tokens.end())
        continue;
      for (int i : lookup[it->second]) {
        ++intersections[i];
        found = true;
      }
    }
    if (!found)
      return fingerprints[fallback].label;
    double best = -1;
    int index = -1;
    for (size_t i = 0; i < fingerprints.size(); i++)
      if (intersections[i]) {
        double score = (double)intersections[i] /
                       (query.tokens.size() + fingerprints[i].tokens.size() -
                        intersections[i]);
        if (score > best ||
            (score == best &&
             (index < 0 || fingerprints[i].rank < fingerprints[index].rank))) {
          best = score;
          index = (int)i;
        }
      }
    return fingerprints[index].label;
  }
};
} // namespace
