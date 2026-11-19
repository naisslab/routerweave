// FlowPrint's unchanged destination/certificate clustering and fingerprinting.
#include "native_baselines.h"
#include <algorithm>
#include <cmath>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdexcept>

namespace rwbase {
namespace {
using Tokens = std::vector<std::string>;
using IndexSet = std::set<int>;
using Signature = std::set<long long>;
FingerprintRef empty_fp() { return std::make_shared<Fingerprint>(); }
bool present(const FingerprintRef &fp) { return fp && !fp->tokens.empty(); }
FingerprintRef make_fp(const std::set<std::string> &tokens, int count) {
  auto fp = std::make_shared<Fingerprint>();
  fp->tokens.assign(tokens.begin(), tokens.end());
  fp->n_flows = count;
  return fp;
}
double similarity(const Tokens &a, const Tokens &b) {
  size_t i = 0, j = 0, intersection = 0;
  while (i < a.size() && j < b.size()) {
    if (a[i] < b[j])
      ++i;
    else if (b[j] < a[i])
      ++j;
    else {
      ++intersection;
      ++i;
      ++j;
    }
  }
  return static_cast<double>(intersection) /
         std::max<size_t>(a.size() + b.size() - intersection, 1);
}
FingerprintRef merge(const FingerprintRef &a, const FingerprintRef &b) {
  auto fp = std::make_shared<Fingerprint>();
  std::set_union(a->tokens.begin(), a->tokens.end(), b->tokens.begin(),
                 b->tokens.end(), std::back_inserter(fp->tokens));
  fp->n_flows = a->n_flows + b->n_flows;
  return fp;
}
// Fingerprint equality/hash in the original uses token contents, not n_flows.
// Preserve the first representative of each token set, and the original
// partial mapping update (rather than replacing it with connected components).
void merge_fingerprints(std::vector<FingerprintRef> &predictions) {
  std::map<Tokens, FingerprintRef> distinct;
  std::vector<FingerprintRef> unique;
  for (const auto &fp : predictions)
    if (distinct.emplace(fp->tokens, fp).second)
      unique.push_back(fp);
  std::stable_sort(unique.begin(), unique.end(),
                   [](const auto &a, const auto &b) {
                     if (a->tokens.size() != b->tokens.size())
                       return a->tokens.size() < b->tokens.size();
                     return a->n_flows < b->n_flows;
                   });
  std::map<Tokens, FingerprintRef> mapping;
  for (size_t i = 0; i < unique.size(); ++i)
    for (size_t j = i + 1; j < unique.size(); ++j) {
      const auto &a = unique[i];
      const auto &b = unique[j];
      // Retain score_combinations' length prefilter, including its double
      // precision boundary at (1 - .9), before the actual Jaccard test.
      if (a->tokens.empty() ||
          static_cast<double>(b->tokens.size() - a->tokens.size()) /
                  std::max<size_t>(b->tokens.size(), 1) >
              (1. - .9) ||
          similarity(a->tokens, b->tokens) < .9)
        continue;
      auto ai = mapping.find(a->tokens), bi = mapping.find(b->tokens);
      auto combined = merge(ai == mapping.end() ? a : ai->second,
                            bi == mapping.end() ? b : bi->second);
      mapping[a->tokens] = combined;
      mapping[b->tokens] = combined;
    }
  for (auto &fp : predictions) {
    auto it = mapping.find(fp->tokens);
    if (it != mapping.end())
      fp = it->second;
  }
}
// Input indices are already in start-time order. Strict '<' makes ties select
// the following fingerprint, including the all-unassigned empty case.
void assign_nearest(const std::vector<Flow> &flows,
                    const std::vector<int> &order,
                    std::vector<FingerprintRef> &result) {
  size_t i = 0;
  while (i < order.size()) {
    if (present(result[i])) {
      ++i;
      continue;
    }
    size_t first = i;
    while (i < order.size() && !present(result[i]))
      ++i;
    size_t after = i;
    double before_time = first ? flows[order[first - 1]].start
                               : std::numeric_limits<double>::infinity();
    double after_time = after < order.size()
                            ? flows[order[after]].start
                            : std::numeric_limits<double>::infinity();
    FingerprintRef before_fp = first ? result[first - 1] : empty_fp();
    FingerprintRef after_fp = after < order.size() ? result[after] : empty_fp();
    for (size_t k = first; k < after; ++k) {
      double t = flows[order[k]].start;
      result[k] = std::abs(t - before_time) < std::abs(t - after_time)
                      ? before_fp
                      : after_fp;
    }
  }
}
IndexSet intersection(const IndexSet &a, const IndexSet &b) {
  IndexSet result;
  std::set_intersection(a.begin(), a.end(), b.begin(), b.end(),
                        std::inserter(result, result.end()));
  return result;
}
struct Destination {
  bool active = true;
  std::vector<int> samples;
  std::set<std::string> tokens;
};
std::vector<FingerprintRef> single_batch(const std::vector<Flow> &flows,
                                         const std::vector<int> &order) {
  std::vector<Destination> clusters;
  std::map<std::string, int> destinations, certificates;
  for (int index : order) {
    const auto &flow = flows[index];
    auto di = destinations.find(flow.destination),
         ci = certificates.find(flow.certificate);
    int d = di == destinations.end() ? -1 : di->second,
        c = ci == certificates.end() ? -1 : ci->second, chosen;
    if (c >= 0 && d >= 0 && c != d) {
      chosen = static_cast<int>(clusters.size());
      clusters.emplace_back();
      for (int old : {c, d}) {
        clusters[chosen].samples.insert(clusters[chosen].samples.end(),
                                        clusters[old].samples.begin(),
                                        clusters[old].samples.end());
        clusters[chosen].tokens.insert(clusters[old].tokens.begin(),
                                       clusters[old].tokens.end());
        clusters[old].active = false;
      }
      // Redirect every old destination/certificate identity to the new
      // NetworkDestination, matching Cluster.fit's merge branch.
      for (auto &item : destinations)
        if (item.second == c || item.second == d)
          item.second = chosen;
      for (auto &item : certificates)
        if (item.second == c || item.second == d)
          item.second = chosen;
    } else if (c >= 0 || d >= 0)
      chosen = c >= 0 ? c : d;
    else {
      chosen = static_cast<int>(clusters.size());
      clusters.emplace_back();
    }
    clusters[chosen].samples.push_back(index);
    clusters[chosen].tokens.insert(flow.destination);
    // None is excluded from the cluster lookup, but included in every
    // NetworkDestination's certificates and thus in fingerprint tokens.
    clusters[chosen].tokens.insert(flow.certificate);
    if (flow.destination != "N")
      destinations[flow.destination] = chosen;
    if (flow.certificate != "N")
      certificates[flow.certificate] = chosen;
  }
  double start = flows[order.front()].start;
  std::vector<Signature> signatures;
  std::vector<std::vector<int>> expansion;
  std::map<Signature, int> signature_index;
  // NetworkDestination identifiers increase with each creation/merge.
  // Python sorts these identifiers before inserting compressed graph nodes.
  for (size_t i = 0; i < clusters.size(); ++i)
    if (clusters[i].active) {
      Signature active;
      for (int flow : clusters[i].samples)
        for (double timestamp : flows[flow].timestamps)
          active.insert(
              static_cast<long long>(std::floor((timestamp - start) / 30.)));
      auto inserted =
          signature_index.emplace(active, static_cast<int>(signatures.size()));
      int node = inserted.first->second;
      if (inserted.second) {
        signatures.push_back(active);
        expansion.emplace_back();
      }
      expansion[node].push_back(static_cast<int>(i));
    }
  int n = static_cast<int>(signatures.size());
  std::vector<IndexSet> neighbours(n);
  for (int i = 0; i < n; ++i)
    for (int j = i + 1; j < n; ++j) {
      size_t equal = 0;
      auto a = signatures[i].begin(), b = signatures[j].begin();
      while (a != signatures[i].end() && b != signatures[j].end()) {
        if (*a < *b)
          ++a;
        else if (*b < *a)
          ++b;
        else {
          ++equal;
          ++a;
          ++b;
        }
      }
      size_t combined = signatures[i].size() + signatures[j].size() - equal;
      if (equal && static_cast<double>(equal) / combined >= .1) {
        neighbours[i].insert(j);
        neighbours[j].insert(i);
      }
    }
  std::vector<FingerprintRef> fingerprints;
  // Bron-Kerbosch with pivoting enumerates every maximal compressed clique;
  // singleton compressed nodes may expand to multiple destinations.
  std::function<void(std::vector<int> &, IndexSet, IndexSet)> visit;
  visit = [&](std::vector<int> &clique, IndexSet candidates,
              IndexSet excluded) {
    if (candidates.empty() && excluded.empty()) {
      std::set<std::string> tokens;
      int cluster_count = 0, flow_count = 0;
      for (int node : clique)
        for (int cluster : expansion[node]) {
          ++cluster_count;
          flow_count += static_cast<int>(clusters[cluster].samples.size());
          tokens.insert(clusters[cluster].tokens.begin(),
                        clusters[cluster].tokens.end());
        }
      if (cluster_count > 1)
        fingerprints.push_back(make_fp(tokens, flow_count));
      return;
    }
    int pivot = -1;
    size_t largest = 0;
    IndexSet both = candidates;
    both.insert(excluded.begin(), excluded.end());
    for (int node : both) {
      size_t count = intersection(candidates, neighbours[node]).size();
      if (pivot < 0 || count > largest) {
        pivot = node;
        largest = count;
      }
    }
    IndexSet branches = candidates;
    if (pivot >= 0)
      for (int node : neighbours[pivot])
        branches.erase(node);
    for (int node : branches) {
      clique.push_back(node);
      visit(clique, intersection(candidates, neighbours[node]),
            intersection(excluded, neighbours[node]));
      clique.pop_back();
      candidates.erase(node);
      excluded.insert(node);
    }
  };
  IndexSet candidates;
  for (int i = 0; i < n; ++i)
    candidates.insert(i);
  std::vector<int> clique;
  visit(clique, candidates, {});
  std::stable_sort(fingerprints.begin(), fingerprints.end(),
                   [](const auto &a, const auto &b) {
                     if (a->tokens.size() != b->tokens.size())
                       return a->tokens.size() < b->tokens.size();
                     return a->n_flows < b->n_flows;
                   });
  std::map<std::string, FingerprintRef> mapping;
  for (const auto &fp : fingerprints)
    for (const auto &token : fp->tokens)
      mapping[token] = fp;
  std::vector<FingerprintRef> result;
  result.reserve(order.size());
  for (int index : order) {
    auto it = mapping.find(flows[index].destination);
    if (it == mapping.end())
      it = mapping.find(flows[index].certificate);
    result.push_back(it == mapping.end() ? empty_fp() : it->second);
  }
  assign_nearest(flows, order, result);
  merge_fingerprints(result);
  return result;
}
} // namespace

std::vector<FingerprintRef> fingerprints(const std::vector<Flow> &flows) {
  if (flows.empty())
    return {};
  std::vector<int> order(flows.size());
  std::iota(order.begin(), order.end(), 0);
  for (const auto &flow : flows)
    if (!std::isfinite(flow.start) || !std::isfinite(flow.end))
      throw std::runtime_error("Nonfinite FlowPrint timestamp");
  std::stable_sort(order.begin(), order.end(), [&](int a, int b) {
    return flows[a].start < flows[b].start;
  });
  double low = flows[order.front()].start, high = flows[order.back()].start;
  int batch_count =
      std::max(1, static_cast<int>(std::ceil((high - low) / 300.)));
  if (low == high) {
    low -= .5;
    high += .5;
  }
  // np.histogram uses equally spaced edges over the observed min/max, so
  // batch widths need not be exactly 300 seconds. np.digitize excludes only
  // the final histogram edge and places equality into the following bin.
  std::vector<double> edges(batch_count);
  double step = (high - low) / batch_count;
  for (int i = 0; i < batch_count; ++i)
    edges[i] = low + static_cast<double>(i) * step;
  std::map<int, std::vector<int>> batches;
  for (int index : order) {
    int batch = static_cast<int>(
        std::upper_bound(edges.begin(), edges.end(), flows[index].start) -
        edges.begin());
    batches[batch].push_back(index);
  }
  std::vector<FingerprintRef> by_original(flows.size());
  for (const auto &batch : batches) {
    auto prediction = single_batch(flows, batch.second);
    for (size_t i = 0; i < batch.second.size(); ++i)
      by_original[batch.second[i]] = prediction[i];
  }
  std::vector<FingerprintRef> sorted;
  sorted.reserve(flows.size());
  for (int index : order)
    sorted.push_back(by_original[index]);
  merge_fingerprints(sorted);
  assign_nearest(flows, order, sorted);
  for (size_t i = 0; i < order.size(); ++i)
    by_original[order[i]] = sorted[i];
  return by_original;
}
} // namespace rwbase
