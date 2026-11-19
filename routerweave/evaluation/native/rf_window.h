// Author s6_binary_predict.py:251--317, with explicit causal readiness.
#include <list>
struct RFWindowBurst {
  double start, end, ready, probability;
  int label;
  std::string name;
  std::vector<unsigned> frames;
};
struct RFWindow {
  struct Group {
    double bound;
    unsigned unfinished = 0;
    std::vector<RFWindowBurst> votes;
  };
  double epoch, length;
  unsigned emitted = 0;
  std::vector<RFWindowBurst> pending;
  std::list<Group> groups;
  std::map<unsigned, Group *> assigned;
  RFWindow(double e, const std::string &device) : epoch(e), length(5) {
    const std::set<std::string> longer = {"wyze-cam",    "ikettle",
                                          "echospot",    "dlink-camera",
                                          "ring-camera", "ring-doorbell"};
    if (longer.count(device))
      length = 35;
  }
  template <class ActiveFlows, class ClockType>
  void advance(double due, const ActiveFlows &flows, ClockType &clock) {
    // Route completed bursts to windows with already sealed membership.
    for (auto it = pending.begin(); it != pending.end();) {
      auto found = assigned.find(it->frames.front());
      if (found == assigned.end()) {
        ++it;
        continue;
      }
      found->second->votes.push_back(std::move(*it));
      found->second->unfinished--;
      assigned.erase(found);
      it = pending.erase(it);
    }
    for (;;) {
      double first = INFINITY;
      for (const auto &b : pending)
        first = std::min(first, b.start);
      for (const auto &item : flows) {
        const auto &a = item.second;
        if (a.data.t.size() >= 2 && !assigned.count(a.frames.front()))
          first = std::min(first, a.data.t.front());
      }
      if (!std::isfinite(first))
        break;
      double bound = std::floor(epoch + first) + length - epoch;
      if (due <= bound + 1e-9)
        break; // Include arrivals exactly on the boundary.
      bool uncertain = false;
      // A singleton can still become eligible and precede the current anchor.
      for (const auto &item : flows)
        if (item.second.data.t.size() < 2 &&
            item.second.data.t.front() <= bound + 1e-9)
          uncertain = true;
      if (uncertain)
        break;
      groups.push_back({bound, 0, {}});
      Group *group = &groups.back();
      for (auto it = pending.begin(); it != pending.end();)
        if (it->start <= bound + 1e-9) {
          group->votes.push_back(std::move(*it));
          it = pending.erase(it);
        } else
          ++it;
      for (const auto &item : flows) {
        const auto &a = item.second;
        if (a.data.t.size() >= 2 && a.data.t.front() <= bound + 1e-9 &&
            !assigned.count(a.frames.front())) {
          assigned.emplace(a.frames.front(), group);
          group->unfinished++;
        }
      }
    }
    // Independent windows may finish out of timestamp order.
    for (auto it = groups.begin(); it != groups.end();) {
      if (it->unfinished) {
        ++it;
        continue;
      }
      auto &votes = it->votes;
      std::sort(votes.begin(), votes.end(), [](const auto &a, const auto &b) {
        return std::tie(a.start, a.name, a.probability) <
               std::tie(b.start, b.name, b.probability);
      });
      if (votes.empty())
        throw std::runtime_error("Empty RF window");
      int chosen = votes.front().label, best = 0;
      double probability = 0, start = votes.front().start, end = start,
             ready = 0;
      std::vector<unsigned> frames;
      for (const auto &b : votes) {
        int count = 0;
        for (const auto &other : votes)
          if (other.label == b.label)
            count++;
        // Unknown participates; the saved forests have no '000' sentinel model.
        if (count > best || (count == best && b.probability > probability)) {
          best = count;
          chosen = b.label;
          probability = b.probability;
        }
        end = std::max(end, b.end);
        ready = std::max(ready, b.ready);
        frames.insert(frames.end(), b.frames.begin(), b.frames.end());
      }
      std::sort(frames.begin(), frames.end());
      std::ostringstream out;
      out << std::setprecision(17) << "{\"type\":\""
          << (chosen > 0 ? "iot_event" : "iot_rejected_candidate")
          << "\",\"start\":" << start << ",\"end\":" << end
          << ",\"confirmed_at\":" << due << ",\"window_end\":" << it->bound
          << ",\"window_seconds\":" << length
          << ",\"last_burst_ready\":" << ready
          << ",\"burst_count\":" << votes.size() << ",\"label\":" << chosen
          << ",\"probability\":" << probability << ",\"members\":[";
      for (size_t i = 0; i < frames.size(); i++) {
        if (i)
          out << ',';
        out << frames[i];
      }
      out << "],\"published_elapsed\":" << clock.now() << "}\n";
      std::cout << out.str();
      emitted++;
      it = groups.erase(it);
    }
  }
};
