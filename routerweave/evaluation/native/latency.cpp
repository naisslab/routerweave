#include "app_api.h"
#include "baseline_core.h"
#include "flow_online.h"
#include "latency_stream.h"
#include <chrono>
#include <cstring>

struct Clock {
  bool paced;
  double origin = wall_now(), logical = 0, begin = 0;
  explicit Clock(bool p) : paced(p) {}
  double now() const {
    return paced ? wall_now() - origin
                 : logical + (begin ? wall_now() - begin : 0);
  }
  void start(double due) {
    if (paced) {
      double delay = origin + due - wall_now();
      if (delay > 0)
        std::this_thread::sleep_for(std::chrono::duration<double>(delay));
    } else
      logical = std::max(logical, due);
    begin = wall_now();
  }
  void stop() {
    if (!paced)
      logical += wall_now() - begin;
    begin = 0;
  }
};
struct Cursor {
  FILE *file;
  bool done = false, little, nano;
  unsigned cap = 0, wire = 0, link = 1, frame = 0;
  double epoch = 0, stamp = 0;
  Bytes raw;
  static uint32_t u32(const unsigned char *p, bool le) {
    return le ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
                    (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
              : (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                    (uint32_t(p[2]) << 8) | p[3];
  }
  explicit Cursor(const char *path) {
    file = fopen(path, "rb");
    unsigned char h[24];
    if (!file || fread(h, 1, 24, file) != 24)
      throw std::runtime_error("PCAP header");
    auto m = u32(h, false);
    little = m == 0xd4c3b2a1 || m == 0x4d3cb2a1;
    nano = m == 0x4d3cb2a1 || m == 0xa1b23c4d;
    link = u32(h + 20, little);
    if (link != 1)
      throw std::runtime_error("Ethernet PCAP required");
    next(true);
  }
  ~Cursor() { fclose(file); }
  void next(bool first = false) {
    unsigned char h[16];
    auto n = fread(h, 1, 16, file);
    if (!n) {
      done = true;
      stamp = INFINITY;
      return;
    }
    if (n != 16)
      throw std::runtime_error("PCAP record");
    cap = u32(h + 8, little);
    wire = u32(h + 12, little);
    if (cap > 262144)
      throw std::runtime_error("Packet bound");
    raw.resize(cap);
    if (fread(raw.data(), 1, cap, file) != cap)
      throw std::runtime_error("Packet payload");
    double t = u32(h, little) + u32(h + 4, little) / (nano ? 1e9 : 1e6);
    if (first)
      epoch = t;
    double previous = stamp;
    stamp = t - epoch;
    if (!first && stamp < previous - 1e-7)
      throw std::runtime_error("PCAP timestamps not ordered");
    frame++;
  }
};
#ifdef RF_WINDOW
#include "rf_window.h"
#endif
struct RFOnline {
  struct Active {
    rwbase::RFData data;
    std::vector<unsigned> frames;
  };
  std::map<std::tuple<int, uint32_t, int, int>, Active> flows;
  rwbase::Target target;
  void *model;
  int device;
  unsigned events = 0;
  RFOnline(rwbase::Target t, void *m, int d) : target(t), model(m), device(d) {}
#ifdef RF_WINDOW
  std::unique_ptr<RFWindow> windows;
  std::vector<std::string> label_names;
  void configure_windows(double epoch, const std::string &name,
                         const std::string &root) {
    windows = std::make_unique<RFWindow>(epoch, name);
    std::ifstream in(root + "/rf-labels.txt");
    std::string line;
    while (std::getline(in, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      label_names.push_back(line);
    }
    if (label_names.empty())
      throw std::runtime_error("RF label names missing");
  }
#endif
  void publish(Active &a, double due, Clock &clock) {
    if (a.data.t.size() < 2)
      return;
    auto f = rwbase::rf_features(a.data, -INFINITY, INFINITY);
    if (f.x.size() != 22)
      throw std::runtime_error("RF active burst partition");
    int32_t label;
    double probability;
    if (rf_predict(model, device, f.x.data(), 1, &label, &probability))
      throw std::runtime_error("RF traversal");
    const char *type = label > 0 ? "iot_event" : "iot_rejected_candidate";
#ifdef RF_WINDOW
    type = "rf_burst";
    windows->pending.push_back(
        {a.data.t.front(), a.data.t.back(), due, probability, label,
         label < 0 ? "unknown" : label_names.at(label), a.frames});
#endif
    std::ostringstream out;
    out << std::setprecision(17) << "{\"type\":\"" << type
        << "\",\"start\":" << a.data.t.front() << ",\"end\":" << a.data.t.back()
        << ",\"confirmed_at\":" << due << ",\"label\":" << label
        << ",\"probability\":" << probability << ",\"members\":[";
    for (size_t i = 0; i < a.frames.size(); i++) {
      if (i)
        out << ',';
      out << a.frames[i];
    }
    out << "],\"published_elapsed\":" << clock.now() << "}\n";
    std::cout << out.str();
    if (label > 0)
      events++;
  }
  void tick(double due, Clock &clock) {
    for (auto it = flows.begin(); it != flows.end();)
      if (due - it->second.data.t.back() > 1.0 + 1e-9) {
        publish(it->second, due, clock);
        it = flows.erase(it);
      } else
        ++it;
#ifdef RF_WINDOW
    windows->advance(due, flows, clock);
#endif
  }
  void feed(const Cursor &c, Clock &clock) {
    Bytes b(40 + c.cap);
    unsigned h[] = {0xa1b2c3d4, 0x00040002, 0, 0, 262144, 1};
    std::memcpy(b.data(), h, 24);
    unsigned sec = (unsigned)c.stamp,
             micro = (unsigned)llround((c.stamp - sec) * 1e6);
    if (micro == 1000000) {
      sec++;
      micro = 0;
    }
    unsigned rh[] = {sec, micro, c.cap, c.wire};
    std::memcpy(b.data() + 24, rh, 16);
    std::memcpy(b.data() + 40, c.raw.data(), c.cap);
    for (auto &p : rwbase::decode_packets(b, target)) {
      uint32_t remote = p.direction == 1 ? p.dst : p.src;
      auto k = std::make_tuple(p.protocol, remote,
                               p.direction == 1 ? p.sport : p.dport,
                               p.direction == 1 ? p.dport : p.sport);
      auto it = flows.find(k);
      if (it != flows.end() && c.stamp - it->second.data.t.back() > 1.) {
        publish(it->second, c.stamp, clock);
        flows.erase(it);
      }
      auto &a = flows[k];
      auto data = rwbase::rf_data(b, target);
      if (data.t.size() != 1)
        throw std::runtime_error("Baseline parser disagreement");
      a.data.t.push_back(c.stamp);
      a.data.size.push_back(data.size[0]);
      a.data.payload.push_back(data.payload[0]);
      a.data.flow.push_back(0);
      a.data.direction.push_back(data.direction[0]);
      a.data.local.push_back(data.local[0]);
      a.frames.push_back(c.frame);
    }
  }
};
int main(int argc, char **argv) {
  try {
    if (argc != 10)
      throw std::runtime_error(
          "latency ROOT MODE PCAP IP MAC DEVICE DETECTOR DURATION PACED");
    std::string root = argv[1], mode = argv[2];
    bool app = mode.find("app-") == 0;
    bool paced = std::stoi(argv[9]);
    int device = std::stoi(argv[6]);
    double duration = std::stod(argv[8]), end = duration + (app ? 0 : 30);
    Cursor c(argv[3]);
    rwbase::Target target =
        command_target(app ? argv[4] : argv[5], app ? "ip" : "mac");
    std::map<std::string, Model> models;
    std::unique_ptr<BStream> stream;
    std::unique_ptr<FPModel> fp;
    std::unique_ptr<FlowOnline> flow;
    std::unique_ptr<RFOnline> rf;
    void *forest = nullptr;
    if (mode == "app-rw") {
      const char *ip = argv[4];
      rw_application_load((root + "/weights.bin").c_str(),
                          (root + "/normalizer.bin").c_str(), &ip, 1);
      rw_application_mode(0);
    } else if (mode == "app-fp") {
      fp = std::make_unique<FPModel>(root + "/flowprint.bin");
      flow = std::make_unique<FlowOnline>(target);
    } else if (mode == "iot-rw") {
      models = load_models(root + "/iot-models.bin");
      stream = std::make_unique<BStream>(target.mac, models.at(argv[7]),
                                         models.at("classifier"), device, 0);
    } else if (mode == "iot-rf") {
      char name[128];
      std::snprintf(name, sizeof(name), "/rf/device-%03d.bin", device);
      forest = rf_load_model((root + name).c_str());
      if (!forest)
        throw std::runtime_error("RF load");
      rf = std::make_unique<RFOnline>(target, forest, device);
    } else
      throw std::runtime_error("Unknown mode");
#ifdef RF_WINDOW
    if (rf) {
      rf->configure_windows(c.epoch, argv[7], root);
      end = duration + rf->windows->length + 2;
    }
#endif
    std::map<std::vector<std::string>, int> cache;
    std::cout << std::setprecision(17);
    Clock clock(paced);
    double cpu0 = cpu_now(), service = 0, tick = .5, update = 30;
    if (mode == "app-rw")
      rw_application_start(clock.origin);
    while (std::min(c.stamp, tick) <= end + 1e-8) {
      bool packet = c.stamp < tick;
      double due = packet ? c.stamp : tick;
      if (packet && due >= duration) {
        c.done = true;
        c.stamp = INFINITY;
        continue;
      }
      clock.start(due);
      double begin = wall_now();
      if (packet) {
        if (mode == "app-rw")
          rw_application_packet(0, c.raw.data(), c.cap, c.wire, c.stamp,
                                c.link);
        else if (flow)
          flow->feed(c.raw.data(), c.cap, c.wire, c.stamp);
        else if (stream)
          stream->feed(c.raw.data(), c.cap, c.stamp);
        else
          rf->feed(c, clock);
        c.next();
      } else {
        if (app && tick >= update - 1e-8) {
          if (mode == "app-rw") {
            double at = clock.now();
            rw_application_step(tick);
            std::cout << "{\"type\":\"latency\",\"cutoff\":" << tick
                      << ",\"published_elapsed\":" << at + wall_now() - begin
                      << ",\"processing_seconds\":" << wall_now() - begin
                      << "}\n";
          } else {
            auto flows = flow->window(tick);
            auto fingerprints = rwbase::fingerprints(flows);
            std::map<int, int> counts;
            std::vector<int> order;
            for (auto &q : fingerprints) {
              auto it = cache.find(q->tokens);
              if (it == cache.end())
                it = cache.emplace(q->tokens, fp->predict(*q)).first;
              int label = it->second;
              if (!counts.count(label))
                order.push_back(label);
              counts[label]++;
            }
            int chosen = fp->fingerprints[fp->fallback].label, best = 0;
            for (int label : order)
              if (counts[label] > best) {
                chosen = label;
                best = counts[label];
              }
            std::ostringstream out;
            out << "{\"type\":\"prediction\",\"cutoff\":"
                << std::setprecision(17) << tick << ",\"label\":" << chosen
                << ",\"fingerprints\":" << fingerprints.size()
                << ",\"queries\":" << cache.size();
            std::string prefix = out.str();
            std::cout << prefix << ",\"published_elapsed\":" << clock.now()
                      << ",\"processing_seconds\":" << wall_now() - begin
                      << "}\n";
          }
          update += 5;
        }
        if (stream)
          stream->tick(tick, clock.now());
        if (rf)
          rf->tick(tick, clock);
        tick += .5;
      }
      double elapsed = wall_now() - begin;
      service += elapsed;
      clock.stop();
    }
    if (stream)
      stream->emit_wait_state();
#ifdef RF_WINDOW
    if (rf)
      std::cout << "{\"type\":\"rf_window_state\",\"pending_bursts\":"
                << rf->windows->pending.size()
                << ",\"pending_windows\":" << rf->windows->groups.size()
                << ",\"unclassified_window_bursts\":"
                << rf->windows->assigned.size()
                << ",\"emitted_windows\":" << rf->windows->emitted
                << ",\"window_seconds\":" << rf->windows->length << "}\n";
#endif
    std::cout << "{\"type\":\"summary\",\"paced\":"
              << (paced ? "true" : "false") << ",\"epoch\":" << c.epoch
              << ",\"logical_elapsed\":" << clock.now()
              << ",\"wall_seconds\":" << wall_now() - clock.origin
              << ",\"service_seconds\":" << service
              << ",\"cpu_seconds\":" << cpu_now() - cpu0
              << ",\"peak_rss_mib\":" << peak_mib()
              << ",\"pending_rf_bursts\":" << (rf ? rf->flows.size() : 0)
              << "}\n";
    if (forest)
      rf_free_model(forest);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 2;
  }
  return 0;
}
