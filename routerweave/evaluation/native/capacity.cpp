#include "native_iot.cpp"
#include "app_api.h"
#include "capacity_stream.h"
#include <atomic>
#include <cstdio>
#include <thread>

struct Cursor {
  FILE *file = nullptr;
  int task = 0, id = 0;
  unsigned link = 1, cap = 0, wire = 0;
  bool little = true, nano = false, done = false;
  double epoch = 0, stamp = 0, due = 0, previous = -INFINITY;
  std::vector<uint8_t> frame;
  static uint32_t number(const uint8_t *p, bool le) {
    return le ? uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
                    (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24)
              : (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                    (uint32_t(p[2]) << 8) | p[3];
  }
  Cursor(std::string path, int t, int i) : task(t), id(i) {
    file = std::fopen(path.c_str(), "rb");
    uint8_t h[24];
    if (!file || std::fread(h, 1, 24, file) != 24)
      throw std::runtime_error("Input PCAP header");
    auto magic = number(h, false);
    little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    nano = magic == 0x4d3cb2a1 || magic == 0xa1b23c4d;
    link = number(h + 20, little);
    if (link != 1)
      throw std::runtime_error("Ethernet input required");
    next(true);
  }
  ~Cursor() {
    if (file)
      std::fclose(file);
  }
  void next(bool first = false) {
    uint8_t h[16];
    size_t n = std::fread(h, 1, 16, file);
    if (!n) {
      done = true;
      due = INFINITY;
      return;
    }
    if (n != 16)
      throw std::runtime_error("Truncated PCAP record");
    cap = number(h + 8, little);
    wire = number(h + 12, little);
    if (cap > 262144)
      throw std::runtime_error("PCAP packet bound");
    frame.resize(cap);
    if (std::fread(frame.data(), 1, cap, file) != cap)
      throw std::runtime_error("Truncated PCAP packet");
    double original =
        number(h, little) + number(h + 4, little) / (nano ? 1e9 : 1e6);
    if (first)
      epoch = original;
    stamp = original - epoch;
    due = std::max(previous, stamp);
    previous = due;
  }
};
static void wait_to(double due) {
  while (true) {
    double left = due - wall_now();
    if (left <= 0)
      return;
    std::this_thread::sleep_for(std::chrono::duration<double>(left));
  }
}
int main(int argc, char **argv) {
  try {
    if (argc != 7)
      throw std::runtime_error(
          "full-replay ROOT INPUTS WARM OBSERVE PACED TAIL");
    std::string root = argv[1];
    double warm = std::stod(argv[3]), end = warm + std::stod(argv[4]),
           tail = std::stod(argv[6]), finish = end + tail;
    bool paced = std::stoi(argv[5]);
    std::ifstream manifest(argv[2]);
    int app_count, iot_count;
    if (!(manifest >> app_count >> iot_count) || app_count < 1 ||
        app_count > 64 || iot_count < 0 || iot_count > 64)
      throw std::runtime_error("Logical stream counts");
    std::vector<std::string> ips, app_paths;
    for (int k = 0; k < app_count; k++) {
      std::string path, ip;
      manifest >> path >> ip;
      app_paths.push_back(root + '/' + path);
      ips.push_back(ip);
    }
    std::vector<const char *> ip_array;
    for (auto &ip : ips)
      ip_array.push_back(ip.c_str());
    rw_application_load(
        (root + "/weights.bin").c_str(), (root + "/normalizer.bin").c_str(),
        ip_array.data(), app_count);
    std::map<std::string, Model> models;
    if (iot_count)
      models = load_models(root + "/native-models.bin");
    std::vector<std::unique_ptr<BStream>> iot;
    std::vector<std::unique_ptr<Cursor>> cursors;
    double input_read_start = wall_now(), input_cpu_start = cpu_now();
    for (int k = 0; k < app_count; k++)
      cursors.emplace_back(new Cursor(app_paths[k], 0, k));
    for (int k = 0; k < iot_count; k++) {
      std::string path, mac, detector;
      int device;
      manifest >> path >> mac >> detector >> device;
      iot.emplace_back(new BStream(mac_address(mac), models.at(detector),
                                   models.at("classifier"), device, k));
      cursors.emplace_back(new Cursor(root + '/' + path, 1, k));
    }
    if (!manifest)
      throw std::runtime_error("Stream manifest incomplete");
    static char output_buffer[8 * 1024 * 1024];
    if (!paced)
      setvbuf(stdout, output_buffer, _IOFBF, sizeof(output_buffer));
    std::cout << std::setprecision(17);
    double origin = paced ? wall_now() : input_read_start,
           cpu_origin = paced ? cpu_now() : input_cpu_start, warm_cpu = 0,
           end_cpu = 0, warm_actual = 0, end_actual = 0;
    std::atomic<int> mark{0};
    std::thread monitor;
    rw_application_mode(paced);
    rw_application_start(origin);
    if (paced)
      monitor = std::thread([&] {
        wait_to(origin + warm);
        warm_cpu = cpu_now();
        warm_actual = wall_now() - origin;
        mark.store(1);
        wait_to(origin + end);
        end_cpu = cpu_now();
        end_actual = wall_now() - origin;
        mark.store(2);
      });
    double tick = .5, app = 30, service = 0, period_cpu = 0;
    unsigned long raw_packets = 0;
    double last_round_finish = 0, observation_drained_at = 0;
    while (true) {
      double due = INFINITY;
      int which = -1;
      for (size_t k = 0; k < cursors.size(); k++)
        if (cursors[k]->due < due) {
          due = cursors[k]->due;
          which = (int)k;
        }
      double next = std::min(due, tick);
      if (next >= finish - 1e-8)
        break;
      if (paced) {
        wait_to(origin + next);
        if (next >= warm && mark.load() < 1)
          while (mark.load() < 1)
            std::this_thread::yield();
        if (next >= end && mark.load() < 2)
          while (mark.load() < 2)
            std::this_thread::yield();
      }
      double begin = wall_now(), cpu0 = cpu_now();
      if (due < tick) {
        auto &c = *cursors[which];
        if (c.task == 0)
          rw_application_packet(c.id, c.frame.data(), c.cap, c.wire, c.stamp,
                                c.link);
        else
          iot[c.id]->feed(c.frame.data(), c.cap, c.stamp);
        raw_packets++;
        c.next();
        service += wall_now() - begin;
        period_cpu += cpu_now() - cpu0;
        if (next < end)
          observation_drained_at =
              std::max(observation_drained_at, wall_now() - origin);
        continue;
      }
      // All packets strictly before this watermark have been delivered. No
      // future packet is ingested merely because the real executor fell behind.
      bool round = std::fmod(tick, 5.) == 0;
      if (tick >= app - 1e-8) {
        rw_application_step(tick);
        app += 5;
      }
      for (auto &s : iot)
        s->tick(tick, wall_now() - origin);
      service += wall_now() - begin;
      period_cpu += cpu_now() - cpu0;
      if (next < end)
        observation_drained_at =
            std::max(observation_drained_at, wall_now() - origin);
      if (round) {
        last_round_finish = wall_now() - origin;
        std::cout << "{\"type\":\"round\",\"due\":" << tick
                  << ",\"service_seconds\":" << service
                  << ",\"finish_elapsed\":" << last_round_finish
                  << ",\"cpu_seconds\":" << period_cpu
                  << ",\"actual_primary_calls\":" << rw_application_calls()
                  << ",\"raw_packets\":" << raw_packets << "}\n";
        if (paced)
          std::cout.flush();
        service = 0;
        period_cpu = 0;
      }
      tick += .5;
    }
    if (!paced && iot_count == 0 && tail == 0)
      rw_application_step(end);
    if (paced)
      wait_to(origin + finish);
    if (paced)
      monitor.join();
    double total_cpu = cpu_now() - cpu_origin;
    unsigned long calls = 0, events = 0;
    int max_context = 0;
    size_t peak_units = 0;
    for (size_t k = 0; k < iot.size(); k++) {
      auto &s = *iot[k];
      s.emit_wait_state();
      calls += s.calls;
      events += s.events;
      max_context = std::max(max_context, s.max_context);
      peak_units = std::max(peak_units, s.peak_units);
      std::cout << "{\"type\":\"iot_state\",\"stream\":" << k
                << ",\"packets\":" << s.packets << ",\"calls\":" << s.calls
                << ",\"events\":" << s.events
                << ",\"quiet_closures\":" << s.quiet_closures
                << ",\"packet_closures\":" << s.packet_closures
                << ",\"peak_history_units\":" << s.peak_units
                << ",\"max_inference_units\":" << s.max_context
                << ",\"peak_pending_packets\":" << s.peak_pending_packets
                << "}\n";
    }
    std::cout << "{\"type\":\"summary\",\"app_streams\":" << app_count
              << ",\"iot_streams\":" << iot_count
              << ",\"actual_primary_calls\":" << rw_application_calls()
              << ",\"iot_calls\":" << calls << ",\"iot_events\":" << events
              << ",\"raw_packets\":" << raw_packets
              << ",\"observation_cpu_seconds\":" << end_cpu - warm_cpu
              << ",\"total_cpu_seconds\":" << total_cpu
              << ",\"cpu_window_start\":" << warm_actual
              << ",\"cpu_window_end\":" << end_actual
              << ",\"peak_rss_mib\":" << peak_mib()
              << ",\"max_iot_context\":" << max_context
              << ",\"peak_iot_history_units\":" << peak_units
              << ",\"elapsed_seconds\":" << wall_now() - origin
              << ",\"remaining_backlog_seconds\":"
              << std::max(0., observation_drained_at - end)
              << ",\"capture_boundary_closures\":0}\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 2;
  }
  return 0;
}
