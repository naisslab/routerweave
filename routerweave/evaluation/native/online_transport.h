#pragma once
#include "native_iot.h"
#include <memory>
namespace rwiot {
class OnlineTransport {
  struct Impl;
  std::unique_ptr<Impl> impl;

public:
  explicit OnlineTransport(std::array<uint8_t, 6>);
  ~OnlineTransport();
  void feed(const uint8_t *, size_t, double);
  std::vector<Unit> advance(double);
  size_t pending_packets() const;
};
} // namespace rwiot
