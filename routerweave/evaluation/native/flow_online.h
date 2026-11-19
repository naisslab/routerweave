#pragma once
#include "native_baselines.h"
#include <memory>
class FlowOnline {
  struct Impl;
  std::unique_ptr<Impl> impl;

public:
  explicit FlowOnline(rwbase::Target target);
  ~FlowOnline();
  void feed(const unsigned char *, unsigned, unsigned, double);
  std::vector<rwbase::Flow> window(double cutoff);
};
