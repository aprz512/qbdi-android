#pragma once

#include <cstdint>

struct SignalProbeResult {
  bool guest_handler_called = false;
  bool guest_pc_original = false;
  bool register_cookie = false;
  bool qbdi_handler_traced = false;
  bool handler_query_hidden = false;
};

SignalProbeResult run_native_signal_probe(uintptr_t entry,
                                          uintptr_t module_address) noexcept;

extern "C" __attribute__((visibility("default"))) uint32_t
qbdi_signal_probe_bits(uintptr_t entry, uintptr_t module_address) noexcept;
