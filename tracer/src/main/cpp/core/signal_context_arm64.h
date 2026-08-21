#pragma once

#include <QBDI/State.h>

#include <array>
#include <cstdint>

struct Arm64SignalContext {
  std::array<uint64_t, 31> regs{};
  uint64_t sp = 0;
  uint64_t pc = 0;
  uint64_t pstate = 0;
};

bool qbdi_gpr_to_signal_context(const QBDI::GPRState &source,
                                Arm64SignalContext *destination) noexcept;

bool signal_context_to_qbdi_gpr(const Arm64SignalContext &source,
                                QBDI::GPRState *destination) noexcept;

#if defined(__ANDROID__) && defined(__aarch64__)
#include <ucontext.h>

__attribute__((visibility("hidden"))) bool
qbdi_gpr_to_ucontext(const QBDI::GPRState &source,
                     ucontext_t *destination) noexcept;

__attribute__((visibility("hidden"))) bool
ucontext_to_qbdi_gpr(const ucontext_t &source,
                     QBDI::GPRState *destination) noexcept;
#endif
