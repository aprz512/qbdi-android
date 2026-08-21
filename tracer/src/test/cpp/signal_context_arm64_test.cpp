#include "core/signal_context_arm64.h"

#include <QBDI/State.h>

#include <cstdio>
#include <cstdlib>

namespace {

void check(bool condition, const char *expression, int line) {
  if (condition)
    return;
  std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
  std::abort();
}

#define CHECK(expression)                                                      \
  check(static_cast<bool>(expression), #expression, __LINE__)

void round_trips_every_guest_register_through_the_pure_context() {
  QBDI::GPRState source{};
  for (size_t index = 0; index < 31; ++index) {
    QBDI_GPR_SET(&source, index,
                 0x1000000000000000ULL + index * 0x0101010101010101ULL);
  }
  source.sp = 0x4040404040404040ULL;
  source.pc = 0x5050505050505050ULL;
  source.nzcv = 0x60000000U;

  Arm64SignalContext context{};
  QBDI::GPRState restored{};
  CHECK(qbdi_gpr_to_signal_context(source, &context));
  CHECK(signal_context_to_qbdi_gpr(context, &restored));

  for (size_t index = 0; index < 31; ++index) {
    CHECK(QBDI_GPR_GET(&restored, index) == QBDI_GPR_GET(&source, index));
  }
  CHECK(restored.sp == 0x4040404040404040ULL);
  CHECK(restored.pc == 0x5050505050505050ULL);
  CHECK(restored.nzcv == 0x60000000U);
}

void copies_a_hand_derived_context_into_guest_registers() {
  Arm64SignalContext context{};
  for (size_t index = 0; index < context.regs.size(); ++index) {
    context.regs[index] = 0x8000U + index * 0x101U;
  }
  context.sp = 0x9000900090009000ULL;
  context.pc = 0xa000a000a000a000ULL;
  context.pstate = 0xb0000000U;
  QBDI::GPRState restored{};

  CHECK(signal_context_to_qbdi_gpr(context, &restored));

  CHECK(restored.x0 == 0x8000U);
  CHECK(restored.x8 == 0x8808U);
  CHECK(restored.x29 == 0x9d1dU);
  CHECK(restored.lr == 0x9e1eU);
  CHECK(restored.sp == 0x9000900090009000ULL);
  CHECK(restored.pc == 0xa000a000a000a000ULL);
  CHECK(restored.nzcv == 0xb0000000U);
}

void rejects_null_destinations_without_touching_memory() {
  const QBDI::GPRState gpr{};
  const Arm64SignalContext context{};
  CHECK(!qbdi_gpr_to_signal_context(gpr, nullptr));
  CHECK(!signal_context_to_qbdi_gpr(context, nullptr));
}

} // namespace

int main() {
  round_trips_every_guest_register_through_the_pure_context();
  copies_a_hand_derived_context_into_guest_registers();
  rejects_null_destinations_without_touching_memory();
}
