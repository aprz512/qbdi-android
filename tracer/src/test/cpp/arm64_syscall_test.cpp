#include "core/arm64_syscall.h"

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

void recognizes_only_arm64_svc_encodings() {
  CHECK(is_arm64_svc(0xd4000001U));
  CHECK(is_arm64_svc(0xd4002461U));
  CHECK(!is_arm64_svc(0xd4000000U));
  CHECK(!is_arm64_svc(0xd4200000U));
  CHECK(!is_arm64_svc(0xd503201fU));
}

void snapshots_syscall_pc_number_and_six_arguments() {
  QBDI::GPRState gpr{};
  gpr.pc = 0x71001234U;
  gpr.x8 = 131U;
  gpr.x0 = 100U;
  gpr.x1 = 101U;
  gpr.x2 = 9U;
  gpr.x3 = 0x3333333333333333ULL;
  gpr.x4 = 0x4444444444444444ULL;
  gpr.x5 = 0x5555555555555555ULL;

  const Arm64SyscallSnapshot call = snapshot_arm64_syscall(gpr.pc, gpr);

  CHECK(call.pc == 0x71001234U);
  CHECK(call.number == 131);
  CHECK(call.args[0] == 100U);
  CHECK(call.args[1] == 101U);
  CHECK(call.args[2] == 9U);
  CHECK(call.args[3] == 0x3333333333333333ULL);
  CHECK(call.args[4] == 0x4444444444444444ULL);
  CHECK(call.args[5] == 0x5555555555555555ULL);
}

} // namespace

int main() {
  recognizes_only_arm64_svc_encodings();
  snapshots_syscall_pc_number_and_six_arguments();
}
