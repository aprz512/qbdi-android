#include "core/arm64_syscall.h"

bool is_arm64_svc(uint32_t opcode) noexcept {
  return (opcode & 0xffe0001fU) == 0xd4000001U;
}

Arm64SyscallSnapshot
snapshot_arm64_syscall(uintptr_t pc, const QBDI::GPRState &gpr) noexcept {
  Arm64SyscallSnapshot snapshot{};
  snapshot.pc = pc;
  snapshot.number = static_cast<int64_t>(gpr.x8);
  snapshot.args = {gpr.x0, gpr.x1, gpr.x2, gpr.x3, gpr.x4, gpr.x5};
  return snapshot;
}
