#pragma once

#include <QBDI/State.h>

#include <array>
#include <cstdint>

struct Arm64SyscallSnapshot {
  uintptr_t pc = 0;
  int64_t number = -1;
  std::array<uint64_t, 6> args{};
};

bool is_arm64_svc(uint32_t opcode) noexcept;

Arm64SyscallSnapshot snapshot_arm64_syscall(uintptr_t pc,
                                            const QBDI::GPRState &gpr) noexcept;
