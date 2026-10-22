#pragma once

#include <QBDI/State.h>

#include <array>
#include <cstdint>
#include <cstddef>

struct Arm64SyscallSnapshot {
  uintptr_t pc = 0;
  int64_t number = -1;
  std::array<uint64_t, 6> args{};
};

bool is_arm64_svc(uint32_t opcode) noexcept;

Arm64SyscallSnapshot snapshot_arm64_syscall(uintptr_t pc,
                                            const QBDI::GPRState &gpr) noexcept;

constexpr size_t kSyscallPathBytes = 128;
enum class SyscallPathState { NotApplicable, Complete, Unreadable, Partial, Truncated };
struct SyscallPathSnapshot {
  SyscallPathState state = SyscallPathState::NotApplicable;
  uint8_t argument = 1;
  uintptr_t address = 0;
  size_t size = 0;
  std::array<unsigned char, kSyscallPathBytes> bytes{};
};
constexpr size_t kSyscallPathCount = 2;
struct SyscallPathSnapshots {
  size_t count = 0;
  std::array<SyscallPathSnapshot, kSyscallPathCount> paths{};
};
using SyscallMemoryReader = bool (*)(uintptr_t, void *, size_t);
SyscallPathSnapshot snapshot_syscall_path(const Arm64SyscallSnapshot &call,
                                        SyscallMemoryReader reader) noexcept;
SyscallPathSnapshots snapshot_syscall_paths(const Arm64SyscallSnapshot &call,
                                          SyscallMemoryReader reader) noexcept;
bool format_syscall_entry(const Arm64SyscallSnapshot &call, uint64_t id,
                          const SyscallPathSnapshot &path, char *output, size_t capacity) noexcept;
bool format_syscall_entry(const Arm64SyscallSnapshot &call, uint64_t id,
                          const SyscallPathSnapshots &paths, char *output, size_t capacity) noexcept;
bool format_syscall_return(const Arm64SyscallSnapshot &call, uint64_t id,
                           bool observed, uint64_t raw, const char *reason,
                           char *output, size_t capacity, unsigned schema = 1) noexcept;
