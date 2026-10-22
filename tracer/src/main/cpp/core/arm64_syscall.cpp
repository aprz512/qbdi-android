#include "core/arm64_syscall.h"

#include <cerrno>
#include <cstdio>
#include <limits>

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

namespace {
SyscallPathSnapshot snapshot_path(uintptr_t address, uint8_t argument,
                                  SyscallMemoryReader reader) noexcept {
  SyscallPathSnapshot result{};
  result.address = address;
  result.argument = argument;
  result.state = SyscallPathState::Unreadable;
  const int saved_errno = errno;
  if (reader != nullptr && result.address != 0) {
    for (size_t index = 0; index < result.bytes.size(); ++index) {
      unsigned char byte = 0;
      if (result.address > std::numeric_limits<uintptr_t>::max() - index ||
          !reader(result.address + index, &byte, 1)) {
        result.state = index == 0 ? SyscallPathState::Unreadable : SyscallPathState::Partial;
        break;
      }
      if (byte == 0) {
        result.state = SyscallPathState::Complete;
        break;
      }
      result.bytes[result.size++] = byte;
      result.state = SyscallPathState::Truncated;
    }
  }
  errno = saved_errno;
  return result;
}
} // namespace

SyscallPathSnapshot snapshot_syscall_path(const Arm64SyscallSnapshot &call,
                                        SyscallMemoryReader reader) noexcept {
  if (call.number != 56) return {};
  return snapshot_path(call.args[1], 1, reader);
}

SyscallPathSnapshots snapshot_syscall_paths(const Arm64SyscallSnapshot &call,
                                          SyscallMemoryReader reader) noexcept {
  // Linux arm64 direct string arguments; encoded structures (e.g. sockaddr,
  // io_uring requests and fsconfig's command-dependent value) are not guessed.
  struct Selection { int64_t number; uint8_t first; int8_t second; };
  static constexpr Selection selections[] = {
      {5,0,-1}, {6,0,-1}, {8,0,-1}, {9,0,-1}, {11,0,-1}, {12,0,-1},
      {14,0,-1}, {15,0,-1}, {27,1,-1}, {34,1,-1}, {35,1,-1},
      {36,0,2}, {37,1,3}, {38,1,3}, {39,0,-1}, {40,0,1}, {41,0,1},
      {43,0,-1}, {45,0,-1}, {48,1,-1}, {49,0,-1}, {51,0,-1},
      {53,1,-1}, {54,1,-1}, {56,1,-1}, {60,1,-1}, {78,1,-1},
      {79,1,-1}, {88,1,-1}, {221,0,-1}, {224,0,-1}, {225,0,-1},
      {263,4,-1}, {264,1,-1}, {276,1,3}, {281,1,-1}, {291,1,-1},
      {428,1,-1}, {429,1,3}, {433,1,-1}, {437,1,-1}, {439,1,-1},
      {442,1,-1}, {452,1,-1},
  };
  SyscallPathSnapshots result{};
  for (const auto &selection : selections) {
    if (selection.number != call.number) continue;
    result.paths[result.count++] = snapshot_path(call.args[selection.first], selection.first, reader);
    if (selection.second >= 0) {
      const auto argument = static_cast<uint8_t>(selection.second);
      result.paths[result.count++] = snapshot_path(call.args[argument], argument, reader);
    }
    break;
  }
  return result;
}

namespace {
bool format_path(const SyscallPathSnapshot &path, char *output, size_t capacity) noexcept {
  if (path.state == SyscallPathState::NotApplicable) {
    const int length = std::snprintf(output, capacity, "null");
    return length >= 0 && static_cast<size_t>(length) < capacity;
  }
    const char *state = path.state == SyscallPathState::Complete ? "complete" :
                        path.state == SyscallPathState::Partial ? "partial" :
                        path.state == SyscallPathState::Truncated ? "truncated" : "unreadable";
    char hex[kSyscallPathBytes * 2 + 1]{}, display[kSyscallPathBytes * 5 + 1]{};
    constexpr char digits[] = "0123456789abcdef";
    size_t cursor = 0;
    if (path.size > path.bytes.size()) return false;
    for (size_t index = 0; index < path.size; ++index) {
      const unsigned char byte = path.bytes[index];
      hex[index * 2] = digits[byte >> 4U]; hex[index * 2 + 1] = digits[byte & 15U];
      if (byte >= 0x20 && byte < 0x7f && byte != '"' && byte != '\\') display[cursor++] = byte;
      else if (byte == '"' || byte == '\\') { display[cursor++] = '\\'; display[cursor++] = byte; }
      else { display[cursor++] = '\\'; display[cursor++] = '\\'; display[cursor++] = 'x';
             display[cursor++] = digits[byte >> 4U]; display[cursor++] = digits[byte & 15U]; }
    }
    const int length = std::snprintf(output, capacity,
        "{\"argument\":%u,\"address\":\"0x%llx\",\"status\":\"%s\",\"limit\":128,\"bytesHex\":\"%s\",\"display\":\"%s\"}",
        unsigned(path.argument), static_cast<unsigned long long>(path.address), state, hex, display);
    return length >= 0 && static_cast<size_t>(length) < capacity;
}
} // namespace

bool format_syscall_entry(const Arm64SyscallSnapshot &call, uint64_t id,
                          const SyscallPathSnapshot &path, char *output, size_t capacity) noexcept {
  char path_json[1536];
  if (!format_path(path, path_json, sizeof(path_json))) return false;
  const int length = std::snprintf(output, capacity,
      "{\"schema\":1,\"id\":%llu,\"number\":%lld,\"pc\":\"0x%llx\",\"args\":[\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\"],\"path\":%s}",
      static_cast<unsigned long long>(id), static_cast<long long>(call.number),
      static_cast<unsigned long long>(call.pc),
      static_cast<unsigned long long>(call.args[0]), static_cast<unsigned long long>(call.args[1]),
      static_cast<unsigned long long>(call.args[2]), static_cast<unsigned long long>(call.args[3]),
      static_cast<unsigned long long>(call.args[4]), static_cast<unsigned long long>(call.args[5]), path_json);
  return length >= 0 && static_cast<size_t>(length) < capacity;
}

bool format_syscall_entry(const Arm64SyscallSnapshot &call, uint64_t id,
                          const SyscallPathSnapshots &paths, char *output, size_t capacity) noexcept {
  if (paths.count > kSyscallPathCount) return false;
  char path_json[kSyscallPathCount][1536]{};
  for (size_t index = 0; index < paths.count; ++index) {
    if (!format_path(paths.paths[index], path_json[index], sizeof(path_json[index]))) return false;
  }
  const int length = std::snprintf(output, capacity,
      "{\"schema\":2,\"id\":%llu,\"number\":%lld,\"pc\":\"0x%llx\",\"args\":[\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\",\"0x%llx\"],\"paths\":[%s%s%s]}",
      static_cast<unsigned long long>(id), static_cast<long long>(call.number),
      static_cast<unsigned long long>(call.pc),
      static_cast<unsigned long long>(call.args[0]), static_cast<unsigned long long>(call.args[1]),
      static_cast<unsigned long long>(call.args[2]), static_cast<unsigned long long>(call.args[3]),
      static_cast<unsigned long long>(call.args[4]), static_cast<unsigned long long>(call.args[5]),
      paths.count > 0 ? path_json[0] : "", paths.count == 2 ? "," : "", paths.count == 2 ? path_json[1] : "");
  return length >= 0 && static_cast<size_t>(length) < capacity;
}

bool format_syscall_return(const Arm64SyscallSnapshot &call, uint64_t id,
                           bool observed, uint64_t raw, const char *reason,
                           char *output, size_t capacity, unsigned schema) noexcept {
  char returned[32] = "null", error[16] = "null";
  if (observed) {
    std::snprintf(returned, sizeof(returned), "\"0x%llx\"", static_cast<unsigned long long>(raw));
    if (raw >= UINT64_MAX - 4094)
      std::snprintf(error, sizeof(error), "%llu", static_cast<unsigned long long>(~raw + 1));
  }
  const int length = std::snprintf(output, capacity,
      "{\"schema\":%u,\"id\":%llu,\"number\":%lld,\"pc\":\"0x%llx\",\"observed\":%s,\"rawReturn\":%s,\"linuxErrorNumber\":%s,\"reason\":\"%s\"}",
      schema, static_cast<unsigned long long>(id), static_cast<long long>(call.number),
      static_cast<unsigned long long>(call.pc), observed ? "true" : "false", returned, error, reason);
  return length >= 0 && static_cast<size_t>(length) < capacity;
}
