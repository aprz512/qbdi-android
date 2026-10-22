#include "core/arm64_syscall.h"

#include <QBDI/State.h>

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include "third_party/nlohmann/json.hpp"

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

const char *readable = nullptr;
size_t readable_size = 0;
bool read_byte(uintptr_t address, void *destination, size_t size) {
  const auto start = reinterpret_cast<uintptr_t>(readable);
  if (size != 1 || address < start || address - start >= readable_size) {
    errno = EFAULT;
    return false;
  }
  std::memcpy(destination, reinterpret_cast<const void *>(address), 1);
  return true;
}

void bounded_paths_preserve_partial_bytes_and_errno() {
  char text[140]; std::memset(text, 'p', sizeof(text));
  readable = text;
  Arm64SyscallSnapshot call{};
  call.number = 56; call.args[1] = reinterpret_cast<uintptr_t>(text);
  errno = 123;
  readable_size = 0;
  CHECK(snapshot_syscall_path(call, read_byte).state == SyscallPathState::Unreadable);
  CHECK(errno == 123);
  readable_size = 4;
  auto partial = snapshot_syscall_path(call, read_byte);
  CHECK(partial.state == SyscallPathState::Partial && partial.size == 4);
  CHECK(errno == 123);
  readable_size = sizeof(text);
  CHECK(snapshot_syscall_path(call, read_byte).state == SyscallPathState::Truncated);
  text[7] = 0;
  const auto complete = snapshot_syscall_path(call, read_byte);
  CHECK(complete.state == SyscallPathState::Complete && complete.size == 7);
  char encoded[2048];
  CHECK(format_syscall_entry(call, 7, complete, encoded, sizeof(encoded)));
  const auto value = nlohmann::json::parse(encoded);
  CHECK(value["id"] == 7 && value["path"]["status"] == "complete");
  CHECK(value["path"]["display"] == "ppppppp");
  CHECK(!format_syscall_entry(call, 7, complete, encoded, 8));
  text[0] = '"'; text[1] = '\\'; text[2] = '\n'; text[3] = static_cast<char>(0xff); text[4] = 0;
  CHECK(format_syscall_entry(call, 8, snapshot_syscall_path(call, read_byte), encoded, sizeof(encoded)));
  const auto escaped = nlohmann::json::parse(encoded);
  CHECK(escaped["path"]["bytesHex"] == "225c0aff");
  call.number = 172;
  CHECK(snapshot_syscall_path(call, read_byte).state == SyscallPathState::NotApplicable);
}

void raw_returns_and_linux_errors_do_not_invent_missing_values() {
  Arm64SyscallSnapshot call{};
  char encoded[512];
  CHECK(format_syscall_return(call, 4, true, UINT64_MAX - 13, "post_instruction", encoded, sizeof(encoded)));
  auto value = nlohmann::json::parse(encoded);
  CHECK(value["rawReturn"] == "0xfffffffffffffff2" && value["linuxErrorNumber"] == 14);
  CHECK(format_syscall_return(call, 4, true, UINT64_MAX - 4095, "post_instruction", encoded, sizeof(encoded)));
  CHECK(nlohmann::json::parse(encoded)["linuxErrorNumber"].is_null());
  CHECK(format_syscall_return(call, 4, false, 42, "signal_intervened", encoded, sizeof(encoded)));
  value = nlohmann::json::parse(encoded);
  CHECK(value["rawReturn"].is_null() && value["linuxErrorNumber"].is_null() && value["observed"] == false);
}

void double_paths_have_independent_arguments_and_bounded_bytes() {
  char text[256]; std::memset(text, 0xff, sizeof(text));
  readable = text; readable_size = sizeof(text);
  Arm64SyscallSnapshot call{};
  call.number = 38;  // renameat, oldpath/newpath.
  call.args[1] = reinterpret_cast<uintptr_t>(text);
  call.args[3] = reinterpret_cast<uintptr_t>(text + 128);
  errno = 123;
  const auto paths = snapshot_syscall_paths(call, read_byte);
  CHECK(paths.count == 2 && paths.paths[0].argument == 1 && paths.paths[1].argument == 3);
  CHECK(paths.paths[0].size == 128 && paths.paths[1].size == 128 && errno == 123);
  char encoded[4096];
  CHECK(format_syscall_entry(call, 9, paths, encoded, sizeof(encoded)));
  const auto value = nlohmann::json::parse(encoded);
  CHECK(value["schema"] == 2 && value["paths"].size() == 2);
  CHECK(value["paths"][0]["bytesHex"].get<std::string>().size() == 256);
  CHECK(value["paths"][1]["status"] == "truncated");
  CHECK(!format_syscall_entry(call, 9, paths, encoded, 1024));
  call.number = 78;
  CHECK(snapshot_syscall_paths(call, read_byte).count == 1);
  call.number = 172;
  CHECK(snapshot_syscall_paths(call, read_byte).count == 0);
}

} // namespace

int main() {
  recognizes_only_arm64_svc_encodings();
  snapshots_syscall_pc_number_and_six_arguments();
  bounded_paths_preserve_partial_bytes_and_errno();
  raw_returns_and_linux_errors_do_not_invent_missing_values();
  double_paths_have_independent_arguments_and_bounded_bytes();
}
