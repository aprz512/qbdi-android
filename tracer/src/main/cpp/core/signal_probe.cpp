#include "core/signal_probe.h"

#include "core/arm64_syscall.h"
#include "core/signal_context_arm64.h"

#include <QBDI.h>
#include <QBDI/State.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

constexpr uint64_t kSignalProbeCookie = 0x514244495349474eULL;
constexpr int64_t kArm64Tgkill = 131;
constexpr int64_t kArm64RtSigaction = 134;
constexpr int64_t kArm64Gettid = 178;
constexpr uint64_t kKernelSignalSetBytes = 8U;
constexpr uint32_t kProbeGuestCalled = 1U << 0U;
constexpr uint32_t kProbeGuestPcOriginal = 1U << 1U;
constexpr uint32_t kProbeRegisterCookie = 1U << 2U;
constexpr uint32_t kProbeQbdiHandlerTraced = 1U << 3U;
constexpr uint32_t kProbeHandlerQueryHidden = 1U << 4U;
constexpr uint32_t kProbeVirtualStackBytes = 0x100000U;
constexpr sig_atomic_t kHandlerBeginMarker = 0x13579bdf;
constexpr sig_atomic_t kHandlerReturnMarker = 0x2468ace0;

struct KernelSigaction {
  void (*handler)(int, siginfo_t *, void *) = nullptr;
  uint64_t flags = 0;
  void (*restorer)() = nullptr;
  uint64_t mask = 0;
};

struct SignalProbeState {
  QBDI::VM primary_vm;
  QBDI::GPRState interrupted_gpr{};
  QBDI::GPRState restored_gpr{};
  KernelSigaction guest_action{};
  struct sigaction incumbent_action {};
  uint8_t *primary_stack = nullptr;
  uintptr_t guest_handler = 0;
  int signal_number = SIGUSR2;
  std::atomic<bool> signal_completed{false};
  volatile sig_atomic_t handler_instruction_count = 0;
  volatile sig_atomic_t handler_begin_marker = 0;
  volatile sig_atomic_t handler_return_marker = 0;
  std::atomic<bool> dispatch_ready{false};
  bool master_installed = false;
  bool guest_action_valid = false;
  bool awaiting_restore = false;
  bool restore_applied = false;
};

static_assert(std::atomic<SignalProbeState *>::is_always_lock_free);
static_assert(std::atomic<int>::is_always_lock_free);
static_assert(std::atomic<bool>::is_always_lock_free);

std::atomic<SignalProbeState *> g_active_probe{nullptr};
std::atomic<int> g_active_probe_tid{0};
std::atomic_flag g_probe_claimed = ATOMIC_FLAG_INIT;

__attribute__((always_inline)) inline int raw_gettid() noexcept {
  register uint64_t x0 __asm__("x0");
  register uint64_t x8 __asm__("x8") = static_cast<uint64_t>(kArm64Gettid);
  __asm__ volatile("svc 0" : "=r"(x0) : "r"(x8) : "memory", "cc");
  return static_cast<int>(x0);
}

__attribute__((no_stack_protector)) void
signal_probe_master_handler(int signal_number, siginfo_t *info,
                            void *) noexcept {
  if (g_active_probe_tid.load(std::memory_order_acquire) != raw_gettid())
    return;
  SignalProbeState *state = g_active_probe.load(std::memory_order_acquire);
  if (state == nullptr || !state->guest_action_valid ||
      state->guest_action.handler == nullptr ||
      !state->dispatch_ready.load(std::memory_order_acquire))
    return;
  state->dispatch_ready.store(false, std::memory_order_relaxed);

  ucontext_t guest_context;
  if (!qbdi_gpr_to_ucontext(state->interrupted_gpr, &guest_context))
    return;

  state->handler_begin_marker = kHandlerBeginMarker;
  state->guest_action.handler(signal_number, info, &guest_context);
  state->handler_return_marker = kHandlerReturnMarker;
  if (!ucontext_to_qbdi_gpr(guest_context, &state->restored_gpr))
    return;

  state->signal_completed.store(true, std::memory_order_release);
}

bool install_master_action(SignalProbeState *state) noexcept {
  if (state == nullptr)
    return false;
  if (state->master_installed)
    return true;
  struct sigaction master_action {};
  master_action.sa_sigaction = signal_probe_master_handler;
  master_action.sa_flags = SA_SIGINFO;
  if (sigemptyset(&master_action.sa_mask) != 0 ||
      sigaction(state->signal_number, &master_action,
                &state->incumbent_action) != 0) {
    return false;
  }
  state->master_installed = true;
  return true;
}

QBDI::VMAction emulate_rt_sigaction(SignalProbeState *state,
                                    const Arm64SyscallSnapshot &call,
                                    QBDI::GPRState *gpr) noexcept {
  if (state == nullptr || gpr == nullptr)
    return QBDI::STOP;
  if (call.args[0] != static_cast<uint64_t>(state->signal_number) ||
      call.args[3] != kKernelSignalSetBytes) {
    gpr->x0 = static_cast<uint64_t>(-EINVAL);
    return QBDI::SKIP_INST;
  }

  auto *old_action = reinterpret_cast<KernelSigaction *>(call.args[2]);
  if (old_action != nullptr) {
    const KernelSigaction visible =
        state->guest_action_valid ? state->guest_action : KernelSigaction{};
    std::memcpy(old_action, &visible, sizeof(visible));
  }

  const auto *new_action =
      reinterpret_cast<const KernelSigaction *>(call.args[1]);
  if (new_action != nullptr) {
    KernelSigaction guest_action{};
    std::memcpy(&guest_action, new_action, sizeof(guest_action));
    const uintptr_t handler = reinterpret_cast<uintptr_t>(guest_action.handler);
    if (handler == 0 || handler == 1 || !install_master_action(state)) {
      gpr->x0 = static_cast<uint64_t>(-EINVAL);
      return QBDI::SKIP_INST;
    }
    state->guest_action = guest_action;
    state->guest_handler = handler;
    state->guest_action_valid = true;
  }

  gpr->x0 = 0;
  return QBDI::SKIP_INST;
}

bool restore_guest_after_signal(SignalProbeState *state,
                                QBDI::GPRState *gpr) noexcept {
  if (state == nullptr || gpr == nullptr || !state->awaiting_restore ||
      !state->signal_completed.load(std::memory_order_acquire)) {
    return false;
  }
  const uint64_t syscall_result = gpr->x0;
  const uintptr_t continuation_pc = gpr->pc;
  const bool handler_changed_x0 =
      state->restored_gpr.x0 != state->interrupted_gpr.x0;
  const bool handler_changed_pc =
      state->restored_gpr.pc != state->interrupted_gpr.pc;
  *gpr = state->restored_gpr;
  if (!handler_changed_x0)
    gpr->x0 = syscall_result;
  if (!handler_changed_pc)
    gpr->pc = continuation_pc;
  state->awaiting_restore = false;
  state->restore_applied = true;
  return handler_changed_pc;
}

QBDI::VMAction on_primary_instruction(QBDI::VM *, QBDI::GPRState *gpr,
                                      QBDI::FPRState *, void *opaque) {
  auto *state = static_cast<SignalProbeState *>(opaque);
  if (state == nullptr || gpr == nullptr)
    return QBDI::STOP;

  if (restore_guest_after_signal(state, gpr))
    return QBDI::BREAK_TO_VM;

  if (state->guest_handler != 0 && gpr->pc == state->guest_handler) {
    state->handler_instruction_count = 1;
  }

  uint32_t opcode = 0;
  std::memcpy(&opcode, reinterpret_cast<const void *>(gpr->pc), sizeof(opcode));
  if (!is_arm64_svc(opcode))
    return QBDI::CONTINUE;

  const Arm64SyscallSnapshot call = snapshot_arm64_syscall(gpr->pc, *gpr);
  if (call.number == kArm64RtSigaction) {
    return emulate_rt_sigaction(state, call, gpr);
  }
  if (call.number == kArm64Tgkill &&
      call.args[2] == static_cast<uint64_t>(state->signal_number)) {
    state->interrupted_gpr = *gpr;
    state->signal_completed.store(false, std::memory_order_relaxed);
    state->handler_begin_marker = 0;
    state->handler_return_marker = 0;
    state->dispatch_ready.store(true, std::memory_order_release);
    state->awaiting_restore = true;
    state->restore_applied = false;
  }
  return QBDI::CONTINUE;
}

void release_probe_state(SignalProbeState *state) noexcept {
  if (state == nullptr)
    return;
  g_active_probe.store(nullptr, std::memory_order_release);
  g_active_probe_tid.store(0, std::memory_order_release);
  if (state->master_installed) {
    (void)sigaction(state->signal_number, &state->incumbent_action, nullptr);
    state->master_installed = false;
  }
  if (state->primary_stack != nullptr) {
    QBDI::alignedFree(state->primary_stack);
    state->primary_stack = nullptr;
  }
  g_probe_claimed.clear(std::memory_order_release);
}

uint32_t result_bits(const SignalProbeResult &result) noexcept {
  uint32_t bits = 0;
  if (result.guest_handler_called)
    bits |= kProbeGuestCalled;
  if (result.guest_pc_original)
    bits |= kProbeGuestPcOriginal;
  if (result.register_cookie)
    bits |= kProbeRegisterCookie;
  if (result.qbdi_handler_traced)
    bits |= kProbeQbdiHandlerTraced;
  if (result.handler_query_hidden)
    bits |= kProbeHandlerQueryHidden;
  return bits;
}

} // namespace

SignalProbeResult run_native_signal_probe(uintptr_t entry,
                                          uintptr_t module_address) noexcept {
  SignalProbeResult result{};
  if (entry == 0 || module_address == 0)
    return result;
  if (g_probe_claimed.test_and_set(std::memory_order_acquire))
    return result;

  SignalProbeState state{};
  QBDI::GPRState *primary_gpr = state.primary_vm.getGPRState();
  const bool stacks_ready =
      primary_gpr != nullptr &&
      QBDI::allocateVirtualStack(primary_gpr, kProbeVirtualStackBytes,
                                 &state.primary_stack);
  if (!stacks_ready) {
    release_probe_state(&state);
    return result;
  }
  const bool modules_ready =
      state.primary_vm.addInstrumentedModuleFromAddr(module_address);
  const uint32_t primary_callback =
      modules_ready ? state.primary_vm.addCodeCB(QBDI::PREINST,
                                                 on_primary_instruction, &state)
                    : static_cast<uint32_t>(QBDI::INVALID_EVENTID);
  if (!modules_ready || primary_callback == QBDI::INVALID_EVENTID) {
    release_probe_state(&state);
    return result;
  }

  g_active_probe.store(&state, std::memory_order_release);
  g_active_probe_tid.store(raw_gettid(), std::memory_order_release);
  const QBDI::rword cookie = kSignalProbeCookie;
  QBDI::rword target_bits = 0;
  const bool target_called =
      state.primary_vm.callA(&target_bits, entry, 1U, &cookie);

  release_probe_state(&state);
  if (!target_called)
    return result;

  const uint32_t bits = static_cast<uint32_t>(target_bits);
  result.guest_handler_called =
      (bits & kProbeGuestCalled) != 0 &&
      state.handler_begin_marker == kHandlerBeginMarker &&
      state.handler_return_marker == kHandlerReturnMarker;
  result.guest_pc_original = (bits & kProbeGuestPcOriginal) != 0;
  result.register_cookie =
      (bits & kProbeRegisterCookie) != 0 && state.restore_applied;
  result.qbdi_handler_traced = state.handler_instruction_count != 0;
  result.handler_query_hidden = (bits & kProbeHandlerQueryHidden) != 0;
  return result;
}

extern "C" uint32_t qbdi_signal_probe_bits(uintptr_t entry,
                                           uintptr_t module_address) noexcept {
  return result_bits(run_native_signal_probe(entry, module_address));
}
