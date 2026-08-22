#include "core/signal_broker.h"

#include <cerrno>
#include <cstring>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#if defined(__ANDROID__) && defined(__aarch64__)
#include <ucontext.h>
#endif

namespace {

std::atomic<SignalBroker *> g_active_signal_broker{nullptr};
pthread_once_t g_signal_broker_atfork_once = PTHREAD_ONCE_INIT;
std::atomic<int> g_signal_broker_atfork_error{EAGAIN};
thread_local SignalBroker *g_prepared_signal_broker = nullptr;
static_assert(std::atomic<SignalBroker *>::is_always_lock_free);
static_assert(std::atomic<SignalBrokerThreadState *>::is_always_lock_free);
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static_assert(std::atomic<uintptr_t>::is_always_lock_free);

constexpr uintptr_t kDefaultHandler = 0;
constexpr uintptr_t kIgnoreHandler = 1;

#if defined(__ANDROID__) && defined(__aarch64__)

__attribute__((always_inline)) inline long raw_rt_sigaction(
        int signal_number, const KernelSignalAction *action,
        KernelSignalAction *old_action) noexcept {
    register uint64_t x0 __asm__("x0") = static_cast<uint64_t>(signal_number);
    register uint64_t x1 __asm__("x1") = reinterpret_cast<uintptr_t>(action);
    register uint64_t x2 __asm__("x2") = reinterpret_cast<uintptr_t>(old_action);
    register uint64_t x3 __asm__("x3") = kKernelSignalSetBytes;
    register uint64_t x8 __asm__("x8") = static_cast<uint64_t>(kArm64RtSigaction);
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return static_cast<long>(x0);
}

__attribute__((always_inline)) inline long raw_rt_sigprocmask(
        int how, const uint64_t *set, uint64_t *old_set) noexcept {
    register uint64_t x0 __asm__("x0") = static_cast<uint64_t>(how);
    register uint64_t x1 __asm__("x1") = reinterpret_cast<uintptr_t>(set);
    register uint64_t x2 __asm__("x2") = reinterpret_cast<uintptr_t>(old_set);
    register uint64_t x3 __asm__("x3") = kKernelSignalSetBytes;
    register uint64_t x8 __asm__("x8") = 135U;
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return static_cast<long>(x0);
}

__attribute__((always_inline)) inline long raw_tgkill(
        int pid, int tid, int signal_number) noexcept {
    register uint64_t x0 __asm__("x0") = static_cast<uint64_t>(pid);
    register uint64_t x1 __asm__("x1") = static_cast<uint64_t>(tid);
    register uint64_t x2 __asm__("x2") = static_cast<uint64_t>(signal_number);
    register uint64_t x8 __asm__("x8") = 131U;
    __asm__ volatile("svc 0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x8)
                     : "memory", "cc");
    return static_cast<long>(x0);
}

__attribute__((always_inline)) inline int raw_getpid() noexcept {
    register uint64_t x0 __asm__("x0");
    register uint64_t x8 __asm__("x8") = 172U;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return static_cast<int>(x0);
}

__attribute__((always_inline)) inline int raw_gettid() noexcept {
    register uint64_t x0 __asm__("x0");
    register uint64_t x8 __asm__("x8") = 178U;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return static_cast<int>(x0);
}

__attribute__((always_inline)) inline void copy_signal_bytes(
        void *destination, const void *source, size_t size) noexcept {
    auto *output = static_cast<volatile unsigned char *>(destination);
    const auto *input = static_cast<const volatile unsigned char *>(source);
    for (size_t index = 0; index < size; ++index) output[index] = input[index];
}

#endif

long default_rt_sigaction(void *, int signal_number,
                          const KernelSignalAction *action,
                          KernelSignalAction *old_action) noexcept {
#if defined(__ANDROID__) && defined(__aarch64__)
    return raw_rt_sigaction(signal_number, action, old_action);
#else
    struct sigaction replacement{};
    struct sigaction previous{};
    if (action != nullptr) {
        replacement.sa_sigaction = reinterpret_cast<void (*)(int, siginfo_t *, void *)>(
                action->handler);
        replacement.sa_flags = static_cast<int>(action->flags);
        std::memcpy(&replacement.sa_mask, &action->mask, sizeof(action->mask));
    }
    if (::sigaction(signal_number, action != nullptr ? &replacement : nullptr,
                    old_action != nullptr ? &previous : nullptr) != 0) {
        return -errno;
    }
    if (old_action != nullptr) {
        old_action->handler = reinterpret_cast<uintptr_t>(previous.sa_sigaction);
        old_action->flags = static_cast<uint64_t>(previous.sa_flags);
        old_action->restorer = 0;
        std::memcpy(&old_action->mask, &previous.sa_mask,
                    sizeof(old_action->mask));
    }
    return 0;
#endif
}

long default_rt_sigprocmask(void *, int how, const uint64_t *set,
                            uint64_t *old_set) noexcept {
#if defined(__ANDROID__) && defined(__aarch64__)
    return raw_rt_sigprocmask(how, set, old_set);
#else
    sigset_t replacement{};
    sigset_t previous{};
    if (set != nullptr) std::memcpy(&replacement, set, sizeof(*set));
    const int result = ::pthread_sigmask(
            how, set != nullptr ? &replacement : nullptr,
            old_set != nullptr ? &previous : nullptr);
    if (result != 0) return -result;
    if (old_set != nullptr) std::memcpy(old_set, &previous, sizeof(*old_set));
    return 0;
#endif
}

long default_tgkill(void *, int pid, int tid, int signal_number) noexcept {
#if defined(__ANDROID__) && defined(__aarch64__)
    return raw_tgkill(pid, tid, signal_number);
#else
    const long result = ::syscall(SYS_tgkill, pid, tid, signal_number);
    return result < 0 ? -errno : result;
#endif
}

int default_getpid(void *) noexcept {
#if defined(__ANDROID__) && defined(__aarch64__)
    return raw_getpid();
#else
    return ::getpid();
#endif
}

int default_gettid(void *) noexcept {
#if defined(__ANDROID__) && defined(__aarch64__)
    return raw_gettid();
#else
    return static_cast<int>(::syscall(SYS_gettid));
#endif
}

bool default_copy_from_guest(void *, uintptr_t address, void *destination,
                             size_t size) noexcept {
    if (address == 0 || destination == nullptr || size == 0) return false;
    const iovec local{destination, size};
    const iovec remote{reinterpret_cast<void *>(address), size};
    return ::process_vm_readv(::getpid(), &local, 1, &remote, 1, 0) ==
           static_cast<ssize_t>(size);
}

bool default_copy_to_guest(void *, uintptr_t address, const void *source,
                           size_t size) noexcept {
    if (address == 0 || source == nullptr || size == 0) return false;
    const iovec local{const_cast<void *>(source), size};
    const iovec remote{reinterpret_cast<void *>(address), size};
    return ::process_vm_writev(::getpid(), &local, 1, &remote, 1, 0) ==
           static_cast<ssize_t>(size);
}

SignalBrokerPlatform default_platform() noexcept {
    return {nullptr, default_rt_sigaction, default_rt_sigprocmask,
            default_tgkill, default_getpid, default_gettid,
            default_copy_from_guest, default_copy_to_guest};
}

uint64_t signal_bit(int signal_number) noexcept {
    return signal_number > 0 && signal_number <= 64
                   ? 1ULL << static_cast<unsigned>(signal_number - 1)
                   : 0;
}

constexpr uint32_t kSignalHandlerCounterMaximum = 0xffffU;

#if defined(QTRACE_HOST_TEST)
SignalBrokerTestGate g_action_publication_gate = nullptr;
#endif

uint32_t increment_saturated(std::atomic<uint32_t> *counter) noexcept {
    uint32_t value = counter->load(std::memory_order_relaxed);
    while (value < kSignalHandlerCounterMaximum &&
           !counter->compare_exchange_weak(
                   value, value + 1U, std::memory_order_acq_rel,
                   std::memory_order_relaxed)) {}
    return value < kSignalHandlerCounterMaximum ? value + 1U : value;
}

uint32_t signal_handler_flags(uint32_t depth,
                              uint32_t nested_deliveries) noexcept {
    const uint32_t bounded_depth =
            depth < kSignalHandlerCounterMaximum
                    ? depth
                    : kSignalHandlerCounterMaximum;
    const uint32_t bounded_nested =
            nested_deliveries < kSignalHandlerCounterMaximum
                    ? nested_deliveries
                    : kSignalHandlerCounterMaximum;
    return bounded_depth | (bounded_nested << 16U);
}

void register_signal_broker_atfork() noexcept {
    g_signal_broker_atfork_error.store(
            ::pthread_atfork(signal_broker_atfork_prepare,
                             signal_broker_atfork_parent,
                             signal_broker_atfork_child),
            std::memory_order_release);
}

bool signal_broker_atfork_ready() noexcept {
    const int once_error = ::pthread_once(&g_signal_broker_atfork_once,
                                          register_signal_broker_atfork);
    if (once_error != 0) {
        g_signal_broker_atfork_error.store(once_error,
                                           std::memory_order_release);
    }
    return g_signal_broker_atfork_error.load(std::memory_order_acquire) == 0;
}

} // namespace

void signal_broker_atfork_prepare() noexcept {
    SignalBroker *broker = g_active_signal_broker.load(std::memory_order_acquire);
    if (broker == nullptr || broker->detached()) return;
    broker->update_mutex_.lock();
    g_prepared_signal_broker = broker;
}

void signal_broker_atfork_parent() noexcept {
    SignalBroker *broker = g_prepared_signal_broker;
    if (broker == nullptr) return;
    g_prepared_signal_broker = nullptr;
    broker->update_mutex_.unlock();
}

void signal_broker_atfork_child() noexcept {
    SignalBroker *broker = g_prepared_signal_broker;
    g_prepared_signal_broker = nullptr;
    if (broker != nullptr) broker->detach_after_fork_child();
}

bool SignalBrokerThreadState::initialize(
        uint32_t tid, FlightArtifact *artifact,
        const FlightThreadRegistration &registration,
        QBDI::GPRState *guest_gpr) noexcept {
    if (attached_.load(std::memory_order_acquire) || tid == 0 || artifact == nullptr ||
        guest_gpr == nullptr || !artifact->valid() || registration.tid != tid ||
        registration.directory_index == kFlightInvalidIndex) {
        return false;
    }
    tid_ = tid;
    artifact_ = artifact;
    registration_ = registration;
    Arm64SignalContext context{};
    if (!qbdi_gpr_to_signal_context(*guest_gpr, &context) ||
        !store_guest(context, guest_gpr)) return false;
    attached_.store(true, std::memory_order_release);
    return true;
}

bool SignalBrokerThreadState::publish(
        FlightRecordType type, uintptr_t pc, uintptr_t sp, uintptr_t related,
        uint32_t signal_or_syscall, uint32_t code, uint32_t flags,
        uint64_t *sequence) noexcept {
    if (!attached_.load(std::memory_order_acquire) || artifact_ == nullptr) return false;
    FlightEmergencyRecord record{};
    record.type = static_cast<uint32_t>(type);
    record.tid = tid_;
    record.sequence = artifact_->next_sequence();
    record.pc = pc;
    record.sp = sp;
    record.fault_address = related;
    record.signal_number = signal_or_syscall;
    record.signal_code = code;
    record.flags = flags & ~kFlightEmergencyCommitted;
    if (record.sequence == 0) {
        artifact_->mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        return false;
    }
    if (!artifact_->write_emergency(registration_, record)) {
        if (!artifact_->increment_dropped_coverage_gap(
                    registration_.directory_index)) {
            artifact_->mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        }
        return false;
    }
    if (sequence != nullptr) *sequence = record.sequence;
    return true;
}

bool SignalBrokerThreadState::load_guest(
        Arm64SignalContext *context, QBDI::GPRState **gpr) const noexcept {
    if (context == nullptr || !attached_.load(std::memory_order_acquire)) return false;
    const uint32_t snapshot_index =
            guest_snapshot_index_.load(std::memory_order_acquire) & 1U;
    const GuestSnapshot &snapshot = guest_snapshots_[snapshot_index];
    for (size_t index = 0; index < context->regs.size(); ++index) {
        context->regs[index] = snapshot.words[index].load(std::memory_order_relaxed);
    }
    context->sp = snapshot.words[31].load(std::memory_order_relaxed);
    context->pc = snapshot.words[32].load(std::memory_order_relaxed);
    context->pstate = snapshot.words[33].load(std::memory_order_relaxed);
    if (gpr != nullptr) {
        *gpr = snapshot.gpr.load(std::memory_order_relaxed);
    }
    return true;
}

void SignalBrokerThreadState::publish_guest(
        const Arm64SignalContext &context, QBDI::GPRState *gpr) noexcept {
    const uint32_t snapshot_index =
            (guest_snapshot_index_.load(std::memory_order_relaxed) ^ 1U) & 1U;
    GuestSnapshot &snapshot = guest_snapshots_[snapshot_index];
    for (size_t index = 0; index < context.regs.size(); ++index) {
        snapshot.words[index].store(context.regs[index], std::memory_order_relaxed);
    }
    snapshot.words[31].store(context.sp, std::memory_order_relaxed);
    snapshot.words[32].store(context.pc, std::memory_order_relaxed);
    snapshot.words[33].store(context.pstate, std::memory_order_relaxed);
    snapshot.gpr.store(gpr, std::memory_order_relaxed);
    guest_snapshot_index_.store(snapshot_index, std::memory_order_release);
}

bool SignalBrokerThreadState::store_guest(
        const Arm64SignalContext &context, QBDI::GPRState *gpr) noexcept {
    if (gpr == nullptr) return false;
    publish_guest(context, gpr);
    return signal_context_to_qbdi_gpr(context, gpr);
}

SignalBroker::SignalBroker() noexcept : SignalBroker(default_platform()) {}

SignalBroker::SignalBroker(SignalBrokerPlatform platform) noexcept
        : platform_(platform) {}

SignalBroker::~SignalBroker() {
    SignalBroker *expected = this;
    (void)g_active_signal_broker.compare_exchange_strong(
            expected, nullptr, std::memory_order_acq_rel,
            std::memory_order_acquire);
}

bool SignalBroker::platform_valid() const noexcept {
    return platform_.rt_sigaction != nullptr &&
           platform_.rt_sigprocmask != nullptr && platform_.tgkill != nullptr &&
           platform_.getpid != nullptr && platform_.gettid != nullptr &&
           platform_.copy_from_guest != nullptr &&
           platform_.copy_to_guest != nullptr;
}

bool SignalBroker::valid_signal(int signal_number) const noexcept {
    return signal_number > 0 && signal_number < static_cast<int>(kSignalCount) &&
           signal_number != SIGKILL && signal_number != SIGSTOP;
}

bool SignalBroker::install() noexcept {
    constexpr int signals[]{SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE,
                            SIGTRAP, SIGUSR1, SIGUSR2};
    return install(signals);
}

bool SignalBroker::install(std::span<const int> signal_numbers) noexcept {
    if (!platform_valid() || signal_numbers.empty() || detached() ||
        !signal_broker_atfork_ready()) return false;
    std::lock_guard<std::mutex> guard(update_mutex_);
    for (int signal_number : signal_numbers) {
        if (install_signal(signal_number) < 0) return false;
    }
    g_active_signal_broker.store(this, std::memory_order_release);
    return true;
}

long SignalBroker::install_signal(
        int signal_number,
        const KernelSignalAction *guest_semantics) noexcept {
    if (!valid_signal(signal_number)) return -EINVAL;
    ActionSlot &slot = actions_[static_cast<size_t>(signal_number)];
    KernelSignalAction incumbent{};
    const bool installed = slot.installed.load(std::memory_order_acquire);
    if (!installed) {
        const long result = platform_.rt_sigaction(
                platform_.opaque, signal_number, nullptr, &incumbent);
        if (result < 0) return result;
    }
    KernelSignalAction previous = incumbent;
    if (installed && !read_action(signal_number, &previous, nullptr)) {
        return -EAGAIN;
    }
    KernelSignalAction visible = previous;
    if (guest_semantics != nullptr) {
        visible = *guest_semantics;
    }
    const bool replace_publication = !installed || guest_semantics != nullptr;
    if (replace_publication) {
        if (!publish_action(signal_number, visible)) return -EAGAIN;
        g_active_signal_broker.store(this, std::memory_order_release);
    }
    KernelSignalAction master{};
    master.handler = master_handler_address();
    master.flags = (visible.flags & ~static_cast<uint64_t>(SA_RESETHAND)) |
                   SA_SIGINFO | SA_NODEFER;
    master.restorer = visible.restorer;
    const long result = platform_.rt_sigaction(
            platform_.opaque, signal_number, &master, nullptr);
    if (result < 0) {
        if (replace_publication && !publish_action(signal_number, previous)) {
            return -EAGAIN;
        }
        return result;
    }
    if (installed) return 0;
    slot.installed.store(true, std::memory_order_release);
    return 0;
}

bool SignalBroker::publish_action(
        int signal_number, const KernelSignalAction &action) noexcept {
    ActionSlot &slot = actions_[static_cast<size_t>(signal_number)];
    for (;;) {
        if (slot.next_generation == 0 || slot.next_generation == UINT64_MAX) {
            return false;
        }
        while (slot.acquiring_deliveries.load(std::memory_order_acquire) != 0) {
            (void)::sched_yield();
        }
#if defined(QTRACE_HOST_TEST)
        if (g_action_publication_gate != nullptr) g_action_publication_gate();
#endif
        const uint32_t current = slot.active_generation.load(
                std::memory_order_acquire);
        uint32_t target = 1;
        if (current == target) target = 2;
        ActionGeneration &generation = slot.generations[target];
        while (generation.active_deliveries.load(std::memory_order_acquire) != 0) {
            (void)::sched_yield();
        }
        if (slot.acquiring_deliveries.load(std::memory_order_acquire) != 0 ||
            slot.active_generation.load(std::memory_order_acquire) != current) {
            continue;
        }
        generation.action = action;
        generation.generation = slot.next_generation++;
        uint32_t expected = current;
        if (slot.active_generation.compare_exchange_strong(
                    expected, target, std::memory_order_release,
                    std::memory_order_acquire)) {
            return true;
        }
    }
}

#if defined(QTRACE_HOST_TEST)
void signal_broker_test_set_action_publication_gate(
        SignalBrokerTestGate gate) noexcept {
    g_action_publication_gate = gate;
}
#endif

bool SignalBroker::read_action(int signal_number, KernelSignalAction *action,
                               uint64_t *generation) const noexcept {
    if (!valid_signal(signal_number) || action == nullptr) return false;
    const ActionSlot &slot = actions_[static_cast<size_t>(signal_number)];
    slot.acquiring_deliveries.fetch_add(1, std::memory_order_acq_rel);
    const uint32_t index = slot.active_generation.load(std::memory_order_acquire);
    if (index >= slot.generations.size()) {
        slot.acquiring_deliveries.fetch_sub(1, std::memory_order_release);
        return false;
    }
    const ActionGeneration &selected = slot.generations[index];
    selected.active_deliveries.fetch_add(1, std::memory_order_acq_rel);
    slot.acquiring_deliveries.fetch_sub(1, std::memory_order_release);
    *action = selected.action;
    if (generation != nullptr) *generation = selected.generation;
    selected.active_deliveries.fetch_sub(1, std::memory_order_release);
    return true;
}

bool SignalBroker::reset_if_current(int signal_number,
                                    uint64_t generation) noexcept {
    if (!valid_signal(signal_number)) return false;
    ActionSlot &slot = actions_[static_cast<size_t>(signal_number)];
    const uint32_t current = slot.active_generation.load(std::memory_order_acquire);
    if (current >= slot.generations.size() ||
        slot.generations[current].generation != generation) return false;
    uint32_t expected = current;
    return slot.active_generation.compare_exchange_strong(
            expected, 0, std::memory_order_release, std::memory_order_acquire);
}

bool SignalBroker::publish_syscall(const Arm64SyscallSnapshot &call) noexcept {
    SignalBrokerThreadState *thread = find_thread(
            static_cast<uint32_t>(platform_.gettid(platform_.opaque)));
    return thread == nullptr || thread->publish(
            FlightRecordType::Syscall, call.pc, call.args[0], call.args[1],
            static_cast<uint32_t>(call.number),
            static_cast<uint32_t>(call.args[2]),
            static_cast<uint32_t>(call.args[3]));
}

QBDI::VMAction SignalBroker::observe_rt_sigaction(
        const Arm64SyscallSnapshot &call, QBDI::GPRState *gpr) noexcept {
    if (call.number != kArm64RtSigaction || detached()) return QBDI::CONTINUE;
    if (gpr == nullptr) return QBDI::CONTINUE;
    (void)publish_syscall(call);
    const int signal_number = static_cast<int>(call.args[0]);
    if (!platform_valid() || !valid_signal(signal_number) ||
        call.args[3] != kKernelSignalSetBytes) {
        gpr->x0 = static_cast<uint64_t>(-EINVAL);
        return QBDI::SKIP_INST;
    }

    KernelSignalAction replacement{};
    if (call.args[1] != 0 && !platform_.copy_from_guest(
                                      platform_.opaque, call.args[1], &replacement,
                                      sizeof(replacement))) {
        gpr->x0 = static_cast<uint64_t>(-EFAULT);
        return QBDI::SKIP_INST;
    }

    std::lock_guard<std::mutex> guard(update_mutex_);
    KernelSignalAction visible{};
    if (call.args[2] != 0) {
        if (!read_action(signal_number, &visible, nullptr)) {
            const long result = platform_.rt_sigaction(
                    platform_.opaque, signal_number, nullptr, &visible);
            if (result < 0) {
                gpr->x0 = static_cast<uint64_t>(result);
                return QBDI::SKIP_INST;
            }
        }
    }

    if (call.args[1] != 0) {
        const uint64_t blocked = signal_bit(signal_number);
        uint64_t saved_mask = 0;
        long result = platform_.rt_sigprocmask(
                platform_.opaque, SIG_BLOCK, &blocked, &saved_mask);
        const bool mask_saved = result >= 0;
        if (mask_saved) {
            result = install_signal(signal_number, &replacement);
            const long restore = platform_.rt_sigprocmask(
                    platform_.opaque, SIG_SETMASK, &saved_mask, nullptr);
            if (result >= 0 && restore < 0) result = restore;
        }
        if (result < 0) {
            gpr->x0 = static_cast<uint64_t>(result);
            return QBDI::SKIP_INST;
        }
    }
    if (call.args[2] != 0 &&
        !platform_.copy_to_guest(platform_.opaque, call.args[2], &visible,
                                 sizeof(visible))) {
        gpr->x0 = static_cast<uint64_t>(-EFAULT);
        return QBDI::SKIP_INST;
    }
    gpr->x0 = 0;
    return QBDI::SKIP_INST;
}

bool SignalBroker::register_thread(SignalBrokerThreadState *thread) noexcept {
    if (thread == nullptr || thread->tid_ == 0 ||
        !thread->attached_.load(std::memory_order_acquire) || detached()) {
        return false;
    }
    for (size_t offset = 0; offset < threads_.size(); ++offset) {
        const size_t index = (static_cast<size_t>(thread->tid_) + offset) %
                             threads_.size();
        SignalBrokerThreadState *expected = nullptr;
        if (threads_[index].compare_exchange_strong(
                    expected, thread, std::memory_order_release,
                    std::memory_order_acquire) || expected == thread) {
            return true;
        }
    }
    thread->artifact_->mark_incomplete(FlightIncompleteReason::EmergencyFailure);
    return false;
}

void SignalBroker::unregister_thread(SignalBrokerThreadState *thread) noexcept {
    if (thread == nullptr) return;
    for (std::atomic<SignalBrokerThreadState *> &slot : threads_) {
        SignalBrokerThreadState *expected = thread;
        if (slot.compare_exchange_strong(expected, nullptr,
                                         std::memory_order_acq_rel,
                                         std::memory_order_acquire)) break;
    }
    thread->attached_.store(false, std::memory_order_release);
}

SignalBrokerThreadState *SignalBroker::find_thread(uint32_t tid) const noexcept {
    if (tid == 0) return nullptr;
    for (size_t offset = 0; offset < threads_.size(); ++offset) {
        const size_t index = (static_cast<size_t>(tid) + offset) % threads_.size();
        SignalBrokerThreadState *thread =
                threads_[index].load(std::memory_order_acquire);
        if (thread != nullptr && thread->tid_ == tid &&
            thread->attached_.load(std::memory_order_acquire)) return thread;
    }
    return nullptr;
}

bool SignalBroker::publish_guest_state(SignalBrokerThreadState *thread,
                                       const QBDI::GPRState &gpr) noexcept {
    if (thread == nullptr || detached()) return false;
    Arm64SignalContext context{};
    if (!qbdi_gpr_to_signal_context(gpr, &context)) return false;
    thread->publish_guest(context, const_cast<QBDI::GPRState *>(&gpr));
    return true;
}

bool SignalBroker::prepare_delivery(
        int signal_number, SignalBrokerDelivery *delivery) const noexcept {
    if (delivery == nullptr || detached()) return false;
    SignalBrokerDelivery prepared{};
    prepared.valid = read_action(signal_number, &prepared.action,
                                 &prepared.generation);
    if (!prepared.valid) return false;
    *delivery = prepared;
    return true;
}

bool SignalBroker::dispatch(int signal_number, siginfo_t *info,
                            void *native_context,
                            SignalBrokerThreadState *thread) noexcept {
    SignalBrokerDelivery delivery{};
    return prepare_delivery(signal_number, &delivery) &&
           dispatch(delivery, signal_number, info, native_context, thread);
}

bool SignalBroker::raw_redeliver_default(
        int signal_number, SignalBrokerThreadState *thread) noexcept {
    const KernelSignalAction defaults{};
    const int tid = thread != nullptr ? static_cast<int>(thread->tid_)
                                      : platform_.gettid(platform_.opaque);
    return platform_.rt_sigaction(platform_.opaque, signal_number, &defaults,
                                  nullptr) >= 0 &&
           platform_.tgkill(platform_.opaque,
                            platform_.getpid(platform_.opaque), tid,
                            signal_number) >= 0;
}

bool SignalBroker::dispatch(const SignalBrokerDelivery &delivery,
                            int signal_number, siginfo_t *info,
                            void *native_context,
                            SignalBrokerThreadState *thread) noexcept {
    if (detached() || !delivery.valid || !valid_signal(signal_number)) return false;
    if (thread == nullptr) {
        thread = find_thread(static_cast<uint32_t>(
                platform_.gettid(platform_.opaque)));
    }
    if (thread == nullptr) {
        if (delivery.action.handler == kIgnoreHandler) return true;
        if (delivery.action.handler == kDefaultHandler) {
            return raw_redeliver_default(signal_number, nullptr);
        }
        uint64_t saved_mask = 0;
        (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK, nullptr,
                                       &saved_mask);
        uint64_t handler_mask = saved_mask | delivery.action.mask;
        if ((delivery.action.flags & SA_NODEFER) == 0) {
            handler_mask |= signal_bit(signal_number);
        } else {
            handler_mask &= ~signal_bit(signal_number);
            handler_mask |= delivery.action.mask;
        }
        (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK,
                                       &handler_mask, nullptr);
        if ((delivery.action.flags & SA_RESETHAND) != 0) {
            (void)reset_if_current(signal_number, delivery.generation);
        }
        if ((delivery.action.flags & SA_SIGINFO) != 0) {
            const auto handler = reinterpret_cast<
                    void (*)(int, siginfo_t *, void *)>(delivery.action.handler);
            handler(signal_number, info, native_context);
        } else {
            const auto handler =
                    reinterpret_cast<void (*)(int)>(delivery.action.handler);
            handler(signal_number);
        }
        (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK,
                                       &saved_mask, nullptr);
        return true;
    }
    const uint32_t depth = thread->active_deliveries_.fetch_add(
                                   1, std::memory_order_acq_rel) +
                           1U;
    uint32_t nested_deliveries = 0;
    if (depth == 1) {
        thread->nested_deliveries_.store(0, std::memory_order_relaxed);
    } else {
        nested_deliveries = increment_saturated(&thread->nested_deliveries_);
    }
    const uint32_t handler_flags =
            signal_handler_flags(depth, nested_deliveries);
    Arm64SignalContext guest{};
    QBDI::GPRState *guest_gpr = nullptr;
    bool have_guest = thread->load_guest(&guest, &guest_gpr);
    const bool nested_context = depth > 1 && native_context != nullptr;
#if defined(__ANDROID__) && defined(__aarch64__)
    if (nested_context) {
        const auto *interrupted = static_cast<const ucontext_t *>(native_context);
        for (size_t index = 0; index < guest.regs.size(); ++index) {
            guest.regs[index] = interrupted->uc_mcontext.regs[index];
        }
        guest.sp = interrupted->uc_mcontext.sp;
        guest.pc = interrupted->uc_mcontext.pc;
        guest.pstate = interrupted->uc_mcontext.pstate;
        have_guest = true;
    }
#else
    if (nested_context) {
        guest = static_cast<const SignalBrokerGuestContext *>(native_context)
                        ->registers;
        have_guest = true;
    }
#endif
    const uintptr_t fault = info != nullptr
                                    ? reinterpret_cast<uintptr_t>(info->si_addr)
                                    : 0;
    const uint32_t code = info != nullptr ? static_cast<uint32_t>(info->si_code) : 0;
    (void)thread->publish(FlightRecordType::Signal,
                          have_guest ? guest.pc : 0,
                          have_guest ? guest.sp : 0, fault,
                          static_cast<uint32_t>(signal_number), code,
                          handler_flags);

    if (delivery.action.handler == kIgnoreHandler) {
        thread->active_deliveries_.fetch_sub(1, std::memory_order_release);
        return true;
    }
    if (delivery.action.handler == kDefaultHandler) {
        const bool result = raw_redeliver_default(signal_number, thread);
        thread->active_deliveries_.fetch_sub(1, std::memory_order_release);
        return result;
    }
    if (!have_guest) {
        thread->artifact_->mark_incomplete(FlightIncompleteReason::EmergencyFailure);
        thread->active_deliveries_.fetch_sub(1, std::memory_order_release);
        return false;
    }

    uint64_t begin_sequence = 0;
    (void)thread->publish(FlightRecordType::SignalHandlerBegin, guest.pc,
                          guest.sp, fault,
                          static_cast<uint32_t>(signal_number), code,
                          handler_flags,
                          &begin_sequence);

    uint64_t saved_mask = 0;
    (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK, nullptr,
                                   &saved_mask);
    uint64_t interrupted_mask = saved_mask;
#if defined(__ANDROID__) && defined(__aarch64__)
    if (native_context != nullptr) {
        const auto *interrupted = static_cast<const ucontext_t *>(native_context);
        copy_signal_bytes(&interrupted_mask, &interrupted->uc_sigmask,
                          sizeof(interrupted_mask));
    }
#else
    if (nested_context) {
        interrupted_mask =
                static_cast<const SignalBrokerGuestContext *>(native_context)
                        ->signal_mask;
    }
#endif
    uint64_t delivery_mask = interrupted_mask | delivery.action.mask;
    if ((delivery.action.flags & SA_NODEFER) == 0) {
        delivery_mask |= signal_bit(signal_number);
    } else {
        delivery_mask &= ~signal_bit(signal_number);
        delivery_mask |= delivery.action.mask;
    }
    (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK,
                                   &delivery_mask, nullptr);
    if ((delivery.action.flags & SA_RESETHAND) != 0) {
        (void)reset_if_current(signal_number, delivery.generation);
    }

#if defined(__ANDROID__) && defined(__aarch64__)
    ucontext_t guest_context;
    bool mapped = native_context != nullptr;
    uint64_t returned_mask = interrupted_mask;
    if (mapped) {
        copy_signal_bytes(&guest_context, native_context, sizeof(guest_context));
        for (size_t index = 0; index < guest.regs.size(); ++index) {
            guest_context.uc_mcontext.regs[index] = guest.regs[index];
        }
        guest_context.uc_mcontext.sp = guest.sp;
        guest_context.uc_mcontext.pc = guest.pc;
        guest_context.uc_mcontext.pstate = guest.pstate;
        copy_signal_bytes(&guest_context.uc_sigmask, &interrupted_mask,
                          sizeof(interrupted_mask));
    }
    if (mapped && (delivery.action.flags & SA_SIGINFO) != 0) {
        const auto handler = reinterpret_cast<void (*)(int, siginfo_t *, void *)>(
                delivery.action.handler);
        handler(signal_number, info, &guest_context);
    } else if (mapped) {
        const auto handler = reinterpret_cast<void (*)(int)>(delivery.action.handler);
        handler(signal_number);
    }
    if (mapped) {
        for (size_t index = 0; index < guest.regs.size(); ++index) {
            guest.regs[index] = guest_context.uc_mcontext.regs[index];
        }
        guest.sp = guest_context.uc_mcontext.sp;
        guest.pc = guest_context.uc_mcontext.pc;
        guest.pstate = guest_context.uc_mcontext.pstate;
        copy_signal_bytes(&returned_mask, &guest_context.uc_sigmask,
                          sizeof(returned_mask));
        auto *interrupted = static_cast<ucontext_t *>(native_context);
        copy_signal_bytes(&interrupted->uc_sigmask, &guest_context.uc_sigmask,
                          sizeof(interrupted->uc_sigmask));
        if (nested_context) {
            for (size_t index = 0; index < guest.regs.size(); ++index) {
                interrupted->uc_mcontext.regs[index] = guest.regs[index];
            }
            interrupted->uc_mcontext.sp = guest.sp;
            interrupted->uc_mcontext.pc = guest.pc;
            interrupted->uc_mcontext.pstate = guest.pstate;
        }
    }
#else
    SignalBrokerGuestContext guest_context{guest, interrupted_mask};
    bool mapped = true;
    if ((delivery.action.flags & SA_SIGINFO) != 0) {
        const auto handler = reinterpret_cast<void (*)(int, siginfo_t *, void *)>(
                delivery.action.handler);
        handler(signal_number, info, &guest_context);
    } else {
        const auto handler = reinterpret_cast<void (*)(int)>(delivery.action.handler);
        handler(signal_number);
    }
    guest = guest_context.registers;
    const uint64_t returned_mask = guest_context.signal_mask;
    if (nested_context) {
        *static_cast<SignalBrokerGuestContext *>(native_context) = guest_context;
    }
#endif
#if defined(__ANDROID__) && defined(__aarch64__)
    (void)returned_mask;
#endif
    if (!mapped || (depth == 1 && !thread->store_guest(guest, guest_gpr))) {
        thread->artifact_->mark_incomplete(FlightIncompleteReason::EmergencyFailure);
    }
    (void)thread->publish(FlightRecordType::SignalHandlerReturn, guest.pc,
                          guest.sp, static_cast<uintptr_t>(begin_sequence),
                          static_cast<uint32_t>(signal_number), code,
                          signal_handler_flags(
                                  depth,
                                  thread->nested_deliveries_.load(
                                          std::memory_order_acquire)));
    thread->active_deliveries_.fetch_sub(1, std::memory_order_release);
#if !defined(__ANDROID__) || !defined(__aarch64__)
    const uint64_t restore_mask =
            (delivery.action.flags & SA_SIGINFO) != 0
                    ? returned_mask
                    : saved_mask;
    (void)platform_.rt_sigprocmask(platform_.opaque, SIG_SETMASK, &restore_mask,
                                   nullptr);
#endif
    return mapped;
}

void SignalBroker::detach_after_fork_child() noexcept {
    bool restored_all = true;
    for (size_t index = 1; index < actions_.size(); ++index) {
        ActionSlot &slot = actions_[index];
        if (!slot.installed.load(std::memory_order_acquire)) continue;
        KernelSignalAction visible{};
        const bool readable = read_action(static_cast<int>(index), &visible,
                                          nullptr);
        const KernelSignalAction defaults{};
        const KernelSignalAction *replacement = readable ? &visible : &defaults;
        long result = platform_.rt_sigaction(
                platform_.opaque, static_cast<int>(index), replacement, nullptr);
        if (result < 0 && readable) {
            result = platform_.rt_sigaction(
                    platform_.opaque, static_cast<int>(index), &defaults, nullptr);
        }
        if (result < 0) {
            restored_all = false;
            if (!readable) (void)publish_action(static_cast<int>(index), defaults);
        }
    }
    for (std::atomic<SignalBrokerThreadState *> &slot : threads_) {
        slot.store(nullptr, std::memory_order_release);
    }
    if (restored_all) {
        detached_.store(true, std::memory_order_release);
        SignalBroker *expected = this;
        (void)g_active_signal_broker.compare_exchange_strong(
                expected, nullptr, std::memory_order_acq_rel,
                std::memory_order_acquire);
    } else {
        detached_.store(false, std::memory_order_release);
        g_active_signal_broker.store(this, std::memory_order_release);
    }
}

uintptr_t SignalBroker::master_handler_address() const noexcept {
    return reinterpret_cast<uintptr_t>(master_handler);
}

SignalBroker &SignalBroker::process() noexcept {
    static SignalBroker broker;
    return broker;
}

__attribute__((no_stack_protector)) void SignalBroker::master_handler(
        int signal_number, siginfo_t *info, void *native_context) noexcept {
    SignalBroker *broker = g_active_signal_broker.load(std::memory_order_acquire);
    if (broker != nullptr && !broker->detached()) {
        (void)broker->dispatch(signal_number, info, native_context, nullptr);
    }
}

bool TerminationObserver::is_termination_syscall(int64_t number) noexcept {
    switch (number) {
        case 93:
        case 94:
        case 129:
        case 130:
        case 131:
        case 138:
            return true;
        default:
            return false;
    }
}

QBDI::VMAction TerminationObserver::before_svc(
        const Arm64SyscallSnapshot &snapshot,
        SignalBrokerThreadState *writer) noexcept {
    if (!is_termination_syscall(snapshot.number) || writer == nullptr) {
        return QBDI::CONTINUE;
    }
    (void)writer->publish(
            FlightRecordType::TerminationIntent, snapshot.pc, snapshot.args[0],
            snapshot.args[1], static_cast<uint32_t>(snapshot.number),
            static_cast<uint32_t>(snapshot.args[2]),
            static_cast<uint32_t>(snapshot.args[3]));
    return QBDI::CONTINUE;
}

void detach_process_signal_broker_after_fork_child() noexcept {
    SignalBroker *broker = g_active_signal_broker.load(std::memory_order_acquire);
    if (broker != nullptr) broker->detach_after_fork_child();
}
