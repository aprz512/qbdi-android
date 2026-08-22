#include "core/signal_broker.h"
#include "core/instruction_collector.h"

#include "flight/flight_artifact.h"

#include <QBDI/State.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

std::atomic<uint32_t> g_qbdi_execution_calls{0};

namespace QBDI {

const InstAnalysis *VM::getInstAnalysis(AnalysisType) const { return nullptr; }
std::vector<MemoryAccess> VM::getInstMemoryAccess() const { return {}; }
bool VM::run(rword, rword) {
    g_qbdi_execution_calls.fetch_add(1, std::memory_order_relaxed);
    return false;
}
bool VM::call(rword *, rword, const std::vector<rword> &) {
    g_qbdi_execution_calls.fetch_add(1, std::memory_order_relaxed);
    return false;
}
bool VM::callA(rword *, rword, uint32_t, const rword *) {
    g_qbdi_execution_calls.fetch_add(1, std::memory_order_relaxed);
    return false;
}

} // namespace QBDI

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

constexpr uintptr_t kNormalHandler = 0x71000100U;
constexpr uintptr_t kSiginfoHandler = 0x71000200U;
int g_install_race_calls = 0;
int g_replacement_old_calls = 0;
int g_replacement_new_calls = 0;
int g_fallback_calls = 0;

void install_race_handler(int) { ++g_install_race_calls; }
void replacement_old_handler(int) { ++g_replacement_old_calls; }
void replacement_new_handler(int) { ++g_replacement_new_calls; }
void errno_handler(int) { errno = EDOM; }
void fallback_handler(int);
volatile sig_atomic_t g_child_signal_calls = 0;
volatile sig_atomic_t g_production_master_calls = 0;
std::atomic<uint32_t> g_snapshot_signal_calls{0};
std::atomic<bool> g_snapshot_was_torn{false};
SignalBrokerThreadState *g_snapshot_thread = nullptr;

void child_signal_handler(int) { g_child_signal_calls = 1; }
void production_master_handler(int, siginfo_t *, void *) {
    g_production_master_calls = g_production_master_calls + 1;
}

void snapshot_consistency_handler(int, siginfo_t *, void *) {
    g_snapshot_signal_calls.fetch_add(1, std::memory_order_relaxed);
    Arm64SignalContext guest{};
    if (g_snapshot_thread == nullptr ||
        !g_snapshot_thread->test_load_guest(&guest)) {
        g_snapshot_was_torn.store(true, std::memory_order_relaxed);
        return;
    }
    const uint64_t expected = guest.regs[0];
    for (uint64_t value : guest.regs) {
        if (value != expected) {
            g_snapshot_was_torn.store(true, std::memory_order_relaxed);
        }
    }
    if (guest.sp != expected || guest.pc != expected ||
        guest.pstate != expected) {
        g_snapshot_was_torn.store(true, std::memory_order_relaxed);
    }
}

struct FakeKernel {
    std::array<KernelSignalAction, NSIG> actions{};
    uint64_t mask = 0;
    uintptr_t denied_address = 0;
    int action_calls = 0;
    int mask_calls = 0;
    int tgkill_calls = 0;
    int last_pid = 0;
    int last_tid = 0;
    int last_signal = 0;
    long replacement_error = 0;
    uint32_t replacement_failures = 0;
    bool deliver_during_replacement = false;
    void (*after_mask_set)(FakeKernel *) = nullptr;

    static long rt_sigaction(void *opaque, int signal_number,
                             const KernelSignalAction *action,
                             KernelSignalAction *old_action) noexcept {
        auto *self = static_cast<FakeKernel *>(opaque);
        ++self->action_calls;
        if (signal_number <= 0 || signal_number >= NSIG ||
            signal_number == SIGKILL || signal_number == SIGSTOP) {
            return -EINVAL;
        }
        if (old_action != nullptr) *old_action = self->actions[signal_number];
        if (action != nullptr) {
            if (self->replacement_error != 0) {
                const long error = self->replacement_error;
                if (self->replacement_failures > 0) {
                    --self->replacement_failures;
                }
                if (self->replacement_failures == 0) {
                    self->replacement_error = 0;
                }
                return error;
            }
            self->actions[signal_number] = *action;
            if (self->deliver_during_replacement) {
                self->deliver_during_replacement = false;
                const auto handler = reinterpret_cast<
                        void (*)(int, siginfo_t *, void *)>(action->handler);
                handler(signal_number, nullptr, nullptr);
            }
        }
        return 0;
    }

    static long rt_sigprocmask(void *opaque, int how, const uint64_t *set,
                               uint64_t *old_set) noexcept {
        auto *self = static_cast<FakeKernel *>(opaque);
        ++self->mask_calls;
        if (old_set != nullptr) *old_set = self->mask;
        if (set == nullptr) return 0;
        if (how == SIG_SETMASK) self->mask = *set;
        else if (how == SIG_BLOCK) self->mask |= *set;
        else if (how == SIG_UNBLOCK) self->mask &= ~*set;
        else return -EINVAL;
        if (self->after_mask_set != nullptr) {
            void (*callback)(FakeKernel *) = self->after_mask_set;
            self->after_mask_set = nullptr;
            callback(self);
        }
        return 0;
    }

    static long tgkill(void *opaque, int pid, int tid,
                       int signal_number) noexcept {
        auto *self = static_cast<FakeKernel *>(opaque);
        ++self->tgkill_calls;
        self->last_pid = pid;
        self->last_tid = tid;
        self->last_signal = signal_number;
        return 0;
    }

    static int getpid(void *) noexcept { return 4242; }
    static int gettid(void *) noexcept { return 731; }

    static bool copy_from_guest(void *opaque, uintptr_t address, void *destination,
                                size_t size) noexcept {
        auto *self = static_cast<FakeKernel *>(opaque);
        if (address == 0 || address == self->denied_address ||
            destination == nullptr || size == 0) return false;
        std::memcpy(destination, reinterpret_cast<const void *>(address), size);
        return true;
    }

    static bool copy_to_guest(void *opaque, uintptr_t address, const void *source,
                              size_t size) noexcept {
        auto *self = static_cast<FakeKernel *>(opaque);
        if (address == 0 || address == self->denied_address || source == nullptr ||
            size == 0) return false;
        std::memcpy(reinterpret_cast<void *>(address), source, size);
        return true;
    }

    SignalBrokerPlatform platform() noexcept {
        return {this, rt_sigaction, rt_sigprocmask, tgkill, getpid, gettid,
                copy_from_guest, copy_to_guest};
    }
};

std::atomic<bool> *g_install_window_release = nullptr;

void release_install_window_before_fork() {
    if (g_install_window_release != nullptr) {
        g_install_window_release->store(true, std::memory_order_release);
    }
}

struct RealInstallWindowPlatform {
    std::atomic<bool> master_exposed{false};
    std::atomic<bool> release_master_install{false};
    std::atomic<bool> gate_next_replacement{true};

    static long rt_sigaction(void *opaque, int signal_number,
                             const KernelSignalAction *action,
                             KernelSignalAction *old_action) noexcept {
        auto *self = static_cast<RealInstallWindowPlatform *>(opaque);
        struct sigaction replacement{};
        struct sigaction previous{};
        if (action != nullptr) {
            replacement.sa_sigaction = reinterpret_cast<
                    void (*)(int, siginfo_t *, void *)>(action->handler);
            replacement.sa_flags = static_cast<int>(action->flags);
            std::memcpy(&replacement.sa_mask, &action->mask,
                        sizeof(action->mask));
        }
        if (::sigaction(signal_number,
                        action != nullptr ? &replacement : nullptr,
                        old_action != nullptr ? &previous : nullptr) != 0) {
            return -errno;
        }
        if (old_action != nullptr) {
            old_action->handler = reinterpret_cast<uintptr_t>(
                    previous.sa_sigaction);
            old_action->flags = static_cast<uint64_t>(previous.sa_flags);
            old_action->restorer = 0;
            std::memcpy(&old_action->mask, &previous.sa_mask,
                        sizeof(old_action->mask));
        }
        if (action != nullptr &&
            self->gate_next_replacement.exchange(false,
                                                 std::memory_order_acq_rel)) {
            self->master_exposed.store(true, std::memory_order_release);
            while (!self->release_master_install.load(std::memory_order_acquire)) {}
        }
        return 0;
    }

    static long rt_sigprocmask(void *, int how, const uint64_t *set,
                               uint64_t *old_set) noexcept {
        sigset_t replacement{};
        sigset_t previous{};
        if (set != nullptr) std::memcpy(&replacement, set, sizeof(*set));
        const int result = ::pthread_sigmask(
                how, set != nullptr ? &replacement : nullptr,
                old_set != nullptr ? &previous : nullptr);
        if (result != 0) return -result;
        if (old_set != nullptr) std::memcpy(old_set, &previous, sizeof(*old_set));
        return 0;
    }

    static long tgkill(void *, int pid, int tid, int signal_number) noexcept {
        const long result = ::syscall(SYS_tgkill, pid, tid, signal_number);
        return result < 0 ? -errno : result;
    }

    static int getpid(void *) noexcept { return ::getpid(); }
    static int gettid(void *) noexcept {
        return static_cast<int>(::syscall(SYS_gettid));
    }

    static bool copy_from_guest(void *, uintptr_t address, void *destination,
                                size_t size) noexcept {
        if (address == 0 || destination == nullptr || size == 0) return false;
        std::memcpy(destination, reinterpret_cast<const void *>(address), size);
        return true;
    }

    static bool copy_to_guest(void *, uintptr_t address, const void *source,
                              size_t size) noexcept {
        if (address == 0 || source == nullptr || size == 0) return false;
        std::memcpy(reinterpret_cast<void *>(address), source, size);
        return true;
    }

    SignalBrokerPlatform platform() noexcept {
        return {this, rt_sigaction, rt_sigprocmask, tgkill, getpid, gettid,
                copy_from_guest, copy_to_guest};
    }
};

struct ArtifactFixture {
    explicit ArtifactFixture(uint32_t tid = 731) {
        char directory_template[] = "/tmp/qtrace-signal-broker-XXXXXX";
        char *created = ::mkdtemp(directory_template);
        CHECK(created != nullptr);
        directory = created;
        path = directory + "/artifact.flight.bin";
        FlightOptions options{};
        options.enabled = true;
        options.capacity_bytes = 8ULL * 1024U * 1024U;
        options.chunk_bytes = 256U * 1024U;
        options.max_threads = 2;
        options.protected_chunks = 1;
        static constexpr char target[] = "libtarget.so";
        const FlightArtifactIdentityView identity{
                0x12345678U, 4242, 9, target,
                static_cast<uint16_t>(sizeof(target) - 1U)};
        CHECK(artifact.create(path.c_str(), options, identity));
        CHECK(artifact.register_thread(tid, &registration));
        for (size_t index = 0; index < 31; ++index) {
            QBDI_GPR_SET(&gpr, index, 0x1000U + index);
        }
        gpr.sp = 0x81000000U;
        gpr.pc = 0x71001234U;
        gpr.nzcv = 0x60000000U;
        CHECK(thread.initialize(tid, &artifact, registration, &gpr));
    }

    ~ArtifactFixture() {
        artifact.close();
        (void)::unlink(path.c_str());
        (void)::rmdir(directory.c_str());
    }

    FlightEmergencyRecord emergency() const {
        FlightEmergencyRecord record{};
        CHECK(scan_flight_emergency(
                artifact.emergency_bytes(registration.directory_index), &record));
        return record;
    }

    std::string directory;
    std::string path;
    FlightArtifact artifact;
    FlightThreadRegistration registration{};
    QBDI::GPRState gpr{};
    SignalBrokerThreadState thread{};
};

Arm64SyscallSnapshot sigaction_call(int signal_number,
                                    const KernelSignalAction *action,
                                    KernelSignalAction *old_action,
                                    uint64_t signal_set_bytes = 8) {
    Arm64SyscallSnapshot call{};
    call.pc = 0x71002000U;
    call.number = kArm64RtSigaction;
    call.args = {static_cast<uint64_t>(signal_number),
                 reinterpret_cast<uintptr_t>(action),
                 reinterpret_cast<uintptr_t>(old_action), signal_set_bytes, 0, 0};
    return call;
}

void incumbent_is_visible_before_the_kernel_can_deliver_to_master() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(install_race_handler), 0, 0, 0};
    kernel.deliver_during_replacement = true;
    g_install_race_calls = 0;
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};

    CHECK(broker.install(signals));

    CHECK(g_install_race_calls == 1);
}

std::atomic<bool> g_action_publication_entered{false};
std::atomic<bool> g_action_publication_release{false};
std::atomic<bool> g_action_reset_entered{false};
std::atomic<bool> g_action_reset_release{false};

void action_publication_gate() {
    g_action_publication_entered.store(true, std::memory_order_release);
    while (!g_action_publication_release.load(std::memory_order_acquire)) {}
}

void action_reset_gate() {
    g_action_reset_entered.store(true, std::memory_order_release);
    while (!g_action_reset_release.load(std::memory_order_acquire)) {}
}

void concurrent_action_replacement_never_swallows_a_delivery() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(replacement_old_handler), 0, 0, 0};
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));
    const auto master = reinterpret_cast<void (*)(int, siginfo_t *, void *)>(
            kernel.actions[SIGUSR1].handler);
    KernelSignalAction replacement{
            reinterpret_cast<uintptr_t>(replacement_new_handler), 0, 0, 0};
    QBDI::GPRState gpr{};
    g_replacement_old_calls = 0;
    g_replacement_new_calls = 0;
    g_action_publication_entered.store(false, std::memory_order_relaxed);
    g_action_publication_release.store(false, std::memory_order_relaxed);
    signal_broker_test_set_action_publication_gate(action_publication_gate);

    std::thread updater([&] {
        CHECK(broker.observe_rt_sigaction(
                      sigaction_call(SIGUSR1, &replacement, nullptr), &gpr) ==
              QBDI::SKIP_INST);
    });
    while (!g_action_publication_entered.load(std::memory_order_acquire)) {}
    master(SIGUSR1, nullptr, nullptr);
    g_action_publication_release.store(true, std::memory_order_release);
    updater.join();
    signal_broker_test_set_action_publication_gate(nullptr);

    CHECK(g_replacement_old_calls + g_replacement_new_calls == 1);
}

void reset_generation_stays_pinned_while_reset_reads_it() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    KernelSignalAction reset_action{
            reinterpret_cast<uintptr_t>(replacement_old_handler),
            SA_RESETHAND, 0, 0};
    QBDI::GPRState gpr{};
    CHECK(broker.observe_rt_sigaction(
                  sigaction_call(SIGUSR1, &reset_action, nullptr), &gpr) ==
          QBDI::SKIP_INST);
    g_replacement_old_calls = 0;
    g_action_reset_entered.store(false, std::memory_order_relaxed);
    g_action_reset_release.store(false, std::memory_order_relaxed);
    signal_broker_test_set_action_reset_gate(action_reset_gate);

    std::thread delivery([&] {
        CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, nullptr));
    });
    while (!g_action_reset_entered.load(std::memory_order_acquire)) {}
    CHECK(broker.test_active_action_readers(SIGUSR1) == 1);
    g_action_reset_release.store(true, std::memory_order_release);
    delivery.join();
    signal_broker_test_set_action_reset_gate(nullptr);

    CHECK(g_replacement_old_calls == 1);
}

void kernel_master_never_precedes_replacement_guest_semantics() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(replacement_old_handler), 0, 0, 0};
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));
    KernelSignalAction replacement{
            reinterpret_cast<uintptr_t>(replacement_new_handler), 0, 0, 0};
    QBDI::GPRState gpr{};
    g_replacement_old_calls = 0;
    g_replacement_new_calls = 0;
    kernel.deliver_during_replacement = true;

    CHECK(broker.observe_rt_sigaction(
                  sigaction_call(SIGUSR1, &replacement, nullptr), &gpr) ==
          QBDI::SKIP_INST);

    CHECK(g_replacement_old_calls == 0);
    CHECK(g_replacement_new_calls == 1);
}

void master_preserves_the_incumbent_handlers_errno_semantics() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(errno_handler), 0, 0, 0};
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));
    const auto master = reinterpret_cast<void (*)(int, siginfo_t *, void *)>(
            kernel.actions[SIGUSR1].handler);
    errno = EAGAIN;

    master(SIGUSR1, nullptr, nullptr);

    CHECK(errno == EDOM);
}

void fork_child_detach_restores_native_delivery_before_clearing_broker() {
    struct sigaction previous{};
    CHECK(::sigaction(SIGUSR1, nullptr, &previous) == 0);
    struct sigaction guest{};
    guest.sa_handler = child_signal_handler;
    CHECK(::sigemptyset(&guest.sa_mask) == 0);
    CHECK(::sigaction(SIGUSR1, &guest, nullptr) == 0);
    SignalBroker broker;
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        g_child_signal_calls = 0;
        broker.detach_after_fork_child();
        if (::raise(SIGUSR1) != 0) _exit(2);
        _exit(g_child_signal_calls == 1 ? 0 : 3);
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    CHECK(::sigaction(SIGUSR1, &previous, nullptr) == 0);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

void fork_waits_for_initial_master_publication_and_restores_child_disposition() {
    struct sigaction previous{};
    CHECK(::sigaction(SIGUSR1, nullptr, &previous) == 0);
    struct sigaction incumbent{};
    incumbent.sa_handler = child_signal_handler;
    CHECK(::sigemptyset(&incumbent.sa_mask) == 0);
    CHECK(::sigaction(SIGUSR1, &incumbent, nullptr) == 0);
    RealInstallWindowPlatform real;
    SignalBroker broker(real.platform());
    const int signals[]{SIGUSR1};
    std::atomic<bool> installed{false};
    std::thread installer([&] {
        installed.store(broker.install(signals), std::memory_order_release);
    });
    while (!real.master_exposed.load(std::memory_order_acquire)) {}
    g_install_window_release = &real.release_master_install;
    CHECK(::pthread_atfork(release_install_window_before_fork, nullptr, nullptr) ==
          0);

    const pid_t child = ::fork();
    CHECK(child >= 0);
    if (child == 0) {
        struct sigaction child_action{};
        if (::sigaction(SIGUSR1, nullptr, &child_action) != 0) _exit(2);
        const bool restored = child_action.sa_handler == child_signal_handler;
        g_child_signal_calls = 0;
        if (::raise(SIGUSR1) != 0) _exit(3);
        _exit(restored && g_child_signal_calls == 1 ? 0 : 4);
    }
    int status = 0;
    CHECK(::waitpid(child, &status, 0) == child);
    installer.join();
    g_install_window_release = nullptr;
    CHECK(::sigaction(SIGUSR1, &previous, nullptr) == 0);
    CHECK(installed.load(std::memory_order_acquire));
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

void failed_child_restore_keeps_master_fail_open_to_incumbent() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(fallback_handler), 0, 0, 0};
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));
    const uintptr_t master = kernel.actions[SIGUSR1].handler;
    kernel.replacement_error = -EPERM;
    kernel.replacement_failures = 2;
    g_fallback_calls = 0;

    broker.detach_after_fork_child();

    CHECK(!broker.detached());
    CHECK(kernel.actions[SIGUSR1].handler == master);
    const auto installed_master = reinterpret_cast<
            void (*)(int, siginfo_t *, void *)>(master);
    installed_master(SIGUSR1, nullptr, nullptr);
    CHECK(g_fallback_calls == 1);
}

void install_query_replace_lazy_install_and_guarded_memory_match_kernel_abi() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {0x12340000U, SA_RESTART, 0x12340100U, 0x44U};
    SignalBroker broker(kernel.platform());
    const int initial_signals[]{SIGUSR1};
    CHECK(broker.install(initial_signals));
    const uintptr_t master = kernel.actions[SIGUSR1].handler;
    CHECK(master != 0 && master != 1 && master != 0x12340000U);
    CHECK((kernel.actions[SIGUSR1].flags & SA_RESTART) != 0);
    CHECK(kernel.actions[SIGUSR1].restorer == 0x12340100U);
    CHECK(broker.install(initial_signals));
    CHECK(kernel.actions[SIGUSR1].handler == master);
    CHECK((kernel.actions[SIGUSR1].flags & SA_RESTART) != 0);
    CHECK(kernel.actions[SIGUSR1].restorer == 0x12340100U);

    QBDI::GPRState gpr{};
    KernelSignalAction visible{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, nullptr, &visible),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(gpr.x0 == 0);
    CHECK(visible.handler == 0x12340000U);
    CHECK(visible.flags == SA_RESTART);
    CHECK(visible.restorer == 0x12340100U);
    CHECK(visible.mask == 0x44U);
    CHECK(kernel.actions[SIGUSR1].handler == master);

    KernelSignalAction replacement{kNormalHandler, SA_NODEFER, 0x71000300U, 0x800U};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &replacement, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    visible = {};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, nullptr, &visible),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(std::memcmp(&visible, &replacement, sizeof(visible)) == 0);
    CHECK(kernel.actions[SIGUSR1].handler == master);
    CHECK((kernel.actions[SIGUSR1].flags & SA_RESTART) == 0);
    CHECK(kernel.actions[SIGUSR1].restorer == replacement.restorer);

    KernelSignalAction combined{kSiginfoHandler, SA_SIGINFO, 0x71000400U, 0x10U};
    kernel.denied_address = 0xdead0000U;
    CHECK(broker.observe_rt_sigaction(
                  sigaction_call(
                          SIGUSR1, &combined,
                          reinterpret_cast<KernelSignalAction *>(
                                  kernel.denied_address)),
                  &gpr) == QBDI::SKIP_INST);
    CHECK(static_cast<int64_t>(gpr.x0) == -EFAULT);
    visible = {};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, nullptr, &visible),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(std::memcmp(&visible, &combined, sizeof(visible)) == 0);

    KernelSignalAction rejected{kSiginfoHandler, SA_SIGINFO, 0x71000400U, 0x10U};
    KernelSignalAction untouched{0x11110000U, SA_RESTART, 0x22220000U, 0x33U};
    const KernelSignalAction sentinel = untouched;
    kernel.replacement_error = -EPERM;
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &rejected, &untouched),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(static_cast<int64_t>(gpr.x0) == -EPERM);
    CHECK(std::memcmp(&untouched, &sentinel, sizeof(untouched)) == 0);
    visible = {};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, nullptr, &visible),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(std::memcmp(&visible, &combined, sizeof(visible)) == 0);

    const int action_calls_before_lazy = kernel.action_calls;
    KernelSignalAction lazy{kSiginfoHandler, SA_SIGINFO | SA_ONSTACK, 0, 0x20U};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR2, &lazy, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(kernel.action_calls == action_calls_before_lazy + 2);
    CHECK(kernel.actions[SIGUSR2].handler == master);
    CHECK((kernel.actions[SIGUSR2].flags & SA_ONSTACK) != 0);

    Arm64SyscallSnapshot denied = sigaction_call(
            SIGUSR1, reinterpret_cast<const KernelSignalAction *>(kernel.denied_address),
            nullptr);
    CHECK(broker.observe_rt_sigaction(denied, &gpr) == QBDI::SKIP_INST);
    CHECK(static_cast<int64_t>(gpr.x0) == -EFAULT);
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGKILL, &replacement, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(static_cast<int64_t>(gpr.x0) == -EINVAL);
    CHECK(broker.observe_rt_sigaction(
                  sigaction_call(SIGUSR1, nullptr, nullptr, 16), &gpr) ==
          QBDI::SKIP_INST);
    CHECK(static_cast<int64_t>(gpr.x0) == -EINVAL);
}

struct HandlerFixture {
    SignalBroker *broker = nullptr;
    SignalBrokerThreadState *thread = nullptr;
    ArtifactFixture *artifact = nullptr;
    FakeKernel *kernel = nullptr;
    int normal_calls = 0;
    int siginfo_calls = 0;
    int nested_calls = 0;
    int nested_context_calls = 0;
    uint64_t observed_mask = 0;
    uintptr_t observed_pc = 0;
    uintptr_t nested_observed_pc = 0;
    bool begin_was_persistent = false;
    uint32_t nested_failure_record_type = 0;
    uint32_t nested_failure_flags = 0;
    bool nested_failure_was_incomplete = false;
    bool tail_return_was_persistent = false;
    uintptr_t tail_observed_pc = 0;
    uint64_t tail_observed_x0 = 0;
    uint32_t tail_observed_depth = 0;
};

HandlerFixture *g_handler_fixture = nullptr;

void fallback_handler(int) { ++g_fallback_calls; }

void normal_handler(int) {
    HandlerFixture &fixture = *g_handler_fixture;
    ++fixture.normal_calls;
    fixture.observed_mask = fixture.kernel->mask;
    fixture.begin_was_persistent =
            fixture.artifact->emergency().type ==
            static_cast<uint32_t>(FlightRecordType::SignalHandlerBegin);
}

void siginfo_handler(int, siginfo_t *, void *context) {
    HandlerFixture &fixture = *g_handler_fixture;
    ++fixture.siginfo_calls;
    auto *guest = static_cast<SignalBrokerGuestContext *>(context);
    fixture.observed_pc = guest->registers.pc;
    for (size_t index = 0; index < guest->registers.regs.size(); ++index) {
        guest->registers.regs[index] = 0x9000U + index;
    }
    guest->registers.sp = 0x92000000U;
    guest->registers.pc = 0x71009990U;
    guest->registers.pstate = 0xa0000000U;
    guest->signal_mask = 1ULL << (SIGHUP - 1);
}

void nested_handler(int signal_number, siginfo_t *info, void *context) {
    HandlerFixture &fixture = *g_handler_fixture;
    ++fixture.nested_calls;
    if (fixture.nested_calls == 1) {
        CHECK(fixture.broker->dispatch(signal_number, info, context,
                                       fixture.thread));
    }
}

void nested_context_handler(int signal_number, siginfo_t *info, void *context) {
    HandlerFixture &fixture = *g_handler_fixture;
    auto *guest = static_cast<SignalBrokerGuestContext *>(context);
    ++fixture.nested_context_calls;
    if (fixture.nested_context_calls == 1) {
        guest->registers.pc = 0x7100aaa0U;
        CHECK(fixture.broker->dispatch(signal_number, info, context,
                                       fixture.thread));
        return;
    }
    fixture.nested_observed_pc = guest->registers.pc;
    guest->registers.regs[0] = 0xfeedfaceU;
}

void nested_publication_failure_handler(int signal_number, siginfo_t *info,
                                        void *context) {
    HandlerFixture &fixture = *g_handler_fixture;
    ++fixture.nested_calls;
    if (fixture.nested_calls == 1) {
        CHECK(fixture.broker->dispatch(signal_number, info, context,
                                       fixture.thread));
        return;
    }
    FlightEmergencyRecord recovered{};
    CHECK(scan_flight_emergency(
            fixture.artifact->artifact.emergency_bytes(
                    fixture.artifact->registration.directory_index),
            &recovered));
    fixture.nested_failure_record_type = recovered.type;
    fixture.nested_failure_flags = recovered.flags;
    fixture.nested_failure_was_incomplete =
            fixture.artifact->artifact.incomplete();
}

constexpr uintptr_t kTailReturnedPc = 0x7100dd00U;
constexpr uint64_t kTailReturnedX0 = 0x1234feedU;
constexpr uintptr_t kTracerTailPc = 0x7f00bad0U;
constexpr uint64_t kTracerTailX0 = 0xbadc0ffeeULL;

void tail_reentry_callback(FakeKernel *) {
    HandlerFixture &fixture = *g_handler_fixture;
    FlightEmergencyRecord recovered{};
    CHECK(scan_flight_emergency(
            fixture.artifact->artifact.emergency_bytes(
                    fixture.artifact->registration.directory_index),
            &recovered));
    fixture.tail_return_was_persistent =
            recovered.type == static_cast<uint32_t>(
                                      FlightRecordType::SignalHandlerReturn);
    SignalBrokerGuestContext tracer_context{};
    tracer_context.registers.pc = kTracerTailPc;
    tracer_context.registers.regs[0] = kTracerTailX0;
    CHECK(fixture.broker->dispatch(SIGUSR1, nullptr, &tracer_context,
                                   fixture.thread));
}

void tail_reentry_handler(int, siginfo_t *, void *context) {
    HandlerFixture &fixture = *g_handler_fixture;
    auto *guest = static_cast<SignalBrokerGuestContext *>(context);
    ++fixture.siginfo_calls;
    if (fixture.siginfo_calls == 1) {
        guest->registers.pc = kTailReturnedPc;
        guest->registers.regs[0] = kTailReturnedX0;
        fixture.kernel->after_mask_set = tail_reentry_callback;
        return;
    }
    fixture.tail_observed_pc = guest->registers.pc;
    fixture.tail_observed_x0 = guest->registers.regs[0];
    FlightEmergencyRecord recovered{};
    CHECK(scan_flight_emergency(
            fixture.artifact->artifact.emergency_bytes(
                    fixture.artifact->registration.directory_index),
            &recovered));
    fixture.tail_observed_depth = recovered.flags & 0xffffU;
}

void native_dispatch_persists_interval_preserves_masks_and_applies_guest_context() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;

    KernelSignalAction normal{
            reinterpret_cast<uintptr_t>(normal_handler), 0, 0,
            1ULL << (SIGTERM - 1)};
    QBDI::GPRState syscall_gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &normal, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    kernel.mask = 1ULL << (SIGINT - 1);
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));
    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));
    CHECK(handler.normal_calls == 1);
    CHECK(handler.begin_was_persistent);
    CHECK(handler.observed_mask ==
          ((1ULL << (SIGINT - 1)) | (1ULL << (SIGTERM - 1)) |
           (1ULL << (SIGUSR1 - 1))));
    CHECK(kernel.mask == (1ULL << (SIGINT - 1)));
    const FlightEmergencyRecord normal_return = artifact.emergency();
    CHECK(normal_return.type ==
          static_cast<uint32_t>(FlightRecordType::SignalHandlerReturn));
    CHECK(normal_return.fault_address != 0);
    CHECK(normal_return.signal_number == SIGUSR1);

    KernelSignalAction siginfo{
            reinterpret_cast<uintptr_t>(siginfo_handler), SA_SIGINFO | SA_NODEFER,
            0, 1ULL << (SIGTERM - 1)};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR2, &siginfo, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    const uintptr_t original_pc = artifact.gpr.pc;
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));
    CHECK(broker.dispatch(SIGUSR2, nullptr, nullptr, &artifact.thread));
    CHECK(handler.siginfo_calls == 1);
    CHECK(handler.observed_pc == original_pc);
    for (size_t index = 0; index < 31; ++index) {
        CHECK(QBDI_GPR_GET(&artifact.gpr, index) == 0x9000U + index);
    }
    CHECK(artifact.gpr.sp == 0x92000000U);
    CHECK(artifact.gpr.pc == 0x71009990U);
    CHECK(artifact.gpr.nzcv == 0xa0000000U);
    CHECK(kernel.mask == (1ULL << (SIGHUP - 1)));
    CHECK(artifact.emergency().type ==
          static_cast<uint32_t>(FlightRecordType::SignalHandlerReturn));
    g_handler_fixture = nullptr;
}

void nested_delivery_maps_the_interrupted_guest_handler_context() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    CHECK(broker.register_thread(&artifact.thread));
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;
    KernelSignalAction action{
            reinterpret_cast<uintptr_t>(nested_context_handler),
            SA_SIGINFO | SA_NODEFER, 0, 0};
    QBDI::GPRState syscall_gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &action, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));

    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));

    CHECK(handler.nested_context_calls == 2);
    CHECK(handler.nested_observed_pc == 0x7100aaa0U);
    CHECK(artifact.gpr.x0 == 0xfeedfaceU);
    const FlightEmergencyRecord outer_return = artifact.emergency();
    CHECK((outer_return.flags & 0xffffU) == 1U);
    CHECK((outer_return.flags >> 16U) == 1U);
    g_handler_fixture = nullptr;
}

void nested_begin_interruption_retains_mmap_ancestor_and_marks_incomplete() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    CHECK(broker.register_thread(&artifact.thread));
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;
    KernelSignalAction action{
            reinterpret_cast<uintptr_t>(nested_publication_failure_handler),
            SA_SIGINFO | SA_NODEFER, 0, 0};
    QBDI::GPRState syscall_gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &action, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));
    artifact.artifact.test_interrupt_emergency_publication(
            FlightRecordType::SignalHandlerBegin, 1, 3);

    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));

    CHECK(handler.nested_calls == 2);
    CHECK(handler.nested_failure_record_type ==
          static_cast<uint32_t>(FlightRecordType::Signal));
    CHECK((handler.nested_failure_flags & 0xffffU) == 2U);
    CHECK((handler.nested_failure_flags >> 16U) == 1U);
    CHECK(handler.nested_failure_was_incomplete);
    g_handler_fixture = nullptr;
}

void pending_signal_cannot_reenter_before_return_publication_and_depth_transition() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    CHECK(broker.register_thread(&artifact.thread));
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;
    KernelSignalAction action{
            reinterpret_cast<uintptr_t>(tail_reentry_handler),
            SA_SIGINFO | SA_NODEFER, 0, 0};
    QBDI::GPRState syscall_gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &action, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));

    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));

    CHECK(handler.siginfo_calls == 2);
    CHECK(handler.tail_return_was_persistent);
    CHECK(handler.tail_observed_depth == 1);
    CHECK(handler.tail_observed_pc == kTailReturnedPc);
    CHECK(handler.tail_observed_x0 == kTailReturnedX0);
    g_handler_fixture = nullptr;
}

void delivery_without_a_registered_flight_thread_preserves_incumbent_behavior() {
    FakeKernel kernel;
    kernel.actions[SIGUSR1] = {
            reinterpret_cast<uintptr_t>(fallback_handler), SA_NODEFER, 0, 0};
    SignalBroker broker(kernel.platform());
    const int signals[]{SIGUSR1};
    CHECK(broker.install(signals));
    g_fallback_calls = 0;
    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, nullptr));
    CHECK(g_fallback_calls == 1);
}

void thread_attachment_rejects_a_missing_returned_register_mapping() {
    ArtifactFixture artifact;
    SignalBrokerThreadState unmapped{};

    CHECK(!unmapped.initialize(artifact.registration.tid, &artifact.artifact,
                               artifact.registration, nullptr));
}

void asynchronous_delivery_never_observes_a_torn_guest_snapshot() {
    const uint32_t tid = static_cast<uint32_t>(::syscall(SYS_gettid));
    ArtifactFixture artifact(tid);
    SignalBroker broker;
    struct sigaction previous{};
    CHECK(::sigaction(SIGUSR1, nullptr, &previous) == 0);
    struct sigaction action{};
    action.sa_sigaction = snapshot_consistency_handler;
    action.sa_flags = SA_SIGINFO;
    CHECK(::sigemptyset(&action.sa_mask) == 0);
    CHECK(::sigaction(SIGUSR1, &action, nullptr) == 0);

    QBDI::GPRState first{};
    QBDI::GPRState second{};
    constexpr uint64_t kFirst = 0x1111111111111111ULL;
    constexpr uint64_t kSecond = 0xeeeeeeeeeeeeeeeeULL;
    for (size_t index = 0; index < 31; ++index) {
        QBDI_GPR_SET(&first, index, kFirst);
        QBDI_GPR_SET(&second, index, kSecond);
    }
    first.sp = first.pc = first.nzcv = kFirst;
    second.sp = second.pc = second.nzcv = kSecond;
    g_snapshot_thread = &artifact.thread;
    g_snapshot_signal_calls.store(0, std::memory_order_relaxed);
    g_snapshot_was_torn.store(false, std::memory_order_relaxed);
    std::atomic<bool> stop{false};
    const pthread_t target = ::pthread_self();
    std::thread sender([&stop, target]() {
        while (!stop.load(std::memory_order_acquire)) {
            (void)::pthread_kill(target, SIGUSR1);
        }
    });
    for (size_t iteration = 0;
         iteration < 100000 &&
         !g_snapshot_was_torn.load(std::memory_order_relaxed); ++iteration) {
        CHECK(broker.publish_guest_state(
                &artifact.thread, (iteration & 1U) == 0 ? first : second));
    }
    stop.store(true, std::memory_order_release);
    sender.join();
    CHECK(::sigaction(SIGUSR1, &previous, nullptr) == 0);
    g_snapshot_thread = nullptr;

    CHECK(g_snapshot_signal_calls.load(std::memory_order_relaxed) > 0);
    CHECK(!g_snapshot_was_torn.load(std::memory_order_relaxed));
}

void production_master_dispatches_registered_thread_without_qbdi_execution() {
    struct sigaction previous{};
    CHECK(::sigaction(SIGUSR2, nullptr, &previous) == 0);
    const uint32_t tid = static_cast<uint32_t>(::syscall(SYS_gettid));
    ArtifactFixture artifact(tid);
    SignalBroker broker;
    const int signals[]{SIGUSR2};
    CHECK(broker.install(signals));
    CHECK(broker.register_thread(&artifact.thread));
    KernelSignalAction guest{
            reinterpret_cast<uintptr_t>(production_master_handler),
            SA_SIGINFO | SA_NODEFER, 0, 0};
    QBDI::GPRState syscall_gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR2, &guest, nullptr),
                                      &syscall_gpr) == QBDI::SKIP_INST);
    CHECK(broker.publish_guest_state(&artifact.thread, artifact.gpr));
    g_production_master_calls = 0;
    g_qbdi_execution_calls.store(0, std::memory_order_relaxed);

    CHECK(::pthread_kill(::pthread_self(), SIGUSR2) == 0);

    CHECK(g_production_master_calls == 1);
    CHECK(g_qbdi_execution_calls.load(std::memory_order_relaxed) == 0);
    const FlightEmergencyRecord recovered = artifact.emergency();
    CHECK(recovered.type == static_cast<uint32_t>(
                                      FlightRecordType::SignalHandlerReturn));
    broker.unregister_thread(&artifact.thread);
    CHECK(::sigaction(SIGUSR2, &previous, nullptr) == 0);
}

void occupied_coverage_gap_stays_sticky_and_counts_signal_publication_loss() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;
    FlightEmergencyRecord gap{};
    gap.type = static_cast<uint32_t>(FlightRecordType::CoverageGap);
    gap.tid = artifact.registration.tid;
    gap.sequence = artifact.artifact.next_sequence();
    gap.pc = 0x7100bad0U;
    gap.flags = 7;
    CHECK(artifact.artifact.write_coverage_gap_sticky(
            artifact.registration.directory_index, gap));

    KernelSignalAction action{
            reinterpret_cast<uintptr_t>(normal_handler), SA_NODEFER, 0, 0};
    QBDI::GPRState gpr{};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &action, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(broker.register_thread(&artifact.thread));
    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));
    CHECK(handler.normal_calls == 1);
    const FlightEmergencyRecord retained = artifact.emergency();
    CHECK(retained.type == static_cast<uint32_t>(FlightRecordType::CoverageGap));
    CHECK(retained.sequence == gap.sequence);
    CHECK(flight_coverage_gap_dropped_count(retained) == 3);
    g_handler_fixture = nullptr;
}

void stale_generations_nested_delivery_reset_default_ignore_and_detach_are_safe() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    CHECK(broker.register_thread(&artifact.thread));
    HandlerFixture handler{&broker, &artifact.thread, &artifact, &kernel};
    g_handler_fixture = &handler;
    QBDI::GPRState gpr{};

    KernelSignalAction old_action{
            reinterpret_cast<uintptr_t>(normal_handler), SA_NODEFER, 0, 0};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &old_action, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    SignalBrokerDelivery stale{};
    CHECK(broker.prepare_delivery(SIGUSR1, &stale));
    KernelSignalAction replacement{1, 0, 0, 0};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, &replacement, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(broker.dispatch(stale, SIGUSR1, nullptr, nullptr, &artifact.thread));
    CHECK(handler.normal_calls == 1);
    CHECK(broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));
    CHECK(handler.normal_calls == 1);

    KernelSignalAction nested{
            reinterpret_cast<uintptr_t>(nested_handler),
            SA_SIGINFO | SA_NODEFER | SA_RESETHAND, 0, 0};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR2, &nested, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(broker.dispatch(SIGUSR2, nullptr, nullptr, &artifact.thread));
    CHECK(handler.nested_calls == 1);
    CHECK(kernel.tgkill_calls == 1);
    CHECK(kernel.last_pid == 4242 && kernel.last_tid == 731 &&
          kernel.last_signal == SIGUSR2);
    const FlightEmergencyRecord nested_return = artifact.emergency();
    CHECK((nested_return.flags & 0xffffU) == 1U);
    CHECK((nested_return.flags >> 16U) == 1U);

    KernelSignalAction ignored{1, 0, 0, 0};
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGTERM, &ignored, nullptr),
                                      &gpr) == QBDI::SKIP_INST);
    CHECK(broker.dispatch(SIGTERM, nullptr, nullptr, &artifact.thread));
    CHECK(kernel.tgkill_calls == 1);

    const int action_calls_before_detach = kernel.action_calls;
    broker.detach_after_fork_child();
    CHECK(kernel.action_calls == action_calls_before_detach + 3);
    CHECK(kernel.actions[SIGUSR1].handler == 1);
    CHECK(kernel.actions[SIGUSR2].handler == 0);
    CHECK(kernel.actions[SIGTERM].handler == 1);
    CHECK(!broker.dispatch(SIGUSR1, nullptr, nullptr, &artifact.thread));
    CHECK(broker.observe_rt_sigaction(sigaction_call(SIGUSR1, nullptr, nullptr),
                                      &gpr) == QBDI::CONTINUE);
    CHECK(kernel.action_calls == action_calls_before_detach + 3);
    g_handler_fixture = nullptr;
}

void instruction_preinst_virtualizes_rt_sigaction_before_collecting_svc() {
    FakeKernel kernel;
    SignalBroker broker(kernel.platform());
    ArtifactFixture artifact;
    CHECK(broker.register_thread(&artifact.thread));
    alignas(uint32_t) uint32_t svc = 0xd4000001U;
    KernelSignalAction action{
            reinterpret_cast<uintptr_t>(normal_handler), SA_NODEFER, 0, 0x40U};
    QBDI::GPRState gpr{};
    gpr.pc = reinterpret_cast<uintptr_t>(&svc);
    gpr.x8 = kArm64RtSigaction;
    gpr.x0 = SIGTERM;
    gpr.x1 = reinterpret_cast<uintptr_t>(&action);
    gpr.x3 = kKernelSignalSetBytes;
    TraceOptions options{};
    ModuleRange module{};
    module.start = gpr.pc;
    module.end = gpr.pc + sizeof(svc);
    InstructionCollector collector(nullptr, nullptr, nullptr, nullptr, nullptr,
                                   options, module, &broker, &artifact.thread);

    CHECK(collector.on_pre(nullptr, &gpr, nullptr) == QBDI::SKIP_INST);
    CHECK(gpr.x0 == 0);
    KernelSignalAction visible{};
    Arm64SyscallSnapshot query = sigaction_call(SIGTERM, nullptr, &visible);
    CHECK(broker.observe_rt_sigaction(query, &gpr) == QBDI::SKIP_INST);
    CHECK(std::memcmp(&visible, &action, sizeof(action)) == 0);
}

} // namespace

int main() {
    incumbent_is_visible_before_the_kernel_can_deliver_to_master();
    concurrent_action_replacement_never_swallows_a_delivery();
    reset_generation_stays_pinned_while_reset_reads_it();
    kernel_master_never_precedes_replacement_guest_semantics();
    master_preserves_the_incumbent_handlers_errno_semantics();
    fork_child_detach_restores_native_delivery_before_clearing_broker();
    fork_waits_for_initial_master_publication_and_restores_child_disposition();
    failed_child_restore_keeps_master_fail_open_to_incumbent();
    install_query_replace_lazy_install_and_guarded_memory_match_kernel_abi();
    delivery_without_a_registered_flight_thread_preserves_incumbent_behavior();
    thread_attachment_rejects_a_missing_returned_register_mapping();
    asynchronous_delivery_never_observes_a_torn_guest_snapshot();
    production_master_dispatches_registered_thread_without_qbdi_execution();
    occupied_coverage_gap_stays_sticky_and_counts_signal_publication_loss();
    native_dispatch_persists_interval_preserves_masks_and_applies_guest_context();
    nested_delivery_maps_the_interrupted_guest_handler_context();
    nested_begin_interruption_retains_mmap_ancestor_and_marks_incomplete();
    pending_signal_cannot_reenter_before_return_publication_and_depth_transition();
    stale_generations_nested_delivery_reset_default_ignore_and_detach_are_safe();
    instruction_preinst_virtualizes_rt_sigaction_before_collecting_svc();
}
