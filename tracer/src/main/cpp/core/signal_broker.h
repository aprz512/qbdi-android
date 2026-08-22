#pragma once

#include "core/arm64_syscall.h"
#include "core/signal_context_arm64.h"
#include "flight/flight_artifact.h"

#include <QBDI/Callback.h>
#include <QBDI/State.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <signal.h>
#include <span>

constexpr int64_t kArm64RtSigaction = 134;
constexpr uint64_t kKernelSignalSetBytes = 8U;

struct KernelSignalAction {
    uintptr_t handler = 0;
    uint64_t flags = 0;
    uintptr_t restorer = 0;
    uint64_t mask = 0;
};

static_assert(sizeof(KernelSignalAction) == 32);

struct SignalBrokerPlatform {
    void *opaque = nullptr;
    long (*rt_sigaction)(void *opaque, int signal_number,
                         const KernelSignalAction *action,
                         KernelSignalAction *old_action) noexcept = nullptr;
    long (*rt_sigprocmask)(void *opaque, int how, const uint64_t *set,
                           uint64_t *old_set) noexcept = nullptr;
    long (*tgkill)(void *opaque, int pid, int tid,
                   int signal_number) noexcept = nullptr;
    int (*getpid)(void *opaque) noexcept = nullptr;
    int (*gettid)(void *opaque) noexcept = nullptr;
    bool (*copy_from_guest)(void *opaque, uintptr_t address, void *destination,
                            size_t size) noexcept = nullptr;
    bool (*copy_to_guest)(void *opaque, uintptr_t address, const void *source,
                          size_t size) noexcept = nullptr;
};

// Host tests receive this portable representation as the SA_SIGINFO context.
// Android arm64 guest handlers receive Bionic's real ucontext_t instead.
struct SignalBrokerGuestContext {
    Arm64SignalContext registers{};
    uint64_t signal_mask = 0;
};

class SignalBroker;
class TerminationObserver;
void signal_broker_atfork_prepare() noexcept;
void signal_broker_atfork_parent() noexcept;
void signal_broker_atfork_child() noexcept;

struct SignalBrokerThreadState {
public:
    bool initialize(uint32_t tid, FlightArtifact *artifact,
                    const FlightThreadRegistration &registration,
                    QBDI::GPRState *guest_gpr) noexcept;

    uint32_t tid() const noexcept { return tid_; }
#if defined(QTRACE_HOST_TEST)
    bool test_load_guest(Arm64SignalContext *context) const noexcept {
        return load_guest(context);
    }
#endif

private:
    friend class SignalBroker;
    friend class TerminationObserver;

    __attribute__((no_stack_protector)) bool publish(
            FlightRecordType type, uintptr_t pc, uintptr_t sp,
            uintptr_t related, uint32_t signal_or_syscall, uint32_t code,
            uint32_t flags, uint64_t *sequence = nullptr) noexcept;
    struct GuestSnapshot {
        std::array<std::atomic<uint64_t>, 34> words{};
        std::atomic<QBDI::GPRState *> gpr{nullptr};
    };

    bool load_guest(Arm64SignalContext *context,
                    QBDI::GPRState **gpr = nullptr) const noexcept;
    void publish_guest(const Arm64SignalContext &context,
                       QBDI::GPRState *gpr) noexcept;
    bool store_guest(const Arm64SignalContext &context,
                     QBDI::GPRState *gpr) noexcept;

    FlightArtifact *artifact_ = nullptr;
    FlightThreadRegistration registration_{};
    std::array<GuestSnapshot, 2> guest_snapshots_{};
    std::atomic<uint32_t> guest_snapshot_index_{0};
    std::atomic<uint32_t> active_deliveries_{0};
    std::atomic<uint32_t> nested_deliveries_{0};
    std::atomic<bool> attached_{false};
    uint32_t tid_ = 0;
};

struct SignalBrokerDelivery {
    KernelSignalAction action{};
    uint64_t generation = 0;
    bool valid = false;
};

class SignalBroker {
public:
    SignalBroker() noexcept;
    explicit SignalBroker(SignalBrokerPlatform platform) noexcept;
    ~SignalBroker();

    SignalBroker(const SignalBroker &) = delete;
    SignalBroker &operator=(const SignalBroker &) = delete;

    bool install() noexcept;
    bool install(std::span<const int> signal_numbers) noexcept;
    QBDI::VMAction observe_rt_sigaction(const Arm64SyscallSnapshot &call,
                                        QBDI::GPRState *gpr) noexcept;
    bool register_thread(SignalBrokerThreadState *thread) noexcept;
    void unregister_thread(SignalBrokerThreadState *thread) noexcept;
    bool publish_guest_state(SignalBrokerThreadState *thread,
                             const QBDI::GPRState &gpr) noexcept;
    bool prepare_delivery(int signal_number,
                          SignalBrokerDelivery *delivery) const noexcept;
    __attribute__((no_stack_protector)) bool dispatch(
            int signal_number, siginfo_t *info, void *native_context,
            SignalBrokerThreadState *thread = nullptr) noexcept;
    __attribute__((no_stack_protector)) bool dispatch(
            const SignalBrokerDelivery &delivery, int signal_number,
            siginfo_t *info, void *native_context,
            SignalBrokerThreadState *thread = nullptr) noexcept;
    __attribute__((no_stack_protector)) void
    detach_after_fork_child() noexcept;

    uintptr_t master_handler_address() const noexcept;
    bool detached() const noexcept {
        return detached_.load(std::memory_order_acquire);
    }
#if defined(QTRACE_HOST_TEST)
    uint32_t test_active_action_readers(int signal_number) const noexcept;
#endif

    static SignalBroker &process() noexcept;

private:
    friend void signal_broker_atfork_prepare() noexcept;
    friend void signal_broker_atfork_parent() noexcept;
    friend void signal_broker_atfork_child() noexcept;

    struct ActionGeneration {
        KernelSignalAction action{};
        uint64_t generation = 0;
        mutable std::atomic<uint32_t> active_deliveries{0};
    };

    struct ActionSlot {
        std::array<ActionGeneration, 3> generations{};
        mutable std::atomic<uint32_t> acquiring_deliveries{0};
        std::atomic<uint32_t> active_generation{UINT32_MAX};
        uint64_t next_generation = 1;
        std::atomic<bool> installed{false};
    };

    bool platform_valid() const noexcept;
    bool valid_signal(int signal_number) const noexcept;
    long install_signal(
            int signal_number,
            const KernelSignalAction *guest_semantics = nullptr) noexcept;
    bool publish_action(int signal_number,
                        const KernelSignalAction &action) noexcept;
    bool read_action(int signal_number, KernelSignalAction *action,
                     uint64_t *generation) const noexcept;
    bool reset_if_current(int signal_number, uint64_t generation) noexcept;
    SignalBrokerThreadState *find_thread(uint32_t tid) const noexcept;
    bool publish_syscall(const Arm64SyscallSnapshot &call) noexcept;
    __attribute__((no_stack_protector)) bool raw_redeliver_default(
            int signal_number, SignalBrokerThreadState *thread) noexcept;

    static void master_handler(int signal_number, siginfo_t *info,
                               void *native_context) noexcept;

    static constexpr size_t kSignalCount = 65;
    static constexpr size_t kThreadSlots = 256;
    SignalBrokerPlatform platform_{};
    std::array<ActionSlot, kSignalCount> actions_{};
    std::array<std::atomic<SignalBrokerThreadState *>, kThreadSlots> threads_{};
    std::mutex update_mutex_;
    std::atomic<bool> detached_{false};
};

class TerminationObserver {
public:
    static bool is_termination_syscall(int64_t number) noexcept;
    static QBDI::VMAction before_svc(
            const Arm64SyscallSnapshot &snapshot,
            SignalBrokerThreadState *writer) noexcept;
};

void detach_process_signal_broker_after_fork_child() noexcept;

#if defined(QTRACE_HOST_TEST)
using SignalBrokerTestGate = void (*)();
void signal_broker_test_set_action_publication_gate(
        SignalBrokerTestGate gate) noexcept;
void signal_broker_test_set_action_reset_gate(
        SignalBrokerTestGate gate) noexcept;
#endif
