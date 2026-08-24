#pragma once

#include "core/qbdi_execution_control.h"
#include "core/qbdi_runner.h"

#include <QBDI/Callback.h>
#include <QBDI/State.h>

#include <cstddef>
#include <cstdint>
#include <memory>

class BinaryTraceWriter;
class CaptureCoordinator;
class FlightArtifact;
class TraceCallbackGate;
class TraceSink;
struct ModuleRange;
struct TraceConfig;
struct TraceContext;
struct TraceInvocation;
struct TraceMetrics;

class QbdiThreadSession;

using QbdiThreadSessionGapReporter = void (*)(void *opaque, uint32_t tid,
                                              uintptr_t pc) noexcept;
using QbdiThreadSessionLifecycleReporter =
        bool (*)(void *opaque, uint32_t tid, bool begin, uint32_t creator_tid,
                 uintptr_t start_routine) noexcept;

using QbdiVmExecutionActivate = uint64_t (*)(
        void *opaque, QBDI::GPRState *gpr) noexcept;
using QbdiVmExecutionClear = void (*)(void *opaque) noexcept;
using QbdiVmExecutionTargetPost = void (*)(
        void *opaque, const QBDI::GPRState *gpr,
        uintptr_t return_address) noexcept;

struct QbdiVmExecutionLifecycle {
    void *opaque = nullptr;
    QbdiVmExecutionActivate activate_callback = nullptr;
    QbdiVmExecutionClear clear_callback = nullptr;
    QbdiVmExecutionTargetPost target_post_callback = nullptr;

    bool activate(QBDI::GPRState *gpr) const noexcept {
        return activate_callback == nullptr ||
               activate_callback(opaque, gpr) != 0;
    }
    void clear() const noexcept {
        if (clear_callback != nullptr) clear_callback(opaque);
    }
    void observe_target_post(const QBDI::GPRState *gpr,
                             uintptr_t return_address) const noexcept {
        if (target_post_callback != nullptr) {
            target_post_callback(opaque, gpr, return_address);
        }
    }
};

void observe_qbdi_vm_target_post(
        const QbdiVmExecutionLifecycle &signal_execution,
        const QBDI::GPRState *gpr, uintptr_t return_address) noexcept;

#if defined(QTRACE_HOST_TEST)
using QbdiThreadSessionTestExecutor = TraceRunResult (*)(
        void *opaque, QbdiThreadSession *session, uintptr_t entry,
        uintptr_t control_start, size_t execution_bytes,
        const uint64_t args[8], uint64_t indirect_result);
using QbdiThreadSessionTestContinuation = TraceRunResult (*)(
        void *opaque, QbdiThreadSession *session) noexcept;
#define QTRACE_SESSION_CALL_NOEXCEPT
#else
#define QTRACE_SESSION_CALL_NOEXCEPT noexcept
#endif

class QbdiThreadSession final {
public:
    ~QbdiThreadSession();

    QbdiThreadSession(const QbdiThreadSession &) = delete;
    QbdiThreadSession &operator=(const QbdiThreadSession &) = delete;

    static QbdiThreadSession *create_normal(
            const TraceConfig &config, const TraceInvocation &invocation,
            TraceContext *context, TraceSink *sink, TraceCallbackGate *callback_gate,
            BinaryTraceWriter *normal_writer) noexcept;
    static QbdiThreadSession *create_flight(
            const TraceConfig &config, const ModuleRange &module,
            const SceneConfig &scene, uint32_t tid, uint32_t module_generation,
            FlightArtifact *artifact) noexcept;

#if defined(QTRACE_HOST_TEST)
    static QbdiThreadSession *create_for_test(
            uint32_t tid, uint32_t module_generation,
            QbdiThreadSessionTestExecutor executor, void *executor_opaque,
            QbdiThreadSessionGapReporter gap_reporter = nullptr,
            void *gap_opaque = nullptr,
            QbdiThreadSessionLifecycleReporter lifecycle_reporter = nullptr,
            void *lifecycle_opaque = nullptr,
            QbdiThreadSessionTestContinuation continuation = nullptr,
            QbdiControlExtentRegistration control_registration = {},
            QbdiVmExecutionLifecycle signal_execution = {}) noexcept;
#endif

    TraceRunResult call(uintptr_t entry, const uint64_t args[8],
                        uint64_t indirect_result) QTRACE_SESSION_CALL_NOEXCEPT;
    TraceRunResult call_gateway(uintptr_t logical_entry,
                                uintptr_t execution_entry,
                                uintptr_t control_start,
                                size_t execution_bytes,
                                const uint64_t args[8],
                                uint64_t indirect_result) QTRACE_SESSION_CALL_NOEXCEPT;

    bool try_enter() noexcept;
    void leave() noexcept;
    bool begin_thread(uint32_t creator_tid, uintptr_t start_routine) noexcept;
    bool publish_native_thread_begin() noexcept;
    bool end_thread() noexcept;
    void mark_coverage_gap(uintptr_t pc) noexcept;
    void copy_cache_metrics(TraceMetrics *metrics) const noexcept;

    bool ready() const noexcept { return ready_; }
    bool running() const noexcept { return entered_ || vm_running_; }
    bool vm_active() const noexcept { return vm_running_; }
    bool incomplete() const noexcept { return incomplete_; }
    uint32_t tid() const noexcept { return tid_; }
    uint32_t module_generation() const noexcept { return module_generation_; }
    uintptr_t thread_entry() const noexcept { return thread_entry_; }

private:
    friend class CaptureCoordinator;
    friend std::shared_ptr<CaptureCoordinator>
    current_capture_coordinator() noexcept;

    struct Impl;

    QbdiThreadSession(uint32_t tid, uint32_t module_generation) noexcept;
    void set_gap_reporter(QbdiThreadSessionGapReporter gap_reporter,
                          void *gap_opaque) noexcept;
    void set_capture_owner(
            const std::weak_ptr<CaptureCoordinator> &owner) noexcept;
    TraceRunResult execute(uintptr_t logical_entry, uintptr_t execution_entry,
                           uintptr_t control_start,
                           size_t execution_bytes,
                           const uint64_t args[8],
                           uint64_t indirect_result) QTRACE_SESSION_CALL_NOEXCEPT;
    TraceRunResult continue_execution() QTRACE_SESSION_CALL_NOEXCEPT;
    bool ensure_control_extent(uintptr_t execution_entry,
                               uintptr_t control_start,
                               size_t execution_bytes) noexcept;
    bool copy_execution_state(QbdiExecutionState *state) const noexcept;

    Impl *impl_ = nullptr;
    QbdiThreadSessionGapReporter gap_reporter_ = nullptr;
    void *gap_opaque_ = nullptr;
    std::weak_ptr<CaptureCoordinator> capture_owner_;
    std::shared_ptr<CaptureCoordinator> active_capture_owner_;
    bool capture_owner_required_ = false;
#if defined(QTRACE_HOST_TEST)
    QbdiThreadSessionTestExecutor test_executor_ = nullptr;
    void *test_executor_opaque_ = nullptr;
    QbdiThreadSessionLifecycleReporter lifecycle_reporter_ = nullptr;
    void *lifecycle_opaque_ = nullptr;
    QbdiThreadSessionTestContinuation test_continuation_ = nullptr;
    QbdiVmExecutionLifecycle test_signal_execution_{};
    QbdiControlExtentRegistration test_control_registration_{};
#endif
    QbdiControlExtentSet control_extents_;
    uintptr_t thread_entry_ = 0;
    uint32_t creator_tid_ = 0;
    uint32_t tid_ = 0;
    uint32_t module_generation_ = 0;
    bool ready_ = false;
    bool entered_ = false;
    bool vm_running_ = false;
    bool incomplete_ = false;
    bool thread_begun_ = false;
    bool thread_ended_ = false;
};

QbdiThreadSession *current_qbdi_thread_session() noexcept;
std::shared_ptr<CaptureCoordinator> current_capture_coordinator() noexcept;
bool make_pthread_exit_control_hole(uintptr_t pthread_exit_destination,
                                    AddressRange *hole) noexcept;
bool recognize_deferred_pthread_exit(uintptr_t destination,
                                     uintptr_t pthread_exit_destination,
                                     uint64_t exit_value,
                                     TraceRunResult *result) noexcept;
bool needs_thread_begin_publication(bool pending, bool published) noexcept;
QBDI::VMAction classify_deferred_pthread_exit_event(
        const QBDI::VMState *vm_state, const QBDI::GPRState *gpr,
        uintptr_t pthread_exit_destination, TraceRunResult *result) noexcept;

#undef QTRACE_SESSION_CALL_NOEXCEPT
