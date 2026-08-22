#pragma once

#include "core/qbdi_runner.h"

#include <cstddef>
#include <cstdint>

class BinaryTraceWriter;
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

#if defined(QTRACE_HOST_TEST)
using QbdiThreadSessionTestExecutor = TraceRunResult (*)(
        void *opaque, QbdiThreadSession *session, uintptr_t entry,
        const uint64_t args[8], uint64_t indirect_result) noexcept;
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
            void *gap_opaque = nullptr) noexcept;
#endif

    TraceRunResult call(uintptr_t entry, const uint64_t args[8],
                        uint64_t indirect_result) noexcept;
    TraceRunResult call_gateway(uintptr_t logical_entry,
                                uintptr_t execution_entry,
                                size_t execution_bytes,
                                const uint64_t args[8],
                                uint64_t indirect_result) noexcept;

    bool try_enter() noexcept;
    void leave() noexcept;
    void mark_coverage_gap(uintptr_t pc) noexcept;
    void copy_cache_metrics(TraceMetrics *metrics) const noexcept;

    bool ready() const noexcept { return ready_; }
    bool running() const noexcept { return entered_ || vm_running_; }
    bool incomplete() const noexcept { return incomplete_; }
    uint32_t tid() const noexcept { return tid_; }
    uint32_t module_generation() const noexcept { return module_generation_; }

private:
    friend class CaptureCoordinator;

    struct Impl;

    QbdiThreadSession(uint32_t tid, uint32_t module_generation) noexcept;
    void set_gap_reporter(QbdiThreadSessionGapReporter gap_reporter,
                          void *gap_opaque) noexcept;
    TraceRunResult execute(uintptr_t logical_entry, uintptr_t execution_entry,
                           size_t execution_bytes,
                           const uint64_t args[8],
                           uint64_t indirect_result) noexcept;

    Impl *impl_ = nullptr;
    QbdiThreadSessionGapReporter gap_reporter_ = nullptr;
    void *gap_opaque_ = nullptr;
#if defined(QTRACE_HOST_TEST)
    QbdiThreadSessionTestExecutor test_executor_ = nullptr;
    void *test_executor_opaque_ = nullptr;
#endif
    uint32_t tid_ = 0;
    uint32_t module_generation_ = 0;
    bool ready_ = false;
    bool entered_ = false;
    bool vm_running_ = false;
    bool incomplete_ = false;
};

QbdiThreadSession *current_qbdi_thread_session() noexcept;
