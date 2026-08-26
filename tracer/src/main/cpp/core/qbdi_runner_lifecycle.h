#pragma once

#include "core/trace_generation_runtime.h"

#include <cstddef>
#include <cstdint>
#include <memory>

class BinaryTraceWriter;

using QbdiTargetCall = bool (*)(void *opaque, uint64_t *return_value);

struct QbdiTargetCallResult {
    bool succeeded = false;
    uint64_t return_value = 0;
    bool child_detached = false;
};

using QbdiRegisterCallback = uint32_t (*)(void *opaque) noexcept;

// Type-erased production seam for the three callbacks required before vm.call. All requested
// registrars are invoked even after an earlier failure, matching QBDI runner setup ordering.
struct QbdiCallbackRegistration {
    void *opaque = nullptr;
    QbdiRegisterCallback add_pre = nullptr;
    QbdiRegisterCallback add_post = nullptr;
    QbdiRegisterCallback add_exec_transfer = nullptr;
    uint32_t invalid_event_id = 0;
    bool requires_post = false;
};

bool register_qbdi_callbacks(const QbdiCallbackRegistration &) noexcept;

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          BinaryTraceWriter *writer) noexcept;

using QbdiElapsedMillis = long (*)(void *opaque) noexcept;

// Owns the normal-runner half of cooperative stop. QBDI only observes the token;
// the runner thread seals the writer after vm.run() unwinds, then acknowledges
// the exact admission. Both operations are idempotent.
class QbdiNormalStopLifecycle final {
public:
    QbdiNormalStopLifecycle(BinaryTraceWriter *writer,
                            std::shared_ptr<TraceGenerationRuntime> runtime,
                            TraceAdmission admission, void *elapsed_opaque,
                            QbdiElapsedMillis elapsed) noexcept;

    bool enabled() const noexcept;
    const TraceStopToken *token() const noexcept;
    bool seal(TraceStopReason reason) noexcept;
    void acknowledge(bool sealed) noexcept;
    bool stop_observed() const noexcept;
    bool sealed() const noexcept;

#if defined(QTRACE_HOST_TEST)
    size_t seal_calls() const noexcept;
    size_t acknowledge_calls() const noexcept;
#endif

private:
    BinaryTraceWriter *writer_ = nullptr;
    std::shared_ptr<TraceGenerationRuntime> runtime_;
    TraceAdmission admission_{};
    void *elapsed_opaque_ = nullptr;
    QbdiElapsedMillis elapsed_ = nullptr;
    bool seal_called_ = false;
    bool acknowledge_called_ = false;
    bool stop_observed_ = false;
    bool sealed_ = false;
    size_t seal_calls_ = 0;
    size_t acknowledge_calls_ = 0;
};
