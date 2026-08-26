#include "core/qbdi_runner_lifecycle.h"

#include "core/trace_process_lifecycle.h"
#include "events/binary_trace_writer.h"

#include <utility>

bool register_qbdi_callbacks(const QbdiCallbackRegistration &registration) noexcept {
    bool succeeded = registration.add_pre != nullptr &&
                     registration.add_pre(registration.opaque) !=
                             registration.invalid_event_id;
    if (registration.requires_post) {
        const bool post_succeeded = registration.add_post != nullptr &&
                                    registration.add_post(registration.opaque) !=
                                            registration.invalid_event_id;
        succeeded = post_succeeded && succeeded;
    }
    const bool exec_succeeded = registration.add_exec_transfer != nullptr &&
                                registration.add_exec_transfer(registration.opaque) !=
                                        registration.invalid_event_id;
    return exec_succeeded && succeeded;
}

QbdiTargetCallResult run_qbdi_target_call(QbdiTargetCall call, void *opaque,
                                          BinaryTraceWriter *writer) noexcept {
    QbdiTargetCallResult result{};
    if (call != nullptr) result.succeeded = call(opaque, &result.return_value);
    result.child_detached = trace_process_child_detached();
    if (result.child_detached && writer != nullptr) writer->detach_after_fork_child();
    return result;
}

QbdiNormalStopLifecycle::QbdiNormalStopLifecycle(
        BinaryTraceWriter *writer,
        std::shared_ptr<TraceGenerationRuntime> runtime,
        TraceAdmission admission, void *elapsed_opaque,
        QbdiElapsedMillis elapsed) noexcept
    : writer_(writer), runtime_(std::move(runtime)), admission_(admission),
      elapsed_opaque_(elapsed_opaque), elapsed_(elapsed) {}

bool QbdiNormalStopLifecycle::enabled() const noexcept {
    return writer_ != nullptr && runtime_ != nullptr && admission_.serial != 0 &&
           elapsed_ != nullptr;
}

const TraceStopToken *QbdiNormalStopLifecycle::token() const noexcept {
    return enabled() ? &runtime_->stop_token() : nullptr;
}

bool QbdiNormalStopLifecycle::seal(TraceStopReason reason) noexcept {
    if (seal_called_) return sealed_;
    seal_called_ = true;
    stop_observed_ = true;
    ++seal_calls_;
    if (!enabled()) return false;
    sealed_ = writer_->stop(reason, elapsed_(elapsed_opaque_));
    return sealed_;
}

void QbdiNormalStopLifecycle::acknowledge(bool sealed) noexcept {
    if (acknowledge_called_) return;
    acknowledge_called_ = true;
    ++acknowledge_calls_;
    if (!enabled()) return;
    if (seal_called_ && sealed_ && sealed) {
        runtime_->acknowledge_sealed(admission_);
    } else {
        runtime_->finish_call(admission_, false);
    }
}

bool QbdiNormalStopLifecycle::stop_observed() const noexcept {
    return stop_observed_;
}

bool QbdiNormalStopLifecycle::sealed() const noexcept { return sealed_; }

#if defined(QTRACE_HOST_TEST)
size_t QbdiNormalStopLifecycle::seal_calls() const noexcept {
    return seal_calls_;
}

size_t QbdiNormalStopLifecycle::acknowledge_calls() const noexcept {
    return acknowledge_calls_;
}
#endif
