#include "core/trace_run_session.h"

void TraceRunSessionOutcome::observe_trace_setup(bool succeeded) noexcept {
    callback_gate_.observe_failure(!succeeded);
}

void TraceRunSessionOutcome::observe_memory_instrumentation(
        bool memory_enabled, bool recording_enabled,
        bool callback_valid) noexcept {
    callback_gate_.observe_failure(
            memory_enabled && (!recording_enabled || !callback_valid));
}

void TraceRunSessionOutcome::observe_target_call(bool succeeded,
                                                 uint64_t return_value,
                                                 bool writer_failed) noexcept {
    return_value_ = return_value;
    callback_gate_.observe_failure(writer_failed);
    footer_success_ = succeeded && callback_gate_.enabled();
}

void TraceRunSessionOutcome::observe_finalization(bool footer_written,
                                                  bool writer_closed) noexcept {
    footer_written_ = footer_written;
    writer_closed_ = writer_closed;
    finalized_ = true;
}

bool TraceRunSessionOutcome::completion_success() const noexcept {
    return finalized_ && footer_success_ && footer_written_ && writer_closed_;
}
