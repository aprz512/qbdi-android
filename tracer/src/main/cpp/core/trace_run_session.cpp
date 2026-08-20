#include "core/trace_run_session.h"
#include "events/binary_trace_writer.h"

void TraceRunSessionOutcome::observe_trace_setup(bool succeeded) noexcept {
    trace_setup_observed_ = true;
    trace_setup_succeeded_ = succeeded;
    callback_gate_.observe_failure(!succeeded);
}

void TraceRunSessionOutcome::observe_memory_instrumentation(
        bool memory_enabled, bool recording_enabled,
        bool callback_valid) noexcept {
    const bool failed = memory_enabled && (!recording_enabled || !callback_valid);
    callback_gate_.observe_failure(failed);
    if (failed) {
        execution_setup_observed_ = true;
        execution_setup_succeeded_ = false;
    }
}

void TraceRunSessionOutcome::observe_execution_setup(bool succeeded) noexcept {
    execution_setup_observed_ = true;
    execution_setup_succeeded_ = succeeded;
    callback_gate_.observe_failure(!succeeded);
}

bool TraceRunSessionOutcome::target_should_run() const noexcept {
    return trace_setup_observed_ && trace_setup_succeeded_ &&
           execution_setup_observed_ && execution_setup_succeeded_;
}

void TraceRunSessionOutcome::observe_target_call(TraceTargetOutcome outcome,
                                                 bool writer_failed) noexcept {
    target_ = outcome;
    callback_gate_.observe_failure(writer_failed);
}

TraceRunFinalization TraceRunSessionOutcome::finalize(BinaryTraceWriter &writer,
                                                      long elapsed_ms) {
    if (finalized_) return finalization_;

    finalization_.target_ran = target_.ran;
    finalization_.outward_return_value = target_.ran ? target_.return_value : 0;
    finalization_.footer_success =
            target_.ran && target_.succeeded && callback_gate_.enabled();
    const bool footer_written = writer.end(finalization_.outward_return_value,
                                           finalization_.footer_success,
                                           elapsed_ms);
    const bool writer_closed = writer.close();
    finalization_.completion_success =
            finalization_.footer_success && footer_written && writer_closed;
    finalization_.should_log_success = finalization_.completion_success;
    finalized_ = true;
    return finalization_;
}
