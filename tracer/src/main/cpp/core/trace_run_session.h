#pragma once

#include "core/trace_callback_gate.h"

#include <cstdint>

class BinaryTraceWriter;

struct TraceTargetOutcome {
    bool ran = false;
    bool succeeded = false;
    uint64_t return_value = 0;
};

struct TraceRunFinalization {
    uint64_t outward_return_value = 0;
    bool target_ran = false;
    bool footer_success = false;
    bool completion_success = false;
    bool should_log_success = false;
};

class TraceRunSessionOutcome {
public:
    TraceCallbackGate *callback_gate() noexcept { return &callback_gate_; }
    const TraceCallbackGate *callback_gate() const noexcept { return &callback_gate_; }

    void observe_trace_setup(bool succeeded) noexcept;
    void observe_memory_instrumentation(bool memory_enabled,
                                        bool recording_enabled,
                                        bool callback_valid) noexcept;
    void observe_execution_setup(bool succeeded) noexcept;
    bool target_should_run() const noexcept;
    void observe_target_call(TraceTargetOutcome outcome,
                             bool writer_failed) noexcept;
    TraceRunFinalization finalize(BinaryTraceWriter &writer, long elapsed_ms);

private:
    TraceCallbackGate callback_gate_{};
    TraceTargetOutcome target_{};
    TraceRunFinalization finalization_{};
    bool execution_setup_observed_ = false;
    bool execution_setup_succeeded_ = false;
    bool trace_setup_observed_ = false;
    bool trace_setup_succeeded_ = false;
    bool finalized_ = false;
};
