#pragma once

#include "core/trace_callback_gate.h"

#include <cstdint>

class TraceRunSessionOutcome {
public:
    TraceCallbackGate *callback_gate() noexcept { return &callback_gate_; }
    const TraceCallbackGate *callback_gate() const noexcept { return &callback_gate_; }

    void observe_trace_setup(bool succeeded) noexcept;
    void observe_memory_instrumentation(bool memory_enabled,
                                        bool recording_enabled,
                                        bool callback_valid) noexcept;
    void observe_target_call(bool succeeded, uint64_t return_value,
                             bool writer_failed) noexcept;
    void observe_finalization(bool footer_written,
                              bool writer_closed) noexcept;

    bool footer_success() const noexcept { return footer_success_; }
    bool completion_success() const noexcept;
    bool should_log_success() const noexcept { return completion_success(); }
    uint64_t return_value() const noexcept { return return_value_; }

private:
    TraceCallbackGate callback_gate_{};
    uint64_t return_value_ = 0;
    bool footer_success_ = false;
    bool footer_written_ = false;
    bool writer_closed_ = false;
    bool finalized_ = false;
};
