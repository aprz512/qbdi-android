#include "flight/flight_trace_sink.h"

bool FlightTraceSink::initialize(FlightChunkWriter *writer, TraceProfile profile,
                                 const TraceContext &context,
                                 const QBDI::GPRState *gpr) noexcept {
    if (initialized_ || failed_) return false;
    initialized_ = encoder_.initialize(writer, profile, context, gpr);
    if (!initialized_) failed_ = true;
    return initialized_;
}

bool FlightTraceSink::initialize(FlightChunkWriter *writer, TraceProfile profile,
                                 const FlightTraceContextView &context,
                                 const QBDI::GPRState *gpr) noexcept {
    if (initialized_ || failed_) return false;
    initialized_ = encoder_.initialize(writer, profile, context, gpr);
    if (!initialized_) failed_ = true;
    return initialized_;
}

bool FlightTraceSink::ensure_initialized(
        FlightChunkWriter *writer, TraceProfile profile,
        const FlightTraceContextView &context,
        const QBDI::GPRState *gpr) noexcept {
    return initialized_ ? !failed() : initialize(writer, profile, context, gpr);
}

bool FlightTraceSink::sync_registers(const QBDI::GPRState &gpr) noexcept {
    return observe(encoder_.registers(gpr));
}

bool FlightTraceSink::observe(bool result) noexcept {
    if (!initialized_ || failed_) return false;
    if (!result) failed_ = true;
    return result;
}

bool FlightTraceSink::thread_begin(uint32_t creator_tid, uint32_t tid,
                                   uintptr_t start_routine,
                                   uint32_t module_generation) noexcept {
    return observe(encoder_.thread_begin(creator_tid, tid, start_routine,
                                         module_generation));
}

bool FlightTraceSink::thread_end(uint32_t tid) noexcept {
    return observe(encoder_.thread_end(tid));
}

bool FlightTraceSink::instruction(const TraceContext &context,
                                  const InstructionRecord &record) noexcept {
    return observe(encoder_.instruction(context, record));
}

bool FlightTraceSink::instruction(
        const TraceContext &context, const InstructionRecord &record,
        const RegisterSnapshot &post_registers) noexcept {
    return observe(encoder_.instruction(context, record, post_registers));
}

bool FlightTraceSink::memory(const TraceContext &context, uintptr_t pc,
                             const MemoryRecord &record) noexcept {
    return observe(encoder_.memory(context, pc, record));
}

bool FlightTraceSink::call(const char *category, std::string_view name,
                           std::string_view detail) noexcept {
    return observe(encoder_.call(category, name, detail));
}

bool FlightTraceSink::rule(const std::string &name, const std::string &detail) noexcept {
    return observe(encoder_.rule(name, detail));
}

bool FlightTraceSink::error(const std::string &message) noexcept {
    return observe(encoder_.error(message));
}
