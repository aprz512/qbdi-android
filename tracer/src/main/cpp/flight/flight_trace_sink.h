#pragma once

#include "events/trace_sink.h"
#include "flight/flight_encoder.h"

#include <QBDI/State.h>

class FlightTraceSink final : public TraceSink {
public:
    FlightTraceSink() noexcept = default;

    // gpr is copied by the encoder before initialize returns; it is not borrowed.
    bool initialize(FlightChunkWriter *writer, TraceProfile profile,
                    const TraceContext &context,
                    const QBDI::GPRState *gpr) noexcept;

    bool instruction(const TraceContext &context,
                     const InstructionRecord &record) noexcept override;
    bool instruction(const TraceContext &context, const InstructionRecord &record,
                     const RegisterSnapshot &post_registers) noexcept override;
    bool memory(const TraceContext &context, uintptr_t pc,
                const MemoryRecord &record) noexcept override;
    bool call(const char *category, std::string_view name,
              std::string_view detail) noexcept override;
    bool rule(const std::string &name, const std::string &detail) noexcept override;
    bool error(const std::string &message) noexcept override;
    bool failed() const noexcept override { return failed_ || encoder_.failed(); }

private:
    bool observe(bool result) noexcept;

    FlightEncoder encoder_;
    bool initialized_ = false;
    bool failed_ = false;
};
