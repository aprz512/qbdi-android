#pragma once

#include "core/trace_config.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

struct EncodeResult {
    bool ok = false;
    size_t size = 0;
};

class TraceEncoder {
public:
    EncodeResult encode_instruction(char *output, size_t capacity, const char *module_name,
                                    const InstructionRecord &record) const noexcept;

    EncodeResult encode_begin(char *output, size_t capacity, const TraceContext &context,
                              TraceProfile profile, bool compression_enabled,
                              size_t effective_buffer_bytes) const noexcept;

    EncodeResult encode_end(char *output, size_t capacity, bool ok, uint64_t return_value,
                            uint64_t elapsed_ms, const TraceMetrics &metrics) const noexcept;

    EncodeResult encode_event(char *output, size_t capacity, std::string_view event_type,
                              std::string_view name, std::string_view detail) const noexcept;
};
