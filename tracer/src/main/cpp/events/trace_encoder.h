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
    // module_name is borrowed. When non-null, it must be readable and unchanged for up to
    // kMaxInstructionLineBytes bytes (or its terminating NUL), across both measure and write passes.
    EncodeResult encode_instruction(char *output, size_t capacity, const char *module_name,
                                    const InstructionRecord &record) const noexcept;

    EncodeResult encode_memory(char *output, size_t capacity, const char *module_name,
                               uintptr_t relative_pc,
                               const MemoryRecord &record) const noexcept;

    EncodeResult encode_begin(char *output, size_t capacity, const TraceContext &context,
                              TraceProfile profile, bool compression_enabled,
                              size_t effective_buffer_bytes) const noexcept;

    EncodeResult encode_end(char *output, size_t capacity, bool ok, uint64_t return_value,
                            uint64_t elapsed_ms, const TraceMetrics &metrics) const noexcept;

    // event_type, name, and detail are borrowed and must remain readable and unchanged for their
    // declared string_view extents across both measure and write passes.
    EncodeResult encode_event(char *output, size_t capacity, std::string_view event_type,
                              std::string_view name, std::string_view detail) const noexcept;
};
