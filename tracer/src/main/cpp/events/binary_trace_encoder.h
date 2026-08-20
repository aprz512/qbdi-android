#pragma once

#include "core/trace_config.h"
#include "events/binary_trace_format.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

struct CachedInstruction;

struct TraceBeginInfo {
    TraceProfile profile = TraceProfile::Fast;
    bool compression_enabled = true;
    uint64_t run_id = 0;
    uint64_t effective_buffer_bytes = 0;
};

struct BinaryEncodeResult {
    bool ok = false;
    size_t size = 0;
};

struct CallChunkInfo {
    uint64_t event_id = 0;
    uint32_t total_detail_bytes = 0;
    uint16_t chunk_index = 0;
    uint16_t chunk_count = 0;
};
using EventChunkInfo = CallChunkInfo;

class BinaryTraceEncoder {
public:
    BinaryEncodeResult encode_stream_header(uint8_t *, size_t,
                                            TraceProfile) const noexcept;
    BinaryEncodeResult encode_begin(uint8_t *, size_t, const TraceContext &,
                                    const TraceBeginInfo &) const noexcept;
    BinaryEncodeResult encode_module_definition(uint8_t *, size_t, uint32_t,
                                                std::string_view,
                                                uintptr_t) const noexcept;
    BinaryEncodeResult encode_instruction_definition(uint8_t *, size_t, uint32_t,
                                                     const CachedInstruction &) const noexcept;
    BinaryEncodeResult encode_instruction(uint8_t *, size_t, uint32_t, uint32_t,
                                          const InstructionRecord &) const noexcept;
    // module_relative_pc is already relative to the module identified by module_id.
    BinaryEncodeResult encode_memory(uint8_t *, size_t, uint32_t module_id,
                                     uintptr_t module_relative_pc,
                                     const MemoryRecord &) const noexcept;
    BinaryEncodeResult encode_call(uint8_t *, size_t, std::string_view,
                                   std::string_view, std::string_view) const noexcept;
    BinaryEncodeResult encode_call_chunk(uint8_t *, size_t, const CallChunkInfo &,
                                         std::string_view, std::string_view,
                                         std::string_view) const noexcept;
    // Only Rule and Error use the common two-string payload.
    BinaryEncodeResult encode_event(uint8_t *, size_t, BinaryRecordType,
                                    std::string_view, std::string_view) const noexcept;
    BinaryEncodeResult encode_event_chunk(uint8_t *, size_t, BinaryRecordType,
                                          const EventChunkInfo &, std::string_view,
                                          std::string_view) const noexcept;
    BinaryEncodeResult encode_end(uint8_t *, size_t, bool, uint64_t, uint64_t,
                                  const TraceMetrics &) const noexcept;
};
