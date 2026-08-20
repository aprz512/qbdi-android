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

struct BinaryEncodeResult {
    bool ok = false;
    size_t size = 0;
};

class BinaryTraceEncoder {
public:
    BinaryEncodeResult encode_stream_header(uint8_t *, size_t,
                                            TraceProfile) const noexcept;
    BinaryEncodeResult encode_begin(uint8_t *, size_t, const TraceContext &,
                                    size_t) const noexcept;
    BinaryEncodeResult encode_module_definition(uint8_t *, size_t, uint32_t,
                                                std::string_view,
                                                uintptr_t) const noexcept;
    BinaryEncodeResult encode_instruction_definition(uint8_t *, size_t, uint32_t,
                                                     const CachedInstruction &) const noexcept;
    BinaryEncodeResult encode_instruction(uint8_t *, size_t, uint32_t,
                                          const InstructionRecord &) const noexcept;
    // module_relative_pc is already relative to the module identified by module_id.
    BinaryEncodeResult encode_memory(uint8_t *, size_t, uint32_t module_id,
                                     uintptr_t module_relative_pc,
                                     const MemoryRecord &) const noexcept;
    BinaryEncodeResult encode_event(uint8_t *, size_t, BinaryRecordType,
                                    std::string_view, std::string_view) const noexcept;
    BinaryEncodeResult encode_end(uint8_t *, size_t, bool, uint64_t, uint64_t,
                                  const TraceMetrics &) const noexcept;
};
