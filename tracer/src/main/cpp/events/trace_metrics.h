#pragma once

#include <cstdint>

struct TraceMetrics {
    uint64_t instructions = 0;
    union {
        // Binary format v1 name. AsyncTraceWriter accounts the uncompressed bytes committed by
        // the producer. The raw_bytes alias keeps the format-2 writer source-compatible until
        // its removal during production-path migration.
        uint64_t encoded_bytes = 0;
        uint64_t raw_bytes;
    };
    uint64_t compressed_bytes = 0;
    uint64_t cache_hits = 0;
    uint64_t cache_misses = 0;
    uint64_t cache_collisions = 0;
    uint64_t buffer_swaps = 0;
    uint64_t producer_waits = 0;
    uint64_t producer_wait_ns = 0;
    uint64_t effective_buffer_bytes = 0;
};
