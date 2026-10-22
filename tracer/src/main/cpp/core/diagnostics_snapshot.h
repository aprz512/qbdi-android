#pragma once
#include <cstdint>

// Explicit cold diagnostic operation. Never call from a signal handler.
extern "C" __attribute__((visibility("default"))) int32_t
qbdi_tracer_snapshot_json(const char *request, uint64_t request_size,
                          char *response, uint64_t response_capacity,
                          uint64_t *response_size) noexcept;
