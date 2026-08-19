#pragma once

#include "core/memory_types.h"

#include <cstddef>
#include <cstdint>

using MemoryReadFunction = bool (*)(uintptr_t, void *, size_t);

size_t bounded_memory_capture_size(size_t access_size,
                                   size_t configured_limit) noexcept;
void capture_memory_bytes(uintptr_t address, size_t access_size,
                          size_t configured_limit, MemoryReadFunction reader,
                          MemoryBytes *capture) noexcept;
uint64_t truncate_memory_value(uint64_t value, uint32_t access_size,
                               uint16_t access_flags) noexcept;
