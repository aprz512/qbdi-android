#pragma once

#include "core/arm64_memory_operand.h"

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kTraceGprCount = kArm64RegisterCount;
constexpr uint64_t kTraceValidGprMask = (1ULL << kTraceGprCount) - 1ULL;
constexpr size_t kMaxRegisterNameBytes = 16;
constexpr size_t kMaxMemoryRecords = 8;

struct CachedInstruction;

constexpr bool valid_trace_gpr_mask(uint64_t mask) noexcept {
    return (mask & ~kTraceValidGprMask) == 0;
}

struct DenseRegisterValues {
    std::array<uint64_t, kTraceGprCount> values{};
    uint8_t count = 0;
};

struct MemoryRecord {
    MemoryAccessKind kind = MemoryAccessKind::Read;
    bool metadata_available = false;
    uint16_t flags = 0;
    uintptr_t address = 0;
    uint32_t size = 0;
    uint64_t value = 0;
    MemoryBytes before{};
    MemoryBytes after{};
};

struct InstructionRecord {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    uintptr_t module_base = 0;
    // Borrowed: when non-null, this object and its fixed character arrays must remain readable
    // through binary encoding.
    const CachedInstruction *decoded = nullptr;
    DenseRegisterValues reads{};
    DenseRegisterValues writes{};
    std::array<MemoryRecord, kMaxMemoryRecords> memory{};
    uint8_t memory_count = 0;
};
