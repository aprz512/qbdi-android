#pragma once

#include "core/arm64_memory_operand.h"

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kTraceGprCount = kArm64RegisterCount;
constexpr size_t kMaxRegisterNameBytes = 16;
constexpr size_t kMaxMemoryRecords = 8;
constexpr size_t kMaxHexdumpBytes = kMaxCapturedMemoryBytes;
constexpr size_t kMaxInstructionLineBytes = 4096;

struct CachedInstruction;

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
    // Legacy producer field retained for compatibility with semantic callers.
    std::array<uint8_t, kMaxHexdumpBytes> hexdump{};
    uint8_t hexdump_size = 0;
};

struct InstructionRecord {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    uintptr_t module_base = 0;
    // Borrowed: when non-null, this object and its fixed character arrays must remain readable and
    // unchanged across both TraceEncoder measure and write passes.
    const CachedInstruction *decoded = nullptr;
    DenseRegisterValues reads{};
    DenseRegisterValues writes{};
    std::array<MemoryRecord, kMaxMemoryRecords> memory{};
    uint8_t memory_count = 0;
};
