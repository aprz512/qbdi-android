#pragma once

#include "core/instruction_cache.h"

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kTraceGprCount = 34;
constexpr size_t kMaxMemoryRecords = 8;
constexpr size_t kMaxHexdumpBytes = 64;
constexpr size_t kMaxInstructionLineBytes = 4096;

struct MemoryRecord {
    char type = 'r';
    uintptr_t address = 0;
    uint32_t size = 0;
    uint64_t value = 0;
    std::array<uint8_t, kMaxHexdumpBytes> hexdump{};
    uint8_t hexdump_size = 0;
};

struct InstructionRecord {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    uintptr_t module_base = 0;
    const CachedInstruction *decoded = nullptr;
    std::array<uint64_t, kTraceGprCount> before{};
    std::array<uint64_t, kTraceGprCount> after{};
    std::array<MemoryRecord, kMaxMemoryRecords> memory{};
    uint8_t memory_count = 0;
};
