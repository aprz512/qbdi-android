#pragma once

#include "core/instruction_cache.h"

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kTraceGprCount = 34;
constexpr size_t kMaxRegisterNameBytes = 16;
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
    // Borrowed: when non-null, this object and its fixed character arrays must remain readable and
    // unchanged across both TraceEncoder measure and write passes.
    const CachedInstruction *decoded = nullptr;
    // Borrowed display identities supplied by the decoder (for example W0, LR, SP, NZCV, PC).
    // Each non-null name must remain readable across both encoder passes.
    std::array<const char *, kTraceGprCount> register_names{};
    std::array<uint64_t, kTraceGprCount> before{};
    std::array<uint64_t, kTraceGprCount> after{};
    std::array<MemoryRecord, kMaxMemoryRecords> memory{};
    uint8_t memory_count = 0;
};
