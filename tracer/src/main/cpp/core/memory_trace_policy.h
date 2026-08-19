#pragma once

#include "core/instruction_cache.h"
#include "core/memory_capture.h"
#include "core/trace_config.h"
#include "events/trace_record.h"

#include <array>

struct NormalizedMemoryAccess {
    uintptr_t inst_address = 0;
    uintptr_t address = 0;
    uint64_t value = 0;
    uint32_t size = 0;
    MemoryAccessKind kind = MemoryAccessKind::Read;
    uint16_t flags = 0;
};

class MemoryTracePolicy {
public:
    static constexpr size_t kQbdiAccessBytes = sizeof(uint64_t);
    static constexpr size_t kMaxAccessesPerOperand =
            kMaxCapturedMemoryBytes / kQbdiAccessBytes;
    static constexpr size_t kMaxPreMemoryCaptures =
            CachedInstruction::kMaxMemoryOperands * kMaxAccessesPerOperand;

    bool capture_after_rule(TraceProfile profile, bool rule_continues,
                            const CachedInstruction &instruction,
                            const RegisterSnapshot &registers,
                            size_t hexdump_limit,
                            MemoryReadFunction reader) noexcept;
    bool add_pre_access(const NormalizedMemoryAccess &access,
                        size_t hexdump_limit,
                        MemoryReadFunction reader) noexcept;
    MemoryRecord record(const NormalizedMemoryAccess &access,
                        TraceProfile profile, size_t hexdump_limit,
                        MemoryReadFunction reader) const noexcept;
    bool matches_instruction(uintptr_t expected_instruction,
                             const NormalizedMemoryAccess &access) const noexcept;
    bool record_if_matches(uintptr_t expected_instruction,
                           const NormalizedMemoryAccess &access,
                           TraceProfile profile, size_t hexdump_limit,
                           MemoryReadFunction reader,
                           MemoryRecord *record) const noexcept;

    size_t pre_capture_count() const noexcept { return pre_memory_count_; }
    bool overflowed() const noexcept { return overflowed_; }

private:
    struct PreMemoryCapture {
        uintptr_t address = 0;
        uint32_t access_size = 0;
        MemoryAccessKind kind = MemoryAccessKind::Read;
        MemoryBytes bytes{};
    };

    bool add_capture(uintptr_t address, uint32_t access_size,
                     MemoryAccessKind kind, size_t hexdump_limit,
                     MemoryReadFunction reader) noexcept;

    std::array<PreMemoryCapture, kMaxPreMemoryCaptures> pre_memory_{};
    uint8_t pre_memory_count_ = 0;
    bool overflowed_ = false;
};
