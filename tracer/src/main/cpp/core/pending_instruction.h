#pragma once

#include "core/instruction_cache.h"
#include "events/trace_record.h"

#include <array>
#include <cstdint>

class PendingInstructionSink {
public:
    virtual ~PendingInstructionSink() = default;
    virtual bool emit(const InstructionRecord &record) = 0;
    virtual bool emit_memory_continuation(uintptr_t pc,
                                          const MemoryRecord &record) = 0;
};

class PendingInstructionCollector {
public:
    explicit PendingInstructionCollector(PendingInstructionSink *sink,
                                         uintptr_t module_base = 0) noexcept;

    bool begin(const InstructionView &instruction, const RegisterSnapshot &registers) noexcept;
    bool complete_pending(const RegisterSnapshot &registers) noexcept;
    bool finish_last(const RegisterSnapshot &registers) noexcept;
    bool append_memory(const MemoryRecord &memory) noexcept;
    bool append_or_emit_memory(const MemoryRecord &memory,
                               const RegisterSnapshot &registers) noexcept;
    bool complete_memory(const RegisterSnapshot &registers) noexcept;

    bool has_pending() const noexcept { return pending_; }
    uint64_t pending_write_mask() const noexcept;

private:
    bool complete(const RegisterSnapshot &registers) noexcept;

    PendingInstructionSink *sink_ = nullptr;
    uintptr_t module_base_ = 0;
    uint64_t next_sequence_ = 1;
    InstructionRecord pending_record_{};
    uintptr_t continuation_pc_ = 0;
    bool continuing_memory_ = false;
    bool pending_ = false;
};
