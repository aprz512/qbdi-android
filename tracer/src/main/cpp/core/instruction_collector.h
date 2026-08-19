#pragma once

#include "core/instruction_cache.h"
#include "core/pending_instruction.h"
#include "core/trace_config.h"

#include <QBDI.h>

#include <array>

class CodeRuleEngine;
class TextTraceWriter;
class TraceCallbackGate;
struct TraceContext;

class InstructionCollector final : public PendingInstructionSink {
public:
    InstructionCollector(InstructionCache *cache, TextTraceWriter *writer,
                         CodeRuleEngine *code_rules, const TraceContext *trace,
                         TraceCallbackGate *trace_gate,
                         const TraceOptions &options) noexcept;

    QBDI::VMAction on_pre(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr);
    QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr);
    QBDI::VMAction on_post(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr);
    void finish_last(const QBDI::GPRState &gpr) noexcept;

    static QBDI::VMAction pre_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                       QBDI::FPRState *fpr, void *data);
    static QBDI::VMAction memory_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                          QBDI::FPRState *fpr, void *data);
    static QBDI::VMAction post_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                        QBDI::FPRState *fpr, void *data);

    bool emit(const InstructionRecord &record) override;
    bool emit_memory_continuation(uintptr_t pc,
                                  const MemoryRecord &record) override;

private:
    InstructionView resolve(QBDI::VM *vm, const QBDI::GPRState *gpr) noexcept;
    static RegisterSnapshot snapshot(const QBDI::GPRState &gpr, uint64_t mask) noexcept;
    void capture_pre_memory(QBDI::VM *vm, const QBDI::GPRState &gpr) noexcept;
    MemoryRecord memory_record(const QBDI::MemoryAccess &access) const noexcept;

    struct PreMemoryCapture {
        uintptr_t address = 0;
        uint32_t access_size = 0;
        uint8_t access_type = 0;
        MemoryBytes bytes{};
    };

    InstructionCache *cache_ = nullptr;
    TextTraceWriter *writer_ = nullptr;
    CodeRuleEngine *code_rules_ = nullptr;
    const TraceContext *trace_ = nullptr;
    TraceCallbackGate *trace_gate_ = nullptr;
    TraceProfile profile_ = TraceProfile::Fast;
    size_t hexdump_limit_ = 0;
    bool decode_memory_ = false;
    CachedInstruction uncached_{};
    InstructionView current_view_{};
    std::array<PreMemoryCapture, CachedInstruction::kMaxMemoryOperands> pre_memory_{};
    uint8_t pre_memory_count_ = 0;
    PendingInstructionCollector pending_;
};
