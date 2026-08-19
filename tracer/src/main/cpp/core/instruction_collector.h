#pragma once

#include "core/instruction_cache.h"
#include "core/pending_instruction.h"

#include <QBDI.h>

class CodeRuleEngine;
class TextTraceWriter;
class TraceCallbackGate;
struct TraceContext;

class InstructionCollector final : public PendingInstructionSink {
public:
    InstructionCollector(InstructionCache *cache, TextTraceWriter *writer,
                         CodeRuleEngine *code_rules, const TraceContext *trace,
                         TraceCallbackGate *trace_gate) noexcept;

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

private:
    InstructionView resolve(QBDI::VM *vm, const QBDI::GPRState *gpr) noexcept;
    static RegisterSnapshot snapshot(const QBDI::GPRState &gpr, uint64_t mask) noexcept;

    InstructionCache *cache_ = nullptr;
    TextTraceWriter *writer_ = nullptr;
    CodeRuleEngine *code_rules_ = nullptr;
    const TraceContext *trace_ = nullptr;
    TraceCallbackGate *trace_gate_ = nullptr;
    CachedInstruction uncached_{};
    InstructionView current_view_{};
    PendingInstructionCollector pending_;
};
