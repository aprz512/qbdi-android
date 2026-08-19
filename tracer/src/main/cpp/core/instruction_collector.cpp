#include "core/instruction_collector.h"

#include "core/qbdi_instruction_decoder.h"
#include "core/trace_callback_gate.h"
#include "events/text_trace_writer.h"
#include "rules/code_rule.h"

#include <QBDI/InstAnalysis.h>
#include <QBDI/State.h>

#include <cstring>

namespace {

const QBDI::AnalysisType kRequiredAnalysis = static_cast<QBDI::AnalysisType>(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY |
        QBDI::ANALYSIS_OPERANDS);

} // namespace

InstructionCollector::InstructionCollector(InstructionCache *cache, TextTraceWriter *writer,
                                           CodeRuleEngine *code_rules,
                                           const TraceContext *trace,
                                           TraceCallbackGate *trace_gate) noexcept
        : cache_(cache), writer_(writer), code_rules_(code_rules), trace_(trace),
          trace_gate_(trace_gate), pending_(this, trace != nullptr ? trace->module_base : 0) {}

QBDI::VMAction InstructionCollector::on_pre(QBDI::VM *vm, QBDI::GPRState *gpr,
                                            QBDI::FPRState *fpr) {
    if (trace_gate_ != nullptr && writer_ != nullptr) trace_gate_->observe_failure(writer_->failed());

    if (gpr != nullptr && pending_.has_pending()) {
        pending_.complete_pending(snapshot(*gpr, pending_.pending_write_mask()));
    }

    current_view_ = resolve(vm, gpr);
    CodeRuleContext rule_context(
            vm, gpr, fpr, &current_view_, trace_,
            trace_gate_ != nullptr ? trace_gate_->writer_or_null(writer_) : writer_);
    const QBDI::VMAction action = code_rules_ != nullptr
                                          ? code_rules_->on_pre_instruction(rule_context)
                                          : QBDI::CONTINUE;
    if (trace_gate_ != nullptr && writer_ != nullptr) trace_gate_->observe_failure(writer_->failed());
    if (action != QBDI::CONTINUE || gpr == nullptr) return action;

    const uint64_t read_mask = current_view_.decoded != nullptr
                                       ? current_view_.decoded->read_gpr_mask
                                       : 0;
    pending_.begin(current_view_, snapshot(*gpr, read_mask));
    return action;
}

QBDI::VMAction InstructionCollector::on_memory(QBDI::VM *vm, QBDI::GPRState *gpr) {
    if (trace_gate_ == nullptr || writer_ == nullptr) return QBDI::CONTINUE;
    trace_gate_->observe_failure(writer_->failed());
    return trace_gate_->trace(QBDI::CONTINUE, [&] {
        const auto accesses = vm->getInstMemoryAccess();
        for (const auto &access: accesses) {
            MemoryRecord memory{};
            memory.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
            memory.address = access.accessAddress;
            memory.size = access.size;
            memory.value = access.value;
            const uintptr_t pc = current_view_.address != 0
                                         ? current_view_.address
                                         : (gpr != nullptr ? gpr->pc : 0);
            if (!writer_->memory(*trace_, pc, memory)) return false;
        }
        return true;
    });
}

QBDI::VMAction InstructionCollector::on_post(QBDI::VM *vm, QBDI::GPRState *gpr,
                                             QBDI::FPRState *fpr) {
    if (trace_gate_ != nullptr && writer_ != nullptr) trace_gate_->observe_failure(writer_->failed());
    CodeRuleContext rule_context(
            vm, gpr, fpr, &current_view_, trace_,
            trace_gate_ != nullptr ? trace_gate_->writer_or_null(writer_) : writer_);
    const QBDI::VMAction action = code_rules_ != nullptr
                                          ? code_rules_->on_post_instruction(rule_context)
                                          : QBDI::CONTINUE;
    if (trace_gate_ != nullptr && writer_ != nullptr) trace_gate_->observe_failure(writer_->failed());
    return action;
}

void InstructionCollector::finish_last(const QBDI::GPRState &gpr) noexcept {
    if (!pending_.has_pending()) return;
    pending_.finish_last(snapshot(gpr, pending_.pending_write_mask()));
}

QBDI::VMAction InstructionCollector::pre_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                                  QBDI::FPRState *fpr, void *data) {
    return static_cast<InstructionCollector *>(data)->on_pre(vm, gpr, fpr);
}

QBDI::VMAction InstructionCollector::memory_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                                     QBDI::FPRState *, void *data) {
    return static_cast<InstructionCollector *>(data)->on_memory(vm, gpr);
}

QBDI::VMAction InstructionCollector::post_callback(QBDI::VM *vm, QBDI::GPRState *gpr,
                                                   QBDI::FPRState *fpr, void *data) {
    return static_cast<InstructionCollector *>(data)->on_post(vm, gpr, fpr);
}

bool InstructionCollector::emit(const InstructionRecord &record) {
    if (writer_ == nullptr) return true;
    if (trace_gate_ == nullptr) return writer_->instruction(*trace_, record);
    trace_gate_->observe_failure(writer_->failed());
    if (!trace_gate_->enabled()) return true;
    const bool emitted = writer_->instruction(*trace_, record);
    trace_gate_->observe_failure(writer_->failed());
    return emitted;
}

InstructionView InstructionCollector::resolve(QBDI::VM *vm,
                                              const QBDI::GPRState *gpr) noexcept {
    const uintptr_t address = gpr != nullptr ? gpr->pc : 0;
    uint32_t opcode = 0;
    if (address != 0) {
        std::memcpy(&opcode, reinterpret_cast<const void *>(address), sizeof(opcode));
        if (cache_ != nullptr) {
            if (const CachedInstruction *cached = cache_->find(opcode); cached != nullptr) {
                return {address, cached};
            }
        }
    }

    const QBDI::InstAnalysis *analysis = vm != nullptr ? vm->getInstAnalysis(kRequiredAnalysis)
                                                       : nullptr;
    uncached_ = analysis != nullptr ? decode_qbdi_instruction(opcode, *analysis)
                                    : CachedInstruction{};
    uncached_.opcode = opcode;
    if (analysis != nullptr && address != 0 && cache_ != nullptr && cache_->enabled()) {
        if (const CachedInstruction *cached = cache_->insert(uncached_); cached != nullptr) {
            return {address, cached};
        }
    }
    return {address, &uncached_};
}

RegisterSnapshot InstructionCollector::snapshot(const QBDI::GPRState &gpr,
                                                uint64_t mask) noexcept {
    RegisterSnapshot result{};
    for (size_t index = 0; index < kTraceGprCount; ++index) {
        if ((mask & (1ULL << index)) != 0) result.values[index] = QBDI_GPR_GET(&gpr, index);
    }
    return result;
}
