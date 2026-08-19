#include "core/instruction_collector.h"

#include "core/qbdi_instruction_decoder.h"
#include "core/safe_memory.h"
#include "core/trace_callback_gate.h"
#include "events/text_trace_writer.h"
#include "rules/code_rule.h"

#include <QBDI/InstAnalysis.h>
#include <QBDI/State.h>

#include <algorithm>
#include <cstring>

namespace {

const QBDI::AnalysisType kRequiredAnalysis = static_cast<QBDI::AnalysisType>(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY |
        QBDI::ANALYSIS_OPERANDS);

struct QbdiDecoderRequest {
    QBDI::VM *vm = nullptr;
    bool decode_memory = false;
};

bool decode_current_instruction(uint32_t opcode, void *data,
                                CachedInstruction *decoded) noexcept {
    auto *request = static_cast<QbdiDecoderRequest *>(data);
    if (request == nullptr || request->vm == nullptr || decoded == nullptr) return false;
    const QBDI::InstAnalysis *analysis = request->vm->getInstAnalysis(kRequiredAnalysis);
    if (analysis == nullptr) return false;
    *decoded = decode_qbdi_instruction(opcode, *analysis, request->decode_memory);
    return true;
}

MemoryAccessKind memory_kind(QBDI::MemoryAccessType type) noexcept {
    if (type == QBDI::MEMORY_READ_WRITE) return MemoryAccessKind::ReadWrite;
    return type == QBDI::MEMORY_WRITE ? MemoryAccessKind::Write
                                      : MemoryAccessKind::Read;
}

NormalizedMemoryAccess normalize(const QBDI::MemoryAccess &access) noexcept {
    return {access.instAddress, access.accessAddress, access.value, access.size,
            memory_kind(access.type), static_cast<uint16_t>(access.flags)};
}

} // namespace

InstructionCollector::InstructionCollector(InstructionCache *cache, TextTraceWriter *writer,
                                           CodeRuleEngine *code_rules,
                                           const TraceContext *trace,
                                           TraceCallbackGate *trace_gate,
                                           const TraceOptions &options) noexcept
        : cache_(cache), writer_(writer), code_rules_(code_rules), trace_(trace),
          trace_gate_(trace_gate), profile_(options.profile),
          hexdump_limit_(options.hexdump_limit),
          decode_memory_(options.memory_enabled()),
          pending_(this, trace != nullptr ? trace->module_base : 0) {}

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
    const bool continues = action == QBDI::CONTINUE && gpr != nullptr;
    if (profile_ == TraceProfile::Full) {
        const CachedInstruction empty{};
        const CachedInstruction &decoded = current_view_.decoded != nullptr
                                                   ? *current_view_.decoded
                                                   : empty;
        const RegisterSnapshot registers = gpr != nullptr
                                                   ? snapshot(*gpr, UINT64_MAX)
                                                   : RegisterSnapshot{};
        memory_policy_.capture_after_rule(profile_, continues, decoded, registers,
                                          hexdump_limit_, safe_read_memory);
    }
    if (!continues) return action;
    if (profile_ == TraceProfile::Full) capture_pre_memory(vm);

    const uint64_t read_mask = current_view_.decoded != nullptr
                                       ? current_view_.decoded->read_gpr_mask
                                       : 0;
    pending_.begin(current_view_, snapshot(*gpr, read_mask));
    return action;
}

QBDI::VMAction InstructionCollector::on_memory(QBDI::VM *vm, QBDI::GPRState *gpr) {
    if (trace_gate_ == nullptr || writer_ == nullptr || trace_ == nullptr || vm == nullptr ||
        !pending_.has_pending()) {
        return QBDI::CONTINUE;
    }
    trace_gate_->observe_failure(writer_->failed());
    return trace_gate_->trace(QBDI::CONTINUE, [&] {
        const auto accesses = vm->getInstMemoryAccess();
        bool matched = false;
        const RegisterSnapshot post_registers = gpr != nullptr
                                                        ? snapshot(*gpr, pending_.pending_write_mask())
                                                        : RegisterSnapshot{};
        for (const auto &access: accesses) {
            const NormalizedMemoryAccess normalized = normalize(access);
            MemoryRecord memory{};
            if (!memory_policy_.record_if_matches(
                        current_view_.address, normalized, profile_, hexdump_limit_,
                        safe_read_memory, &memory)) {
                continue;
            }
            matched = true;
            if (gpr == nullptr || !pending_.append_or_emit_memory(memory, post_registers)) {
                return false;
            }
        }
        if (matched) return gpr != nullptr && pending_.complete_memory(post_registers);
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

bool InstructionCollector::emit_memory_continuation(
        uintptr_t pc, const MemoryRecord &record) {
    if (writer_ == nullptr || trace_ == nullptr) return false;
    if (trace_gate_ != nullptr && !trace_gate_->enabled()) return true;
    return writer_->memory(*trace_, pc, record);
}

InstructionView InstructionCollector::resolve(QBDI::VM *vm,
                                              const QBDI::GPRState *gpr) noexcept {
    const uintptr_t address = gpr != nullptr ? gpr->pc : 0;
    uint32_t opcode = 0;
    if (address != 0) {
        std::memcpy(&opcode, reinterpret_cast<const void *>(address), sizeof(opcode));
        if (cache_ != nullptr) {
            QbdiDecoderRequest request{vm, decode_memory_};
            const CachedInstruction *decoded = cache_->resolve(
                    opcode, decode_current_instruction, &request, &uncached_);
            return {address, decoded != nullptr ? decoded : &uncached_};
        }
    }

    uncached_ = CachedInstruction{};
    QbdiDecoderRequest request{vm, decode_memory_};
    decode_current_instruction(opcode, &request, &uncached_);
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

void InstructionCollector::capture_pre_memory(QBDI::VM *vm) noexcept {
    if (!current_view_.decoded->requires_slow_memory_path || vm == nullptr ||
        memory_policy_.pre_capture_count() >=
                MemoryTracePolicy::kMaxPreMemoryCaptures) {
        return;
    }
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access: accesses) {
        const NormalizedMemoryAccess normalized = normalize(access);
        if (!memory_policy_.matches_instruction(current_view_.address, normalized)) continue;
        memory_policy_.add_pre_access(normalized, hexdump_limit_,
                                      safe_read_memory);
    }
}
