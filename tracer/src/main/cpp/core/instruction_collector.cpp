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
    pre_memory_count_ = 0;
    if (profile_ == TraceProfile::Full && gpr != nullptr) capture_pre_memory(vm, *gpr);
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
            if (access.instAddress != current_view_.address) continue;
            matched = true;
            const MemoryRecord memory = memory_record(access);
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

void InstructionCollector::capture_pre_memory(QBDI::VM *vm,
                                              const QBDI::GPRState &gpr) noexcept {
    if (current_view_.decoded == nullptr) return;
    const RegisterSnapshot registers = snapshot(gpr, UINT64_MAX);
    const size_t operand_count = std::min(
            static_cast<size_t>(current_view_.decoded->memory_operand_count),
            CachedInstruction::kMaxMemoryOperands);
    for (size_t index = 0; index < operand_count; ++index) {
        const MemoryOperand &operand = current_view_.decoded->memory_operands[index];
        uintptr_t address = 0;
        if (!operand.try_effective_address(registers, &address)) continue;
        PreMemoryCapture &capture = pre_memory_[pre_memory_count_++];
        capture.address = address;
        capture.access_size = operand.access_size;
        capture.access_type = operand.access_type;
        capture_memory_bytes(address, operand.access_size, hexdump_limit_, safe_read_memory,
                             &capture.bytes);
    }
    if (!current_view_.decoded->requires_slow_memory_path || vm == nullptr ||
        pre_memory_count_ >= pre_memory_.size()) {
        return;
    }
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access: accesses) {
        if (access.instAddress != current_view_.address ||
            pre_memory_count_ >= pre_memory_.size()) {
            continue;
        }
        bool duplicate = false;
        for (size_t index = 0; index < pre_memory_count_; ++index) {
            duplicate = duplicate ||
                        (pre_memory_[index].address == access.accessAddress &&
                         pre_memory_[index].access_size == access.size);
        }
        if (duplicate) continue;
        PreMemoryCapture &capture = pre_memory_[pre_memory_count_++];
        capture.address = access.accessAddress;
        capture.access_size = access.size;
        capture.access_type = static_cast<uint8_t>(access.type);
        capture_memory_bytes(capture.address, capture.access_size, hexdump_limit_,
                             safe_read_memory, &capture.bytes);
    }
}

MemoryRecord InstructionCollector::memory_record(
        const QBDI::MemoryAccess &access) const noexcept {
    MemoryRecord memory{};
    memory.access_type = static_cast<uint8_t>(access.type);
    memory.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
    memory.flags = static_cast<uint16_t>(access.flags);
    memory.address = access.accessAddress;
    memory.size = access.size;
    memory.value = truncate_memory_value(access.value, access.size, memory.flags);

    if (profile_ != TraceProfile::Full) return memory;
    const size_t capture_size = bounded_memory_capture_size(access.size, hexdump_limit_);
    if (capture_size == 0) return memory;
    memory.before.state = MemoryBytesState::Unavailable;

    for (size_t index = 0; index < pre_memory_count_; ++index) {
        const PreMemoryCapture &capture = pre_memory_[index];
        if (memory.address < capture.address) {
            continue;
        }
        const uintptr_t offset = memory.address - capture.address;
        if (offset > capture.access_size || capture_size > capture.access_size - offset) continue;
        if (capture.bytes.state != MemoryBytesState::Available) {
            memory.before.state = capture.bytes.state == MemoryBytesState::Unavailable
                                          ? MemoryBytesState::Unavailable
                                          : memory.before.state;
            break;
        }
        if (offset > capture.bytes.size || capture_size > capture.bytes.size - offset) continue;
        std::memcpy(memory.before.data.data(), capture.bytes.data.data() + offset, capture_size);
        memory.before.size = static_cast<uint8_t>(capture_size);
        memory.before.state = MemoryBytesState::Available;
        break;
    }

    if ((memory.access_type & static_cast<uint8_t>(QBDI::MEMORY_WRITE)) != 0) {
        capture_memory_bytes(memory.address, memory.size, hexdump_limit_, safe_read_memory,
                             &memory.after);
    }
    return memory;
}
