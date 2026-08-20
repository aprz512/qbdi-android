#include "core/pending_instruction.h"

#include <bit>
#include <cstddef>

namespace {

uint64_t truncate_to_width(uint64_t value, uint8_t width_bytes) noexcept {
    if (width_bytes == 0 || width_bytes >= sizeof(value)) return value;
    const unsigned int width_bits = static_cast<unsigned int>(width_bytes) * 8U;
    return value & ((1ULL << width_bits) - 1ULL);
}

} // namespace

PendingInstructionCollector::PendingInstructionCollector(PendingInstructionSink *sink,
                                                         uintptr_t module_base) noexcept
        : sink_(sink), module_base_(module_base) {}

bool PendingInstructionCollector::begin(const InstructionView &instruction,
                                        const RegisterSnapshot &registers) noexcept {
    if (pending_ && !complete(registers)) return false;

    if (instruction.decoded != nullptr &&
        (!valid_trace_gpr_mask(instruction.decoded->read_gpr_mask) ||
         !valid_trace_gpr_mask(instruction.decoded->write_gpr_mask))) {
        return false;
    }

    continuing_memory_ = false;
    continuation_pc_ = 0;
    pending_record_.sequence = next_sequence_++;
    pending_record_.pc = instruction.address;
    pending_record_.module_base = module_base_;
    pending_record_.decoded = instruction.decoded;
    pending_record_.reads.count = 0;
    pending_record_.writes.count = 0;
    pending_record_.memory_count = 0;
    if (instruction.decoded != nullptr) {
        uint64_t mask = instruction.decoded->read_gpr_mask;
        while (mask != 0) {
            const size_t index = std::countr_zero(mask);
            pending_record_.reads.values[pending_record_.reads.count++] = truncate_to_width(
                    registers.values[index], instruction.decoded->read_gpr_widths[index]);
            mask &= mask - 1U;
        }
    }
    pending_ = true;
    return true;
}

bool PendingInstructionCollector::complete_pending(
        const RegisterSnapshot &registers) noexcept {
    return pending_ && complete(registers);
}

bool PendingInstructionCollector::finish_last(const RegisterSnapshot &registers) noexcept {
    return complete_pending(registers);
}

bool PendingInstructionCollector::append_memory(const MemoryRecord &memory) noexcept {
    if (!pending_ || pending_record_.memory_count >= pending_record_.memory.size()) return false;
    pending_record_.memory[pending_record_.memory_count++] = memory;
    return true;
}

bool PendingInstructionCollector::append_or_emit_memory(
        const MemoryRecord &memory, const RegisterSnapshot &registers) noexcept {
    if (append_memory(memory)) return true;
    if (pending_) {
        continuation_pc_ = pending_record_.pc;
        if (!complete(registers)) return false;
        continuing_memory_ = true;
    }
    return continuing_memory_ && sink_ != nullptr &&
           sink_->emit_memory_continuation(continuation_pc_, memory);
}

bool PendingInstructionCollector::complete_memory(
        const RegisterSnapshot &registers) noexcept {
    if (pending_ && !complete(registers)) return false;
    const bool completed = continuing_memory_ || !pending_;
    continuing_memory_ = false;
    continuation_pc_ = 0;
    return completed;
}

uint64_t PendingInstructionCollector::pending_write_mask() const noexcept {
    return pending_ && pending_record_.decoded != nullptr
                   ? pending_record_.decoded->write_gpr_mask
                   : 0;
}

bool PendingInstructionCollector::complete(const RegisterSnapshot &registers) noexcept {
    if (pending_record_.decoded != nullptr) {
        if (!valid_trace_gpr_mask(pending_record_.decoded->write_gpr_mask)) {
            pending_ = false;
            return false;
        }
        uint64_t mask = pending_record_.decoded->write_gpr_mask;
        while (mask != 0) {
            const size_t index = std::countr_zero(mask);
            pending_record_.writes.values[pending_record_.writes.count++] = truncate_to_width(
                    registers.values[index], pending_record_.decoded->write_gpr_widths[index]);
            mask &= mask - 1U;
        }
    }

    pending_ = false;
    return sink_ != nullptr && sink_->emit(pending_record_);
}
