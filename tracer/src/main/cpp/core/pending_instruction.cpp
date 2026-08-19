#include "core/pending_instruction.h"

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

    pending_record_ = {};
    pending_record_.sequence = next_sequence_++;
    pending_record_.pc = instruction.address;
    pending_record_.module_base = module_base_;
    pending_record_.decoded = instruction.decoded;
    if (instruction.decoded != nullptr) {
        for (size_t index = 0; index < kTraceGprCount; ++index) {
            const uint64_t bit = 1ULL << index;
            if ((instruction.decoded->read_gpr_mask & bit) != 0) {
                pending_record_.before[index] = truncate_to_width(
                        registers.values[index], instruction.decoded->read_gpr_widths[index]);
            }
            if (instruction.decoded->read_register_names[index][0] != '\0') {
                pending_record_.read_register_names[index] =
                        instruction.decoded->read_register_names[index];
            }
            if (instruction.decoded->write_register_names[index][0] != '\0') {
                pending_record_.write_register_names[index] =
                        instruction.decoded->write_register_names[index];
            }
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

uint64_t PendingInstructionCollector::pending_write_mask() const noexcept {
    return pending_ && pending_record_.decoded != nullptr
                   ? pending_record_.decoded->write_gpr_mask
                   : 0;
}

bool PendingInstructionCollector::complete(const RegisterSnapshot &registers) noexcept {
    if (pending_record_.decoded != nullptr) {
        for (size_t index = 0; index < kTraceGprCount; ++index) {
            const uint64_t bit = 1ULL << index;
            if ((pending_record_.decoded->write_gpr_mask & bit) != 0) {
                pending_record_.after[index] = truncate_to_width(
                        registers.values[index], pending_record_.decoded->write_gpr_widths[index]);
            }
        }
    }

    pending_ = false;
    return sink_ != nullptr && sink_->emit(pending_record_);
}
