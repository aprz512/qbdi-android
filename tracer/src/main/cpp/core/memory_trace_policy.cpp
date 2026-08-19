#include "core/memory_trace_policy.h"

#include <algorithm>
#include <cstring>

namespace {

bool kinds_match(MemoryAccessKind captured, MemoryAccessKind actual) noexcept {
    const uint8_t captured_bits = static_cast<uint8_t>(captured);
    const uint8_t actual_bits = static_cast<uint8_t>(actual);
    return (captured_bits & actual_bits) != 0;
}

} // namespace

size_t bounded_memory_capture_size(size_t access_size,
                                   size_t configured_limit) noexcept {
    return std::min(std::min(access_size, configured_limit),
                    kMaxCapturedMemoryBytes);
}

void capture_memory_bytes(uintptr_t address, size_t access_size,
                          size_t configured_limit, MemoryReadFunction reader,
                          MemoryBytes *capture) noexcept {
    if (capture == nullptr) return;
    *capture = {};
    const size_t size = bounded_memory_capture_size(access_size, configured_limit);
    if (size == 0) return;
    if (reader == nullptr || !reader(address, capture->data.data(), size)) {
        capture->state = MemoryBytesState::Unavailable;
        return;
    }
    capture->size = static_cast<uint8_t>(size);
    capture->state = MemoryBytesState::Available;
}

uint64_t truncate_memory_value(uint64_t value, uint32_t access_size,
                               uint16_t access_flags) noexcept {
    constexpr uint16_t kUnknownSize = 1U;
    constexpr uint16_t kMinimumSize = 2U;
    if ((access_flags & (kUnknownSize | kMinimumSize)) != 0 || access_size == 0 ||
        access_size >= sizeof(value)) {
        return value;
    }
    const unsigned int bits = access_size * 8U;
    return value & ((1ULL << bits) - 1ULL);
}

bool MemoryTracePolicy::add_capture(uintptr_t address, uint32_t access_size,
                                    MemoryAccessKind kind,
                                    size_t hexdump_limit,
                                    MemoryReadFunction reader) noexcept {
    if (pre_memory_count_ >= pre_memory_.size()) {
        overflowed_ = true;
        return false;
    }
    PreMemoryCapture &capture = pre_memory_[pre_memory_count_++];
    capture.address = address;
    capture.access_size = access_size;
    capture.kind = kind;
    capture_memory_bytes(address, access_size, hexdump_limit, reader,
                         &capture.bytes);
    return true;
}

bool MemoryTracePolicy::capture_after_rule(
        TraceProfile profile, bool rule_continues,
        const CachedInstruction &instruction,
        const RegisterSnapshot &registers, size_t hexdump_limit,
        MemoryReadFunction reader) noexcept {
    pre_memory_count_ = 0;
    overflowed_ = false;
    if (!rule_continues) return false;
    if (profile != TraceProfile::Full) return true;

    const size_t operand_count = std::min(
            static_cast<size_t>(instruction.memory_operand_count),
            CachedInstruction::kMaxMemoryOperands);
    for (size_t operand_index = 0; operand_index < operand_count; ++operand_index) {
        const MemoryOperand &operand = instruction.memory_operands[operand_index];
        uintptr_t base = 0;
        if (!operand.try_effective_address(registers, &base) ||
            operand.access_size == 0) {
            continue;
        }
        uint32_t remaining = operand.access_size;
        uintptr_t address = base;
        size_t access_count = 0;
        while (remaining != 0 && access_count < kMaxAccessesPerOperand) {
            const uint32_t size = std::min(
                    remaining, static_cast<uint32_t>(kQbdiAccessBytes));
            if (!add_capture(address, size, operand.kind, hexdump_limit, reader)) {
                break;
            }
            address += size;
            remaining -= size;
            ++access_count;
        }
        if (remaining != 0) overflowed_ = true;
    }
    return true;
}

bool MemoryTracePolicy::add_pre_access(const NormalizedMemoryAccess &access,
                                       size_t hexdump_limit,
                                       MemoryReadFunction reader) noexcept {
    for (size_t index = 0; index < pre_memory_count_; ++index) {
        const PreMemoryCapture &capture = pre_memory_[index];
        if (capture.address == access.address &&
            capture.access_size == access.size &&
            kinds_match(capture.kind, access.kind)) {
            return true;
        }
    }
    return add_capture(access.address, access.size, access.kind,
                       hexdump_limit, reader);
}

MemoryRecord MemoryTracePolicy::record(const NormalizedMemoryAccess &access,
                                       TraceProfile profile,
                                       size_t hexdump_limit,
                                       MemoryReadFunction reader) const noexcept {
    MemoryRecord memory{};
    memory.kind = access.kind;
    memory.metadata_available = true;
    memory.flags = access.flags;
    memory.address = access.address;
    memory.size = access.size;
    memory.value = truncate_memory_value(access.value, access.size, access.flags);
    if (profile != TraceProfile::Full) return memory;

    const size_t capture_size = bounded_memory_capture_size(access.size,
                                                            hexdump_limit);
    if (capture_size == 0) return memory;
    memory.before.state = MemoryBytesState::Unavailable;
    for (size_t index = 0; index < pre_memory_count_; ++index) {
        const PreMemoryCapture &capture = pre_memory_[index];
        if (!kinds_match(capture.kind, access.kind) ||
            access.address < capture.address) {
            continue;
        }
        const uintptr_t offset = access.address - capture.address;
        if (offset > capture.access_size ||
            capture_size > capture.access_size - offset) {
            continue;
        }
        if (capture.bytes.state == MemoryBytesState::Unavailable) break;
        if (capture.bytes.state != MemoryBytesState::Available ||
            offset > capture.bytes.size ||
            capture_size > capture.bytes.size - offset) {
            continue;
        }
        std::memcpy(memory.before.data.data(), capture.bytes.data.data() + offset,
                    capture_size);
        memory.before.size = static_cast<uint8_t>(capture_size);
        memory.before.state = MemoryBytesState::Available;
        break;
    }

    const uint8_t kind_bits = static_cast<uint8_t>(memory.kind);
    if ((kind_bits & static_cast<uint8_t>(MemoryAccessKind::Write)) != 0) {
        capture_memory_bytes(memory.address, memory.size, hexdump_limit, reader,
                             &memory.after);
    }
    return memory;
}

bool MemoryTracePolicy::matches_instruction(
        uintptr_t expected_instruction,
        const NormalizedMemoryAccess &access) const noexcept {
    return access.inst_address == expected_instruction;
}

bool MemoryTracePolicy::record_if_matches(
        uintptr_t expected_instruction, const NormalizedMemoryAccess &access,
        TraceProfile profile, size_t hexdump_limit, MemoryReadFunction reader,
        MemoryRecord *record_output) const noexcept {
    if (record_output == nullptr ||
        !matches_instruction(expected_instruction, access)) {
        return false;
    }
    *record_output = record(access, profile, hexdump_limit, reader);
    return true;
}
