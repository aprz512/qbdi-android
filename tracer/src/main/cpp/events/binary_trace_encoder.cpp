#include "events/binary_trace_encoder.h"

#include "core/instruction_cache.h"
#include "core/trace_config.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

static_assert(sizeof(uintptr_t) == 4 || sizeof(uintptr_t) == 8);
static_assert(kTraceGprCount == kBinaryMaxGprCount);
static_assert(CachedInstruction::kMaxMemoryOperands == kBinaryMaxMemoryOperandCount);
static_assert(kMaxCapturedMemoryBytes == kBinaryMaxCapturedMemoryBytes);

constexpr uint64_t kValidGprMask = (1ULL << kTraceGprCount) - 1U;
constexpr uint32_t kValidInstructionFlags =
        static_cast<uint32_t>(InstructionFlags::Branch) |
        static_cast<uint32_t>(InstructionFlags::PcRelative) |
        static_cast<uint32_t>(InstructionFlags::Call) |
        static_cast<uint32_t>(InstructionFlags::Return);

struct AppendBuffer {
    uint8_t *output;
    size_t offset = 0;
};

void append_u8(AppendBuffer &buffer, uint8_t value) noexcept {
    buffer.output[buffer.offset++] = value;
}
void append_u16(AppendBuffer &buffer, uint16_t value) noexcept {
    append_u8(buffer, static_cast<uint8_t>(value));
    append_u8(buffer, static_cast<uint8_t>(value >> 8U));
}

void append_u32(AppendBuffer &buffer, uint32_t value) noexcept {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        append_u8(buffer, static_cast<uint8_t>(value >> shift));
    }
}

void append_u64(AppendBuffer &buffer, uint64_t value) noexcept {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        append_u8(buffer, static_cast<uint8_t>(value >> shift));
    }
}

void append_bytes(AppendBuffer &buffer, const uint8_t *data, size_t size) noexcept {
    for (size_t index = 0; index < size; ++index) append_u8(buffer, data[index]);
}

void append_string(AppendBuffer &buffer, std::string_view value) noexcept {
    append_u16(buffer, static_cast<uint16_t>(value.size()));
    append_bytes(buffer, reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

void append_record_header(AppendBuffer &buffer, BinaryRecordType type,
                          size_t payload_bytes) noexcept {
    append_u16(buffer, static_cast<uint16_t>(type));
    append_u16(buffer, kBinaryRecordFlags);
    append_u32(buffer, static_cast<uint32_t>(payload_bytes));
}

BinaryEncodeResult preflight(uint8_t *output, size_t capacity, size_t required) noexcept {
    if (output == nullptr || capacity < required) return {false, required};
    return {true, required};
}

template <size_t Size>
std::string_view bounded_string(const char (&value)[Size]) noexcept {
    size_t length = 0;
    while (length < Size && value[length] != '\0') ++length;
    return {value, length};
}

bool valid_profile(TraceProfile profile, uint8_t *wire_value) noexcept {
    switch (profile) {
        case TraceProfile::Fast:
            *wire_value = 0;
            return true;
        case TraceProfile::Balanced:
            *wire_value = 1;
            return true;
        case TraceProfile::Full:
            *wire_value = 2;
            return true;
    }
    return false;
}

bool valid_pc_relative_kind(PcRelativeKind kind) noexcept {
    return kind == PcRelativeKind::None || kind == PcRelativeKind::CurrentPc ||
           kind == PcRelativeKind::CurrentPage;
}

bool valid_memory_access_kind(MemoryAccessKind kind) noexcept {
    return kind == MemoryAccessKind::Read || kind == MemoryAccessKind::Write ||
           kind == MemoryAccessKind::ReadWrite;
}

bool valid_memory_state(MemoryBytesState state) noexcept {
    return state == MemoryBytesState::NotCaptured || state == MemoryBytesState::Available ||
           state == MemoryBytesState::Unavailable;
}

bool valid_memory_bytes(const MemoryBytes &bytes) noexcept {
    if (!valid_memory_state(bytes.state) || bytes.size > kBinaryMaxCapturedMemoryBytes) {
        return false;
    }
    return bytes.state == MemoryBytesState::Available || bytes.size == 0;
}

bool valid_memory_operand(const MemoryOperand &operand) noexcept {
    const auto valid_register = [](uint8_t value) {
        return value < kTraceGprCount || value == MemoryOperand::kNoRegister;
    };
    return valid_register(operand.base_reg) && valid_register(operand.index_reg) &&
           operand.extend <= MemoryIndexExtend::Sxtx &&
           operand.address_mode <= MemoryAddressMode::PostIndex &&
           valid_memory_access_kind(operand.kind);
}

uint8_t mask_count(uint64_t mask) noexcept {
    uint8_t count = 0;
    while (mask != 0) {
        ++count;
        mask &= mask - 1U;
    }
    return count;
}

size_t register_definition_bytes(uint64_t mask,
                                 const char names[kTraceGprCount][kMaxRegisterNameBytes]) noexcept {
    size_t bytes = 0;
    for (size_t index = 0; index < kTraceGprCount; ++index) {
        if ((mask & (1ULL << index)) != 0) {
            size_t length = 0;
            while (length < kMaxRegisterNameBytes && names[index][length] != '\0') ++length;
            bytes += 1U + 2U + length;
        }
    }
    return bytes;
}

void append_register_definitions(
        AppendBuffer &buffer, uint64_t mask, const uint8_t widths[kTraceGprCount],
        const char names[kTraceGprCount][kMaxRegisterNameBytes]) noexcept {
    for (size_t index = 0; index < kTraceGprCount; ++index) {
        if ((mask & (1ULL << index)) == 0) continue;
        append_u8(buffer, widths[index]);
        size_t length = 0;
        while (length < kMaxRegisterNameBytes && names[index][length] != '\0') ++length;
        append_string(buffer, {names[index], length});
    }
}

void append_memory_operand(AppendBuffer &buffer, const MemoryOperand &operand) noexcept {
    append_u8(buffer, operand.base_reg);
    append_u8(buffer, operand.index_reg);
    append_u8(buffer, static_cast<uint8_t>(operand.extend));
    append_u8(buffer, static_cast<uint8_t>(operand.address_mode));
    append_u8(buffer, operand.shift);
    append_u8(buffer, static_cast<uint8_t>(operand.kind));
    append_u8(buffer, operand.writeback ? 1U : 0U);
    append_u32(buffer, operand.access_size);
    append_u64(buffer, static_cast<uint64_t>(operand.displacement));
}

void append_memory_bytes(AppendBuffer &buffer, const MemoryBytes &bytes) noexcept {
    append_u8(buffer, static_cast<uint8_t>(bytes.state));
    append_u8(buffer, bytes.size);
    append_bytes(buffer, bytes.data.data(), bytes.size);
}

bool semantic_event_type(BinaryRecordType type) noexcept {
    return type == BinaryRecordType::Rule || type == BinaryRecordType::Error;
}

} // namespace

BinaryEncodeResult BinaryTraceEncoder::encode_stream_header(
        uint8_t *output, size_t capacity, TraceProfile profile) const noexcept {
    uint8_t profile_value = 0;
    if (!valid_profile(profile, &profile_value)) return {};
    const BinaryEncodeResult result = preflight(output, capacity, kBinaryStreamHeaderBytes);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_bytes(buffer, kBinaryTraceMagic, sizeof(kBinaryTraceMagic));
    append_u8(buffer, kBinaryTraceMajorVersion);
    append_u8(buffer, kBinaryTraceMinorVersion);
    append_u8(buffer, kBinaryLittleEndianMarker);
    append_u8(buffer, sizeof(uintptr_t));
    append_u8(buffer, profile_value);
    append_u8(buffer, 0);
    append_u16(buffer, kBinaryStreamHeaderBytes);
    append_u32(buffer, kBinaryRequiredFeatures);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_begin(
        uint8_t *output, size_t capacity, const TraceContext &context,
        const TraceBeginInfo &info) const noexcept {
    uint8_t profile_value = 0;
    if (!valid_profile(info.profile, &profile_value)) return {};
    if (context.scene_name.size() > kBinaryMaxContextStringBytes ||
        context.target_so.size() > kBinaryMaxContextStringBytes) {
        return {};
    }
    const size_t payload_bytes = kBinaryTraceBeginFixedPayloadBytes + context.scene_name.size() +
                                 context.target_so.size();
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::TraceBegin, payload_bytes);
    append_u64(buffer, static_cast<uint64_t>(context.module_base));
    append_u64(buffer, static_cast<uint64_t>(context.target_offset));
    append_u64(buffer, static_cast<uint64_t>(context.target_address));
    append_u32(buffer, static_cast<uint32_t>(context.pid));
    append_u32(buffer, static_cast<uint32_t>(context.tid));
    append_u8(buffer, profile_value);
    append_u8(buffer, info.compression_enabled ? 1U : 0U);
    append_u64(buffer, info.effective_buffer_bytes);
    append_u64(buffer, info.run_id);
    append_string(buffer, context.scene_name);
    append_string(buffer, context.target_so);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_module_definition(
        uint8_t *output, size_t capacity, uint32_t module_id, std::string_view module_name,
        uintptr_t module_base) const noexcept {
    if (module_name.size() > kBinaryMaxModuleNameBytes) return {};
    const size_t payload_bytes = kBinaryModuleDefinitionFixedPayloadBytes + module_name.size();
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::ModuleDefinition, payload_bytes);
    append_u32(buffer, module_id);
    append_u64(buffer, static_cast<uint64_t>(module_base));
    append_string(buffer, module_name);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_instruction_definition(
        uint8_t *output, size_t capacity, uint32_t metadata_id,
        const CachedInstruction &instruction) const noexcept {
    const uint32_t flags = static_cast<uint32_t>(instruction.flags);
    if ((instruction.read_gpr_mask & ~kValidGprMask) != 0 ||
        (instruction.write_gpr_mask & ~kValidGprMask) != 0 ||
        (flags & ~kValidInstructionFlags) != 0 ||
        !valid_pc_relative_kind(instruction.pc_relative_kind) ||
        instruction.memory_operand_count > CachedInstruction::kMaxMemoryOperands) {
        return {};
    }
    for (size_t index = 0; index < instruction.memory_operand_count; ++index) {
        if (!valid_memory_operand(instruction.memory_operands[index])) return {};
    }

    const std::string_view mnemonic = bounded_string(instruction.mnemonic);
    const std::string_view operands = bounded_string(instruction.operands);
    const std::string_view disassembly = bounded_string(instruction.disassembly);
    const size_t payload_bytes =
            kBinaryInstructionDefinitionFixedPayloadBytes + 2U + mnemonic.size() +
            2U + operands.size() + 2U + disassembly.size() +
            register_definition_bytes(instruction.read_gpr_mask,
                                      instruction.read_register_names) +
            register_definition_bytes(instruction.write_gpr_mask,
                                      instruction.write_register_names) +
            static_cast<size_t>(instruction.memory_operand_count) *
                    kBinaryEncodedMemoryOperandBytes;
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::InstructionDefinition, payload_bytes);
    append_u32(buffer, metadata_id);
    append_u32(buffer, instruction.opcode);
    append_u64(buffer, instruction.read_gpr_mask);
    append_u64(buffer, instruction.write_gpr_mask);
    append_u64(buffer, static_cast<uint64_t>(instruction.pc_relative_displacement));
    append_u32(buffer, flags);
    append_u8(buffer, static_cast<uint8_t>(instruction.pc_relative_kind));
    append_u8(buffer, instruction.condition);
    append_u8(buffer, instruction.memory_operand_count);
    append_u8(buffer, instruction.requires_slow_memory_path ? 1U : 0U);
    append_string(buffer, mnemonic);
    append_string(buffer, operands);
    append_string(buffer, disassembly);
    append_register_definitions(buffer, instruction.read_gpr_mask,
                                instruction.read_gpr_widths,
                                instruction.read_register_names);
    append_register_definitions(buffer, instruction.write_gpr_mask,
                                instruction.write_gpr_widths,
                                instruction.write_register_names);
    for (size_t index = 0; index < instruction.memory_operand_count; ++index) {
        append_memory_operand(buffer, instruction.memory_operands[index]);
    }
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_instruction(
        uint8_t *output, size_t capacity, uint32_t module_id, uint32_t metadata_id,
        const InstructionRecord &record) const noexcept {
    if (record.decoded == nullptr || record.pc < record.module_base ||
        (record.decoded->read_gpr_mask & ~kValidGprMask) != 0 ||
        (record.decoded->write_gpr_mask & ~kValidGprMask) != 0) {
        return {};
    }
    const uint8_t read_count = mask_count(record.decoded->read_gpr_mask);
    const uint8_t write_count = mask_count(record.decoded->write_gpr_mask);
    if (record.reads.count != read_count || record.writes.count != write_count) return {};
    const size_t payload_bytes = kBinaryInstructionFixedPayloadBytes +
                                 (static_cast<size_t>(read_count) + write_count) *
                                         sizeof(uint64_t);
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::Instruction, payload_bytes);
    append_u64(buffer, record.sequence);
    append_u32(buffer, module_id);
    append_u64(buffer, static_cast<uint64_t>(record.pc - record.module_base));
    append_u32(buffer, metadata_id);
    append_u8(buffer, read_count);
    append_u8(buffer, write_count);
    size_t dense_index = 0;
    uint64_t read_mask = record.decoded->read_gpr_mask;
    while (read_mask != 0) {
        static_cast<void>(std::countr_zero(read_mask));
        append_u64(buffer, record.reads.values[dense_index++]);
        read_mask &= read_mask - 1U;
    }
    dense_index = 0;
    uint64_t write_mask = record.decoded->write_gpr_mask;
    while (write_mask != 0) {
        static_cast<void>(std::countr_zero(write_mask));
        append_u64(buffer, record.writes.values[dense_index++]);
        write_mask &= write_mask - 1U;
    }
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_memory(
        uint8_t *output, size_t capacity, uint32_t module_id,
        uintptr_t module_relative_pc, const MemoryRecord &record) const noexcept {
    if (!valid_memory_access_kind(record.kind) || !valid_memory_bytes(record.before) ||
        !valid_memory_bytes(record.after)) {
        return {};
    }
    const size_t payload_bytes = kBinaryMemoryFixedPayloadBytes + record.before.size +
                                 record.after.size;
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::Memory, payload_bytes);
    append_u32(buffer, module_id);
    append_u64(buffer, static_cast<uint64_t>(module_relative_pc));
    append_u8(buffer, static_cast<uint8_t>(record.kind));
    append_u8(buffer, record.metadata_available ? 1U : 0U);
    append_u16(buffer, record.flags);
    append_u64(buffer, static_cast<uint64_t>(record.address));
    append_u32(buffer, record.size);
    append_u64(buffer, record.value);
    append_memory_bytes(buffer, record.before);
    append_memory_bytes(buffer, record.after);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_call(
        uint8_t *output, size_t capacity, std::string_view category, std::string_view name,
        std::string_view detail) const noexcept {
    if (category.size() > kBinaryMaxCallCategoryBytes ||
        name.size() > kBinaryMaxCallNameBytes ||
        detail.size() > kBinaryMaxEventDetailBytes) {
        return {};
    }
    const size_t payload_bytes = kBinaryCallFixedPayloadBytes + category.size() + name.size() +
                                 detail.size();
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::Call, payload_bytes);
    append_string(buffer, category);
    append_string(buffer, name);
    append_string(buffer, detail);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_event(
        uint8_t *output, size_t capacity, BinaryRecordType type, std::string_view name,
        std::string_view detail) const noexcept {
    if (!semantic_event_type(type) || name.size() > kBinaryMaxEventNameBytes ||
        detail.size() > kBinaryMaxEventDetailBytes) {
        return {};
    }
    const size_t payload_bytes = kBinaryRuleErrorFixedPayloadBytes + name.size() + detail.size();
    const size_t required = kBinaryRecordHeaderBytes + payload_bytes;
    const BinaryEncodeResult result = preflight(output, capacity, required);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, type, payload_bytes);
    append_string(buffer, name);
    append_string(buffer, detail);
    return {true, buffer.offset};
}

BinaryEncodeResult BinaryTraceEncoder::encode_end(
        uint8_t *output, size_t capacity, bool success, uint64_t return_value,
        uint64_t elapsed_ms, const TraceMetrics &metrics) const noexcept {
    const BinaryEncodeResult result = preflight(output, capacity, kBinaryTraceEndRecordBytes);
    if (!result.ok) return result;

    AppendBuffer buffer{output};
    append_record_header(buffer, BinaryRecordType::TraceEnd, kBinaryTraceEndPayloadBytes);
    append_u8(buffer, success ? 1U : 0U);
    append_u64(buffer, return_value);
    append_u64(buffer, elapsed_ms);
    append_u64(buffer, metrics.instructions);
    append_u64(buffer, metrics.raw_bytes);
    append_u64(buffer, metrics.compressed_bytes);
    append_u64(buffer, metrics.cache_hits);
    append_u64(buffer, metrics.cache_misses);
    append_u64(buffer, metrics.cache_collisions);
    append_u64(buffer, metrics.buffer_swaps);
    append_u64(buffer, metrics.producer_waits);
    append_u64(buffer, metrics.producer_wait_ns);
    append_u64(buffer, metrics.effective_buffer_bytes);
    return {true, buffer.offset};
}
