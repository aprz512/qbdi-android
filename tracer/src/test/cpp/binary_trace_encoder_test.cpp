#include "core/instruction_cache.h"
#include "events/binary_trace_encoder.h"
#include "events/binary_trace_format.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>

namespace {

[[noreturn]] void fail(const char *expression, int line) {
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) \
    do { \
        if (!(expression)) fail(#expression, __LINE__); \
    } while (false)

void check_bytes(const uint8_t *actual, size_t actual_size,
                 std::initializer_list<uint8_t> expected) {
    CHECK(actual_size == expected.size());
    CHECK(std::equal(expected.begin(), expected.end(), actual));
}

void stream_header_is_exact_and_tagged() {
    uint8_t bytes[kBinaryStreamHeaderBytes]{};
    const BinaryTraceEncoder encoder;
    const BinaryEncodeResult result =
            encoder.encode_stream_header(bytes, sizeof(bytes), TraceProfile::Fast);

    CHECK(result.ok);
    CHECK(result.size == kBinaryStreamHeaderBytes);
    CHECK(std::memcmp(bytes, "QTRB", 4) == 0);
    CHECK(bytes[4] == 1);
    CHECK(bytes[5] == 0);
    CHECK(bytes[6] == 1);
    CHECK(bytes[7] == sizeof(uintptr_t));
    CHECK(bytes[8] == 0);
    CHECK(bytes[9] == 0);
    CHECK(bytes[10] == 16);
    CHECK(bytes[11] == 0);
    CHECK(bytes[12] == 0);
    CHECK(bytes[13] == 0);
    CHECK(bytes[14] == 0);
    CHECK(bytes[15] == 0);
}

void trace_begin_has_exact_golden_bytes() {
    TraceContext context{};
    context.package_name = "p";
    context.scene_name = "s";
    context.target_so = "t";
    context.module_base = 0x0102030405060708ULL;
    context.target_offset = 0x1112131415161718ULL;
    context.target_address = 0x2122232425262728ULL;
    context.pid = 0x31323334;
    context.tid = 0x41424344;

    uint8_t bytes[128]{};
    const BinaryEncodeResult result =
            BinaryTraceEncoder{}.encode_begin(bytes, sizeof(bytes), context, 0x5152535455565758ULL);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x01, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
        0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51,
        0x34, 0x33, 0x32, 0x31, 0x44, 0x43, 0x42, 0x41,
        0x01, 0x00, 's', 0x01, 0x00, 't', 0x01, 0x00, 'p',
    });
}

void module_definition_has_exact_golden_bytes() {
    uint8_t bytes[64]{};
    const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_module_definition(
            bytes, sizeof(bytes), 0x11223344U, "m", 0x0102030405060708ULL);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x02, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x44, 0x33, 0x22, 0x11,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x01, 0x00, 'm',
    });
}

void instruction_definition_has_exact_golden_bytes() {
    CachedInstruction decoded{};
    decoded.opcode = 0x11223344U;

    uint8_t bytes[128]{};
    const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_instruction_definition(
            bytes, sizeof(bytes), 0xaabbccddU, decoded);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x03, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0xdd, 0xcc, 0xbb, 0xaa, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
}

void instruction_definition_preserves_pc_relative_kinds_and_displacement() {
    for (const PcRelativeKind kind : {PcRelativeKind::None, PcRelativeKind::CurrentPc,
                                      PcRelativeKind::CurrentPage}) {
        CachedInstruction decoded{};
        decoded.pc_relative_kind = kind;
        decoded.pc_relative_displacement = -2;
        uint8_t bytes[128]{};
        const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_instruction_definition(
                bytes, sizeof(bytes), 1, decoded);
        CHECK(result.ok);
        CHECK(bytes[32] == 0xfe);
        for (size_t index = 33; index < 40; ++index) CHECK(bytes[index] == 0xff);
        CHECK(bytes[44] == static_cast<uint8_t>(kind));
    }
}

void instruction_definition_preserves_static_registers_and_memory_operands() {
    CachedInstruction decoded{};
    decoded.opcode = 0xa1b2c3d4U;
    decoded.read_gpr_mask = (1ULL << 0U) | (1ULL << 33U);
    decoded.write_gpr_mask = 1ULL << 30U;
    decoded.read_gpr_widths[0] = 4;
    decoded.read_gpr_widths[33] = 8;
    decoded.write_gpr_widths[30] = 8;
    std::strcpy(decoded.read_register_names[0], "W0");
    std::strcpy(decoded.read_register_names[33], "PC");
    std::strcpy(decoded.write_register_names[30], "LR");
    std::strcpy(decoded.mnemonic, "ldr");
    std::strcpy(decoded.operands, "x0, [x1]");
    std::strcpy(decoded.disassembly, "ldr x0, [x1]");
    decoded.memory_operand_count = 1;
    decoded.requires_slow_memory_path = true;
    decoded.memory_operands[0].base_reg = 1;
    decoded.memory_operands[0].index_reg = 2;
    decoded.memory_operands[0].extend = MemoryIndexExtend::Sxtw;
    decoded.memory_operands[0].address_mode = MemoryAddressMode::PostIndex;
    decoded.memory_operands[0].shift = 3;
    decoded.memory_operands[0].kind = MemoryAccessKind::ReadWrite;
    decoded.memory_operands[0].access_size = 8;
    decoded.memory_operands[0].displacement = -16;
    decoded.memory_operands[0].writeback = true;

    uint8_t bytes[256]{};
    const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_instruction_definition(
            bytes, sizeof(bytes), 7, decoded);
    CHECK(result.ok);
    CHECK(result.size == kBinaryRecordHeaderBytes + 103);
    CHECK(bytes[4] == 103);
    CHECK(bytes[46] == 1);
    CHECK(bytes[47] == 1);
    CHECK(bytes[result.size - 19] == 1);
    CHECK(bytes[result.size - 18] == 2);
    CHECK(bytes[result.size - 17] == static_cast<uint8_t>(MemoryIndexExtend::Sxtw));
    CHECK(bytes[result.size - 16] == static_cast<uint8_t>(MemoryAddressMode::PostIndex));
    CHECK(bytes[result.size - 15] == 3);
    CHECK(bytes[result.size - 14] == static_cast<uint8_t>(MemoryAccessKind::ReadWrite));
    CHECK(bytes[result.size - 13] == 1);
    CHECK(bytes[result.size - 12] == 8);
    CHECK(bytes[result.size - 8] == 0xf0);
    for (size_t index = result.size - 7; index < result.size; ++index) CHECK(bytes[index] == 0xff);
}

void instruction_has_exact_golden_bytes_and_dense_values() {
    CachedInstruction decoded{};
    decoded.opcode = 0x44332211U;
    decoded.read_gpr_mask = (1ULL << 1U) | (1ULL << 33U);
    decoded.write_gpr_mask = 1ULL << 30U;
    InstructionRecord record{};
    record.sequence = 0x0102030405060708ULL;
    record.pc = 0x1020;
    record.module_base = 0x1000;
    record.decoded = &decoded;
    record.before[1] = 0x1112131415161718ULL;
    record.before[33] = 0x2122232425262728ULL;
    record.after[30] = 0x3132333435363738ULL;

    uint8_t bytes[96]{};
    const BinaryEncodeResult result =
            BinaryTraceEncoder{}.encode_instruction(bytes, sizeof(bytes), 0xaabbccddU, record);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x04, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0xdd, 0xcc, 0xbb, 0xaa,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
        0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
    });
}

void memory_has_exact_golden_bytes_and_all_capture_states() {
    MemoryRecord memory{};
    memory.kind = MemoryAccessKind::Write;
    memory.metadata_available = true;
    memory.flags = 0x3344;
    memory.address = 0x0102030405060708ULL;
    memory.size = 0x11223344U;
    memory.value = 0x1112131415161718ULL;
    memory.before.state = MemoryBytesState::Available;
    memory.before.size = 2;
    memory.before.data[0] = 0xaa;
    memory.before.data[1] = 0xbb;
    memory.after.state = MemoryBytesState::Unavailable;

    uint8_t bytes[96]{};
    BinaryEncodeResult result = BinaryTraceEncoder{}.encode_memory(
            bytes, sizeof(bytes), 0xaabbccddU, 0x2122232425262728ULL, memory);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x05, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
        0xdd, 0xcc, 0xbb, 0xaa,
        0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
        0x02, 0x01, 0x44, 0x33,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x44, 0x33, 0x22, 0x11,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x01, 0x02, 0xaa, 0xbb, 0x02, 0x00,
    });

    memory.before = {};
    memory.after = {};
    result = BinaryTraceEncoder{}.encode_memory(
            bytes, sizeof(bytes), 0xaabbccddU, 0x2122232425262728ULL, memory);
    CHECK(result.ok);
    CHECK(bytes[result.size - 4] == static_cast<uint8_t>(MemoryBytesState::NotCaptured));
    CHECK(bytes[result.size - 2] == static_cast<uint8_t>(MemoryBytesState::NotCaptured));
}

void semantic_events_have_exact_golden_bytes() {
    const BinaryTraceEncoder encoder;
    uint8_t bytes[32]{};

    BinaryEncodeResult result = encoder.encode_event(
            bytes, sizeof(bytes), BinaryRecordType::Call, "n", "d");
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01, 0x00, 'n', 0x01, 0x00, 'd',
    });

    result = encoder.encode_event(bytes, sizeof(bytes), BinaryRecordType::Rule, "r", "x");
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x07, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01, 0x00, 'r', 0x01, 0x00, 'x',
    });

    result = encoder.encode_event(bytes, sizeof(bytes), BinaryRecordType::Error, "e", "!");
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x01, 0x00, 'e', 0x01, 0x00, '!',
    });
}

void trace_end_has_exact_golden_bytes() {
    TraceMetrics metrics{};
    metrics.instructions = 1;
    metrics.raw_bytes = 2;
    metrics.compressed_bytes = 3;
    metrics.cache_hits = 4;
    metrics.cache_misses = 5;
    metrics.cache_collisions = 6;
    metrics.buffer_swaps = 7;
    metrics.producer_waits = 8;
    metrics.producer_wait_ns = 9;
    metrics.effective_buffer_bytes = 10;

    uint8_t bytes[128]{};
    const BinaryEncodeResult result = BinaryTraceEncoder{}.encode_end(
            bytes, sizeof(bytes), true, 0x0102030405060708ULL,
            0x1112131415161718ULL, metrics);
    CHECK(result.ok);
    check_bytes(bytes, result.size, {
        0x09, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00,
        0x01,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
}

template <typename Encode>
void check_one_byte_short_is_atomic(const Encode &encode) {
    std::array<uint8_t, kBinaryMaxEventRecordBytes> full{};
    const BinaryEncodeResult measured = encode(full.data(), full.size());
    CHECK(measured.ok);
    CHECK(measured.size > 0);

    std::array<uint8_t, kBinaryMaxEventRecordBytes> short_output{};
    std::fill(short_output.begin(), short_output.end(), 0xa5);
    const BinaryEncodeResult short_result =
            encode(short_output.data(), measured.size - 1U);
    CHECK(!short_result.ok);
    CHECK(short_result.size == measured.size);
    CHECK(std::all_of(short_output.begin(), short_output.end(),
                      [](uint8_t value) { return value == 0xa5; }));
}

void every_encoding_is_atomic_when_capacity_is_one_byte_short() {
    TraceContext context{};
    context.package_name = "p";
    context.scene_name = "s";
    context.target_so = "t";
    CachedInstruction decoded{};
    decoded.opcode = 1;
    InstructionRecord instruction{};
    instruction.decoded = &decoded;
    MemoryRecord memory{};
    TraceMetrics metrics{};
    const BinaryTraceEncoder encoder;

    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_stream_header(output, capacity, TraceProfile::Fast);
    });
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_begin(output, capacity, context, 1);
    });
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_module_definition(output, capacity, 1, "m", 2);
    });
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_instruction_definition(output, capacity, 1, decoded);
    });
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_instruction(output, capacity, 1, instruction);
    });
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_memory(output, capacity, 1, 2, memory);
    });
    for (const BinaryRecordType type : {BinaryRecordType::Call, BinaryRecordType::Rule,
                                        BinaryRecordType::Error}) {
        check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
            return encoder.encode_event(output, capacity, type, "n", "d");
        });
    }
    check_one_byte_short_is_atomic([&](uint8_t *output, size_t capacity) {
        return encoder.encode_end(output, capacity, true, 0x42, 7, metrics);
    });

    uint8_t too_small[7]{};
    CHECK(!encoder.encode_end(too_small, sizeof(too_small), true, 0x42, 7, metrics).ok);
    CHECK(std::all_of(std::begin(too_small), std::end(too_small),
                      [](uint8_t value) { return value == 0; }));
}

void rejects_invalid_or_oversized_inputs_without_writing() {
    BinaryTraceEncoder encoder;
    std::array<uint8_t, kBinaryMaxEventRecordBytes> output{};
    std::fill(output.begin(), output.end(), 0x5a);

    std::string oversized_name(kBinaryMaxEventNameBytes + 1U, 'n');
    BinaryEncodeResult result = encoder.encode_event(
            output.data(), output.size(), BinaryRecordType::Call, oversized_name, "detail");
    CHECK(!result.ok);
    CHECK(std::all_of(output.begin(), output.end(), [](uint8_t value) { return value == 0x5a; }));

    result = encoder.encode_event(output.data(), output.size(), BinaryRecordType::TraceBegin,
                                  "name", "detail");
    CHECK(!result.ok);
    CHECK(std::all_of(output.begin(), output.end(), [](uint8_t value) { return value == 0x5a; }));

    MemoryRecord memory{};
    memory.before.state = MemoryBytesState::Unavailable;
    memory.before.size = 1;
    result = encoder.encode_memory(output.data(), output.size(), 1, 2, memory);
    CHECK(!result.ok);
    CHECK(std::all_of(output.begin(), output.end(), [](uint8_t value) { return value == 0x5a; }));

    CachedInstruction decoded{};
    decoded.memory_operand_count = CachedInstruction::kMaxMemoryOperands + 1U;
    result = encoder.encode_instruction_definition(output.data(), output.size(), 1, decoded);
    CHECK(!result.ok);
    CHECK(std::all_of(output.begin(), output.end(), [](uint8_t value) { return value == 0x5a; }));
}

void declared_record_maxima_are_exact_and_encodable() {
    CHECK(kBinaryMaxTraceBeginRecordBytes == 819);
    CHECK(kBinaryMaxModuleDefinitionRecordBytes == 277);
    CHECK(kBinaryMaxInstructionDefinitionRecordBytes == 1646);
    CHECK(kBinaryMaxInstructionRecordBytes == 578);
    CHECK(kBinaryMaxMemoryRecordBytes == 176);
    CHECK(kBinaryMaxEventRecordBytes == 4363);
    CHECK(kBinaryTraceEndRecordBytes == 105);

    const BinaryTraceEncoder encoder;
    std::array<uint8_t, kBinaryMaxEventRecordBytes> output{};

    TraceContext context{};
    context.scene_name.assign(kBinaryMaxContextStringBytes, 's');
    context.target_so.assign(kBinaryMaxContextStringBytes, 't');
    context.package_name.assign(kBinaryMaxContextStringBytes, 'p');
    CHECK(encoder.encode_begin(output.data(), output.size(), context, 0).size ==
          kBinaryMaxTraceBeginRecordBytes);

    const std::string module(kBinaryMaxModuleNameBytes, 'm');
    CHECK(encoder.encode_module_definition(output.data(), output.size(), 1, module, 0).size ==
          kBinaryMaxModuleDefinitionRecordBytes);

    CachedInstruction decoded{};
    decoded.read_gpr_mask = (1ULL << kTraceGprCount) - 1U;
    decoded.write_gpr_mask = (1ULL << kTraceGprCount) - 1U;
    std::memset(decoded.mnemonic, 'm', sizeof(decoded.mnemonic));
    std::memset(decoded.operands, 'o', sizeof(decoded.operands));
    std::memset(decoded.disassembly, 'd', sizeof(decoded.disassembly));
    std::memset(decoded.read_register_names, 'r', sizeof(decoded.read_register_names));
    std::memset(decoded.write_register_names, 'w', sizeof(decoded.write_register_names));
    decoded.memory_operand_count = CachedInstruction::kMaxMemoryOperands;
    CHECK(encoder.encode_instruction_definition(output.data(), output.size(), 1, decoded).size ==
          kBinaryMaxInstructionDefinitionRecordBytes);

    InstructionRecord instruction{};
    instruction.decoded = &decoded;
    CHECK(encoder.encode_instruction(output.data(), output.size(), 1, instruction).size ==
          kBinaryMaxInstructionRecordBytes);

    MemoryRecord memory{};
    memory.before.state = MemoryBytesState::Available;
    memory.before.size = kMaxCapturedMemoryBytes;
    memory.after.state = MemoryBytesState::Available;
    memory.after.size = kMaxCapturedMemoryBytes;
    CHECK(encoder.encode_memory(output.data(), output.size(), 1, 0, memory).size ==
          kBinaryMaxMemoryRecordBytes);

    const std::string event_name(kBinaryMaxEventNameBytes, 'n');
    const std::string event_detail(kBinaryMaxEventDetailBytes, 'd');
    CHECK(encoder.encode_event(output.data(), output.size(), BinaryRecordType::Error,
                               event_name, event_detail).size == kBinaryMaxEventRecordBytes);
    CHECK(encoder.encode_end(output.data(), output.size(), true, 0, 0, {}).size ==
          kBinaryTraceEndRecordBytes);
}

} // namespace

int main() {
    stream_header_is_exact_and_tagged();
    trace_begin_has_exact_golden_bytes();
    module_definition_has_exact_golden_bytes();
    instruction_definition_has_exact_golden_bytes();
    instruction_definition_preserves_pc_relative_kinds_and_displacement();
    instruction_definition_preserves_static_registers_and_memory_operands();
    instruction_has_exact_golden_bytes_and_dense_values();
    memory_has_exact_golden_bytes_and_all_capture_states();
    semantic_events_have_exact_golden_bytes();
    trace_end_has_exact_golden_bytes();
    every_encoding_is_atomic_when_capacity_is_one_byte_short();
    rejects_invalid_or_oversized_inputs_without_writing();
    declared_record_maxima_are_exact_and_encodable();
}
