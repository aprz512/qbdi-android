#include "core/instruction_cache.h"
#include "core/safe_memory.h"
#include "core/trace_config.h"
#include "events/trace_encoder.h"

#include <array>
#include <cassert>
#include <cstring>
#include <string>
#include <string_view>

namespace {

RegisterSnapshot snapshot(std::initializer_list<std::pair<size_t, uint64_t>> values) {
    RegisterSnapshot result{};
    for (const auto &[index, value]: values) result.values[index] = value;
    return result;
}

void computes_arm64_effective_addresses_without_signed_overflow() {
    MemoryOperand operand{};
    operand.base_reg = 1;
    operand.index_reg = 2;
    operand.extend = MemoryIndexExtend::Lsl;
    operand.shift = 3;
    operand.displacement = 0x20;
    assert(operand.effective_address(snapshot({{1, 0x1000}, {2, 4}})) == 0x1040);

    operand.extend = MemoryIndexExtend::Uxtw;
    operand.shift = 2;
    assert(operand.effective_address(snapshot({{1, 0x1000}, {2, 0xfeed00000002ULL}})) ==
           0x1028);

    operand.extend = MemoryIndexExtend::Sxtw;
    assert(operand.effective_address(snapshot({{1, 0x1000}, {2, 0xffffffffULL}})) ==
           0x101c);

    operand.extend = MemoryIndexExtend::Sxtx;
    operand.shift = 1;
    operand.displacement = -0x10;
    assert(operand.effective_address(snapshot({{1, 8}, {2, UINT64_MAX}})) ==
           UINT64_MAX - 9U);

    operand.base_reg = MemoryOperand::kNoRegister;
    operand.index_reg = MemoryOperand::kNoRegister;
    operand.displacement = -1;
    assert(operand.effective_address(snapshot({})) == UINT64_MAX);

    operand.base_reg = 31;
    operand.displacement = 0;
    assert(operand.effective_address(snapshot({{31, 0x7000}})) == 0x7000);
}

void distinguishes_offset_preindex_and_postindex_addresses() {
    MemoryOperand operand{};
    operand.base_reg = 5;
    operand.displacement = -16;
    operand.writeback = true;

    operand.address_mode = MemoryAddressMode::PreIndex;
    assert(operand.effective_address(snapshot({{5, 0x1000}})) == 0xff0);
    assert(operand.writeback_address(snapshot({{5, 0x1000}})) == 0xff0);

    operand.address_mode = MemoryAddressMode::PostIndex;
    assert(operand.effective_address(snapshot({{5, 0x1000}})) == 0x1000);
    assert(operand.writeback_address(snapshot({{5, 0x1000}})) == 0xff0);

    operand.shift = 64;
    operand.index_reg = 6;
    uintptr_t address = 0;
    assert(!operand.try_effective_address(snapshot({{5, 1}, {6, 1}}), &address));
}

void bounds_cached_formulas_and_marks_the_slow_path() {
    CachedInstruction instruction{};
    MemoryOperand operand{};
    operand.base_reg = 1;
    for (size_t index = 0; index < CachedInstruction::kMaxMemoryOperands; ++index) {
        operand.displacement = static_cast<int64_t>(index * 8U);
        assert(cache_memory_operand(&instruction, operand));
    }
    assert(instruction.memory_operand_count == CachedInstruction::kMaxMemoryOperands);
    operand.displacement = 32;
    assert(!cache_memory_operand(&instruction, operand));
    assert(instruction.memory_operand_count == CachedInstruction::kMaxMemoryOperands);
    assert(instruction.requires_slow_memory_path);
}

void decodes_common_arm64_addressing_forms() {
    CachedInstruction shifted{};
    assert(decode_arm64_memory_operands(&shifted, 0xf8627820U, true, false, 8, 0));
    assert(shifted.memory_operand_count == 1);
    assert(shifted.memory_operands[0].base_reg == 1);
    assert(shifted.memory_operands[0].index_reg == 2);
    assert(shifted.memory_operands[0].extend == MemoryIndexExtend::Lsl);
    assert(shifted.memory_operands[0].shift == 3);
    assert(shifted.memory_operands[0].effective_address(
                   snapshot({{1, 0x1000}, {2, 4}})) == 0x1020);

    CachedInstruction pre{};
    assert(decode_arm64_memory_operands(&pre, 0xf8408c20U, true, false, 8, 0));
    assert(pre.memory_operands[0].address_mode == MemoryAddressMode::PreIndex);
    assert(pre.memory_operands[0].writeback);
    assert(pre.memory_operands[0].effective_address(snapshot({{1, 0x1000}})) == 0x1008);

    CachedInstruction post{};
    assert(decode_arm64_memory_operands(&post, 0xf8408420U, true, false, 8, 0));
    assert(post.memory_operands[0].address_mode == MemoryAddressMode::PostIndex);
    assert(post.memory_operands[0].effective_address(snapshot({{1, 0x1000}})) == 0x1000);
    assert(post.memory_operands[0].writeback_address(snapshot({{1, 0x1000}})) == 0x1008);

    CachedInstruction unsupported{};
    assert(!decode_arm64_memory_operands(&unsupported, 0U, true, false, 8, 0));
    assert(unsupported.requires_slow_memory_path);

    CachedInstruction simd_post_index{};
    assert(decode_arm64_memory_operands(&simd_post_index, 0x4c9f7020U,
                                        false, true, 0, 16));
    assert(!simd_post_index.requires_slow_memory_path);
    assert(simd_post_index.memory_operands[0].base_reg == 1);
    assert(simd_post_index.memory_operands[0].address_mode ==
           MemoryAddressMode::PostIndex);
    assert(simd_post_index.memory_operands[0].writeback);
    assert(simd_post_index.memory_operands[0].effective_address(
                   snapshot({{1, 0x5000}})) == 0x5000);
    assert(simd_post_index.memory_operands[0].writeback_address(
                   snapshot({{1, 0x5000}})) == 0x5010);

    CachedInstruction simd_register_post{};
    assert(decode_arm64_memory_operands(&simd_register_post, 0x4c827020U,
                                        false, true, 0, 16));
    assert(simd_register_post.memory_operands[0].index_reg == 2);
    assert(simd_register_post.memory_operands[0].effective_address(
                   snapshot({{1, 0x5000}, {2, 0x30}})) == 0x5000);
    assert(simd_register_post.memory_operands[0].writeback_address(
                   snapshot({{1, 0x5000}, {2, 0x30}})) == 0x5030);

    CachedInstruction literal{};
    assert(decode_arm64_memory_operands(&literal, 0x58000040U, true, false, 8, 0));
    assert(literal.memory_operands[0].base_reg == 33);
    assert(literal.memory_operands[0].effective_address(snapshot({{33, 0x4000}})) ==
           0x4008);
}

void enforces_profile_and_hexdump_caps_with_safe_reads() {
    TraceOptions fast{};
    assert(!fast.memory_enabled());
    assert(!fast.hexdump_enabled());

    TraceOptions balanced{};
    balanced.profile = TraceProfile::Balanced;
    assert(balanced.memory_enabled());
    assert(!balanced.hexdump_enabled());

    TraceOptions full{};
    full.profile = TraceProfile::Full;
    full.hexdump_limit = 16;
    assert(full.memory_enabled());
    assert(full.hexdump_enabled());
    assert(bounded_memory_capture_size(80, 0) == 0);
    assert(bounded_memory_capture_size(80, 16) == 16);
    assert(bounded_memory_capture_size(80, 64) == 64);
    assert(bounded_memory_capture_size(8, 64) == 8);

    std::array<uint8_t, 80> source{};
    for (size_t index = 0; index < source.size(); ++index) {
        source[index] = static_cast<uint8_t>(index);
    }
    MemoryBytes sixteen{};
    capture_memory_bytes(reinterpret_cast<uintptr_t>(source.data()), source.size(), 16,
                         safe_read_memory, &sixteen);
    assert(sixteen.state == MemoryBytesState::Available);
    assert(sixteen.size == 16);
    assert(sixteen.data[0] == 0 && sixteen.data[15] == 15);

    MemoryBytes sixty_four{};
    capture_memory_bytes(reinterpret_cast<uintptr_t>(source.data()), source.size(), 64,
                         safe_read_memory, &sixty_four);
    assert(sixty_four.state == MemoryBytesState::Available);
    assert(sixty_four.size == 64);
    assert(sixty_four.data[63] == 63);

    MemoryBytes before_write{};
    capture_memory_bytes(reinterpret_cast<uintptr_t>(source.data()), 4, 16,
                         safe_read_memory, &before_write);
    source[0] = 0xf0;
    source[1] = 0xf1;
    MemoryBytes after_write{};
    capture_memory_bytes(reinterpret_cast<uintptr_t>(source.data()), 4, 16,
                         safe_read_memory, &after_write);
    assert(before_write.state == MemoryBytesState::Available);
    assert(after_write.state == MemoryBytesState::Available);
    assert(before_write.data[0] == 0 && before_write.data[1] == 1);
    assert(after_write.data[0] == 0xf0 && after_write.data[1] == 0xf1);

    MemoryBytes unreadable{};
    capture_memory_bytes(1, 8, 16, safe_read_memory, &unreadable);
    assert(unreadable.state == MemoryBytesState::Unavailable);
    assert(unreadable.size == 0);
}

MemoryRecord memory(uintptr_t address, uint8_t type) {
    MemoryRecord record{};
    record.access_type = type;
    record.address = address;
    record.size = 1;
    record.value = address & 0xffU;
    return record;
}

void encodes_byte_states_flags_and_overflow_in_exact_order() {
    InstructionRecord record{};
    record.sequence = 3;
    record.pc = 0x1010;
    record.module_base = 0x1000;
    record.memory_count = kMaxMemoryRecords;
    for (size_t index = 0; index < kMaxMemoryRecords; ++index) {
        record.memory[index] = memory(0x2000 + index, 1);
    }
    record.memory[0].flags = 5;
    record.memory[0].before.state = MemoryBytesState::Available;
    record.memory[0].before.size = 2;
    record.memory[0].before.data[0] = 0xab;
    record.memory[0].before.data[1] = 0xcd;
    record.memory[0].after.state = MemoryBytesState::Unavailable;
    record.memory[0].access_type = 3;

    TraceEncoder encoder;
    std::array<char, kMaxInstructionLineBytes> output{};
    EncodeResult encoded = encoder.encode_instruction(output.data(), output.size(), "libx.so", record);
    assert(encoded.ok);
    std::string text(output.data(), encoded.size);
    assert(text.starts_with(
            "3 libx.so+0x10 <undecoded> | MEM:rw addr=0x2000 size=1 value=0x0 flags=0x5 pre=abcd post=<unavailable>"));

    for (size_t index = kMaxMemoryRecords; index < kMaxMemoryRecords + 3U; ++index) {
        const MemoryRecord continuation = memory(0x2000 + index, 2);
        encoded = encoder.encode_memory(output.data(), output.size(), "libx.so", 0x10,
                                        continuation);
        assert(encoded.ok);
        text.append(output.data(), encoded.size);
    }
    constexpr std::array<std::string_view, kMaxMemoryRecords + 3U> addresses{
            "2000", "2001", "2002", "2003", "2004", "2005",
            "2006", "2007", "2008", "2009", "200a"};
    size_t cursor = 0;
    for (size_t index = 0; index < kMaxMemoryRecords + 3U; ++index) {
        const std::string needle = "addr=0x" + std::string(addresses[index]);
        const size_t found = text.find(needle, cursor);
        assert(found != std::string::npos);
        cursor = found + needle.size();
    }
    assert(text.find("MEM libx.so+0x10 type=w addr=0x2008 size=1 value=0x8 flags=0x0\n") !=
           std::string::npos);
}

void truncates_known_memory_values_to_access_width() {
    assert(truncate_memory_value(0xfeedface12345678ULL, 1, 0) == 0x78);
    assert(truncate_memory_value(0xfeedface12345678ULL, 4, 0) == 0x12345678);
    assert(truncate_memory_value(0xfeedface12345678ULL, 8, 0) ==
           0xfeedface12345678ULL);
    assert(truncate_memory_value(0xfeedface12345678ULL, 0, 1) ==
           0xfeedface12345678ULL);
    assert(truncate_memory_value(0xfeedface12345678ULL, 1, 2) ==
           0xfeedface12345678ULL);
}

} // namespace

int main() {
    computes_arm64_effective_addresses_without_signed_overflow();
    distinguishes_offset_preindex_and_postindex_addresses();
    bounds_cached_formulas_and_marks_the_slow_path();
    decodes_common_arm64_addressing_forms();
    enforces_profile_and_hexdump_caps_with_safe_reads();
    encodes_byte_states_flags_and_overflow_in_exact_order();
    truncates_known_memory_values_to_access_width();
}
