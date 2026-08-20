#include "core/arm64_memory_decoder.h"
#include "core/arm64_memory_operand.h"
#include "core/instruction_cache.h"
#include "core/memory_capture.h"
#include "core/memory_types.h"
#include "core/memory_trace_policy.h"
#include "core/pending_instruction.h"
#include "core/safe_memory.h"
#include "core/trace_config.h"
#include "events/binary_trace_encoder.h"

#include <array>
#include <cassert>
#include <cstring>
#include <string>
#include <string_view>

namespace {

std::array<uint8_t, 256> policy_memory{};

bool read_policy_memory(uintptr_t address, void *output, size_t size) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    if (address < base || address - base > policy_memory.size() ||
        size > policy_memory.size() - (address - base)) {
        return false;
    }
    std::memcpy(output, reinterpret_cast<const void *>(address), size);
    return true;
}

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

void decodes_write_only_pair_and_simd_lane_formulas_exactly() {
    struct FormulaCase {
        uint32_t opcode;
        uint32_t size;
        uintptr_t base;
        uintptr_t index;
        uintptr_t address;
        uintptr_t writeback;
    };
    constexpr std::array cases{
            FormulaCase{0xa8010440U, 16, 0x1000, 0, 0x1010, 0x1000},
            FormulaCase{0xac3f0440U, 32, 0x1800, 0, 0x17e0, 0x1800},
            FormulaCase{0x0d000c20U, 1, 0x2000, 0, 0x2000, 0x2000},
            FormulaCase{0x0d9f0c20U, 1, 0x3000, 0, 0x3000, 0x3001},
            FormulaCase{0x0d820c20U, 1, 0x4000, 0x20, 0x4000, 0x4020},
            FormulaCase{0x0dbf0c20U, 2, 0x5000, 0, 0x5000, 0x5002},
            FormulaCase{0x0d9f2c20U, 3, 0x6000, 0, 0x6000, 0x6003},
            FormulaCase{0x0dbf2c20U, 4, 0x7000, 0, 0x7000, 0x7004},
    };
    for (const FormulaCase &test: cases) {
        CachedInstruction decoded{};
        assert(decode_arm64_memory_operands(&decoded, test.opcode, false, true,
                                            0, test.size));
        assert(!decoded.requires_slow_memory_path);
        assert(decoded.memory_operand_count == 1);
        const MemoryOperand &operand = decoded.memory_operands[0];
        assert(operand.kind == MemoryAccessKind::Write);
        assert(operand.access_size == test.size);
        RegisterSnapshot registers{};
        registers.values[operand.base_reg] = test.base;
        if (operand.index_reg != MemoryOperand::kNoRegister) {
            registers.values[operand.index_reg] = test.index;
        }
        assert(operand.effective_address(registers) == test.address);
        assert(operand.writeback_address(registers) == test.writeback);
    }
}

void captures_and_matches_every_compound_qbdi_access() {
    for (size_t index = 0; index < policy_memory.size(); ++index) {
        policy_memory[index] = static_cast<uint8_t>(index);
    }
    CachedInstruction decoded{};
    assert(decode_arm64_memory_operands(&decoded, 0x4c002020U, false, true,
                                        0, 64));
    MemoryTracePolicy policy;
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                     snapshot({{1, base}}), 16,
                                     read_policy_memory));
    assert(policy.pre_capture_count() == 8);
    for (size_t index = 0; index < 8; ++index) {
        NormalizedMemoryAccess access{};
        access.inst_address = 0x1000;
        access.address = base + index * 8;
        access.size = 8;
        access.kind = MemoryAccessKind::Write;
        const MemoryRecord record = policy.record(access, TraceProfile::Full, 16,
                                                  read_policy_memory);
        assert(record.before.state == MemoryBytesState::Available);
        assert(record.before.size == 8);
        assert(record.before.data[0] == static_cast<uint8_t>(index * 8));
        assert(record.before.data[7] == static_cast<uint8_t>(index * 8 + 7));
    }

    CachedInstruction post_index{};
    assert(decode_arm64_memory_operands(&post_index, 0x4c9f2020U, false,
                                        true, 0, 64));
    assert(post_index.memory_operands[0].effective_address(
                   snapshot({{1, base}})) == base);
    assert(post_index.memory_operands[0].writeback_address(
                   snapshot({{1, base}})) == base + 64);
}

void matches_table_driven_addressing_classes_through_the_policy() {
    struct AccessCase {
        uint32_t opcode;
        bool loads;
        bool stores;
        uint32_t load_size;
        uint32_t store_size;
        uint64_t base;
        uint64_t index;
        uintptr_t expected;
        MemoryAccessKind kind;
    };
    constexpr std::array cases{
            AccessCase{0xf8625820U, true, false, 8, 0, 0x1000, 3, 0x1018,
                       MemoryAccessKind::Read},
            AccessCase{0xf862d820U, true, false, 8, 0, 0x1000, 0xffffffffULL,
                       0xff8, MemoryAccessKind::Read},
            AccessCase{0xf862f820U, true, false, 8, 0, 0x1000, UINT64_MAX,
                       0xff8, MemoryAccessKind::Read},
            AccessCase{0xf9400c20U, true, false, 8, 0, 0x2000, 0, 0x2018,
                       MemoryAccessKind::Read},
            AccessCase{0xc85f7c20U, true, false, 8, 0, 0x3000, 0, 0x3000,
                       MemoryAccessKind::Read},
            AccessCase{0xf8200041U, true, true, 8, 8, 0x4000, 0, 0x4000,
                       MemoryAccessKind::ReadWrite},
            AccessCase{0x0d000c20U, false, true, 0, 1, 0x5000, 0, 0x5000,
                       MemoryAccessKind::Write},
    };
    for (const AccessCase &test: cases) {
        CachedInstruction decoded{};
        assert(decode_arm64_memory_operands(&decoded, test.opcode, test.loads,
                                            test.stores, test.load_size,
                                            test.store_size));
        const MemoryOperand &operand = decoded.memory_operands[0];
        RegisterSnapshot registers{};
        registers.values[operand.base_reg] = test.base;
        if (operand.index_reg != MemoryOperand::kNoRegister) {
            registers.values[operand.index_reg] = test.index;
        }
        assert(operand.effective_address(registers) == test.expected);

        MemoryTracePolicy policy;
        assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                         registers, 16, read_policy_memory));
        NormalizedMemoryAccess actual{};
        actual.address = test.expected;
        actual.size = std::min<uint32_t>(
                std::max(test.load_size, test.store_size), 8);
        actual.kind = test.kind;
        const MemoryRecord record = policy.record(actual, TraceProfile::Full,
                                                  16, read_policy_memory);
        // Synthetic addresses are intentionally unreadable: the policy must
        // still match the exact formula and report the read failure honestly.
        assert(record.before.state == MemoryBytesState::Unavailable);
        assert(record.kind == test.kind);
    }

    CachedInstruction pair{};
    assert(decode_arm64_memory_operands(&pair, 0xa8010440U, false, true, 0, 16));
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    MemoryTracePolicy policy;
    assert(policy.capture_after_rule(TraceProfile::Full, true, pair,
                                     snapshot({{2, base}}), 16,
                                     read_policy_memory));
    for (size_t index = 0; index < 2; ++index) {
        NormalizedMemoryAccess actual{};
        actual.address = base + 16 + index * 8;
        actual.size = 8;
        actual.kind = MemoryAccessKind::Write;
        assert(policy.record(actual, TraceProfile::Full, 16,
                             read_policy_memory).before.state ==
               MemoryBytesState::Available);
    }


    CachedInstruction lane{};
    assert(decode_arm64_memory_operands(&lane, 0x0d9f0c20U, false, true, 0, 1));
    assert(policy.capture_after_rule(TraceProfile::Full, true, lane,
                                     snapshot({{1, base}}), 16,
                                     read_policy_memory));
    NormalizedMemoryAccess lane_access{};
    lane_access.address = base;
    lane_access.size = 1;
    lane_access.kind = MemoryAccessKind::Write;
    assert(policy.record(lane_access, TraceProfile::Full, 16,
                         read_policy_memory).before.state ==
           MemoryBytesState::Available);
}

struct PipelineSink final : PendingInstructionSink {
    bool emit(const InstructionRecord &value) override {
        instruction = value;
        emitted_instruction = true;
        return true;
    }
    bool emit_memory_continuation(uintptr_t, const MemoryRecord &value) override {
        if (continuation_count >= continuations.size()) return false;
        continuations[continuation_count++] = value;
        return true;
    }
    InstructionRecord instruction{};
    std::array<MemoryRecord, 3> continuations{};
    size_t continuation_count = 0;
    bool emitted_instruction = false;
};

void preserves_policy_records_through_more_than_eight_accesses() {
    CachedInstruction decoded{};
    decoded.memory_operand_count = 2;
    for (size_t index = 0; index < 2; ++index) {
        decoded.memory_operands[index].base_reg = 1;
        decoded.memory_operands[index].kind = MemoryAccessKind::Read;
        decoded.memory_operands[index].access_size = index == 0 ? 64 : 24;
        decoded.memory_operands[index].displacement = static_cast<int64_t>(index * 64);
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    MemoryTracePolicy policy;
    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                     snapshot({{1, base}}), 16,
                                     read_policy_memory));
    PipelineSink sink;
    PendingInstructionCollector pending(&sink);
    assert(pending.begin({0x9000, &decoded}, {}));
    size_t accepted = 0;
    for (size_t index = 0; index < 12; ++index) {
        NormalizedMemoryAccess actual{};
        actual.inst_address = index == 5 ? 0x9004 : 0x9000;
        actual.address = base + accepted * 8;
        actual.size = 8;
        actual.kind = MemoryAccessKind::Read;
        MemoryRecord record{};
        if (!policy.record_if_matches(0x9000, actual, TraceProfile::Full, 16,
                                      read_policy_memory, &record)) {
            assert(index == 5);
            continue;
        }
        assert(record.before.state == MemoryBytesState::Available);
        assert(pending.append_or_emit_memory(record, {}));
        ++accepted;
    }
    assert(accepted == 11);
    assert(pending.complete_memory({}));
    assert(sink.emitted_instruction);
    assert(sink.instruction.memory_count == 8);
    assert(sink.continuation_count == 3);
    for (size_t index = 0; index < 8; ++index) {
        assert(sink.instruction.memory[index].address == base + index * 8);
    }
    for (size_t index = 0; index < 3; ++index) {
        assert(sink.continuations[index].address == base + (index + 8) * 8);
    }
}

void applies_post_rule_state_and_rejects_stopped_pre_work() {
    CachedInstruction decoded{};
    assert(decode_arm64_memory_operands(&decoded, 0xf9000020U, false, true, 0, 8));
    MemoryTracePolicy policy;
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    policy_memory[8] = 0x5a;

    RegisterSnapshot mutated = snapshot({{1, base + 8}});
    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded, mutated,
                                     16, read_policy_memory));
    policy_memory[8] = 0xa5;
    NormalizedMemoryAccess access{};
    access.address = base + 8;
    access.size = 8;
    access.kind = MemoryAccessKind::Write;
    const MemoryRecord changed = policy.record(access, TraceProfile::Full, 16,
                                               read_policy_memory);
    assert(changed.before.data[0] == 0x5a);
    assert(changed.after.data[0] == 0xa5);

    assert(!policy.capture_after_rule(TraceProfile::Full, false, decoded, mutated,
                                      16, read_policy_memory));
    assert(policy.pre_capture_count() == 0);
}

void applies_hexdump_limits_per_normalized_access() {
    CachedInstruction decoded{};
    assert(decode_arm64_memory_operands(&decoded, 0x4c002020U, false, true,
                                        0, 64));
    const uintptr_t base = reinterpret_cast<uintptr_t>(policy_memory.data());
    NormalizedMemoryAccess access{};
    access.address = base + 24;
    access.size = 8;
    access.kind = MemoryAccessKind::Write;
    MemoryTracePolicy policy;

    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                     snapshot({{1, base}}), 0,
                                     read_policy_memory));
    assert(policy.record(access, TraceProfile::Full, 0, read_policy_memory)
                   .before.state == MemoryBytesState::NotCaptured);

    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                     snapshot({{1, base}}), 64,
                                     read_policy_memory));
    const MemoryRecord captured = policy.record(access, TraceProfile::Full, 64,
                                                read_policy_memory);
    assert(captured.before.state == MemoryBytesState::Available);
    assert(captured.before.size == 8);
    assert(captured.after.state == MemoryBytesState::Available);
    assert(captured.after.size == 8);
}

void reports_fixed_policy_overflow_honestly() {
    MemoryTracePolicy policy;
    CachedInstruction decoded{};
    decoded.memory_operand_count = CachedInstruction::kMaxMemoryOperands;
    for (size_t index = 0; index < decoded.memory_operand_count; ++index) {
        decoded.memory_operands[index].base_reg = 1;
        decoded.memory_operands[index].kind = MemoryAccessKind::ReadWrite;
        decoded.memory_operands[index].access_size = 64;
        decoded.memory_operands[index].displacement = static_cast<int64_t>(index * 64);
    }
    assert(policy.capture_after_rule(TraceProfile::Full, true, decoded,
                                     snapshot({{1, reinterpret_cast<uintptr_t>(
                                                         policy_memory.data())}}),
                                     16, read_policy_memory));
    assert(policy.pre_capture_count() == MemoryTracePolicy::kMaxPreMemoryCaptures);
    assert(!policy.overflowed());
    NormalizedMemoryAccess extra_pre{};
    extra_pre.address = reinterpret_cast<uintptr_t>(policy_memory.data()) + 256;
    extra_pre.size = 8;
    extra_pre.kind = MemoryAccessKind::Read;
    assert(!policy.add_pre_access(extra_pre, 16, read_policy_memory));
    assert(policy.overflowed());
    NormalizedMemoryAccess overflow{};
    overflow.address = reinterpret_cast<uintptr_t>(policy_memory.data()) + 256;
    overflow.size = 8;
    overflow.kind = MemoryAccessKind::Write;
    assert(policy.record(overflow, TraceProfile::Full, 16, read_policy_memory)
                   .before.state == MemoryBytesState::Unavailable);

    CachedInstruction oversized{};
    oversized.memory_operand_count = 1;
    oversized.memory_operands[0].base_reg = 1;
    oversized.memory_operands[0].kind = MemoryAccessKind::Read;
    oversized.memory_operands[0].access_size = 72;
    assert(policy.capture_after_rule(TraceProfile::Full, true, oversized,
                                     snapshot({{1, reinterpret_cast<uintptr_t>(
                                                         policy_memory.data())}}),
                                     16, read_policy_memory));
    assert(policy.pre_capture_count() == MemoryTracePolicy::kMaxAccessesPerOperand);
    assert(policy.overflowed());
    overflow.address = reinterpret_cast<uintptr_t>(policy_memory.data()) + 64;
    overflow.kind = MemoryAccessKind::Read;
    assert(policy.record(overflow, TraceProfile::Full, 16, read_policy_memory)
                   .before.state == MemoryBytesState::Unavailable);

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

MemoryRecord memory(uintptr_t address, MemoryAccessKind kind) {
    MemoryRecord record{};
    record.kind = kind;
    record.metadata_available = true;
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
        record.memory[index] = memory(0x2000 + index, MemoryAccessKind::Read);
    }
    record.memory[0].flags = 5;
    record.memory[0].before.state = MemoryBytesState::Available;
    record.memory[0].before.size = 2;
    record.memory[0].before.data[0] = 0xab;
    record.memory[0].before.data[1] = 0xcd;
    record.memory[0].after.state = MemoryBytesState::Unavailable;
    record.memory[0].kind = MemoryAccessKind::ReadWrite;

    BinaryTraceEncoder encoder;
    std::array<uint8_t, kBinaryMaxMemoryRecordBytes> output{};
    for (size_t index = 0; index < kMaxMemoryRecords + 3U; ++index) {
        const MemoryRecord event = index < kMaxMemoryRecords
                                           ? record.memory[index]
                                           : memory(0x2000 + index,
                                                    MemoryAccessKind::Write);
        const BinaryEncodeResult encoded = encoder.encode_memory(
                output.data(), output.size(), 7, 0x10, event);
        assert(encoded.ok);
        assert(output[0] == static_cast<uint8_t>(BinaryRecordType::Memory));
        assert(output[8] == 7);
        assert(output[12] == 0x10);
        assert(output[20] == static_cast<uint8_t>(event.kind));
        uint64_t encoded_address = 0;
        for (size_t byte = 0; byte < sizeof(encoded_address); ++byte) {
            encoded_address |= static_cast<uint64_t>(output[24 + byte]) << (byte * 8U);
        }
        assert(encoded_address == 0x2000 + index);
        if (index == 0) {
            assert(output[21] == 1);
            assert(output[22] == 5);
            assert(output[44] == static_cast<uint8_t>(MemoryBytesState::Available));
            assert(output[45] == 2);
            assert(output[46] == 0xab);
            assert(output[47] == 0xcd);
            assert(output[48] == static_cast<uint8_t>(MemoryBytesState::Unavailable));
            assert(output[49] == 0);
        }
    }
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
    decodes_write_only_pair_and_simd_lane_formulas_exactly();
    captures_and_matches_every_compound_qbdi_access();
    matches_table_driven_addressing_classes_through_the_policy();
    preserves_policy_records_through_more_than_eight_accesses();
    applies_post_rule_state_and_rejects_stopped_pre_work();
    applies_hexdump_limits_per_normalized_access();
    reports_fixed_policy_overflow_honestly();
    enforces_profile_and_hexdump_caps_with_safe_reads();
    encodes_byte_states_flags_and_overflow_in_exact_order();
    truncates_known_memory_values_to_access_width();
}
