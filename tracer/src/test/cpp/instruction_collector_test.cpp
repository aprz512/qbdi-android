#include "core/pending_instruction.h"

#include <array>
#include <cassert>
#include <cstring>
#include <vector>

namespace {

struct RecordingSink final : PendingInstructionSink {
    bool emit(const InstructionRecord &record) override {
        event_addresses.push_back(record.pc);
        records.push_back(record);
        return true;
    }

    bool emit_memory_continuation(uintptr_t, const MemoryRecord &record) override {
        event_addresses.push_back(record.address);
        continuations.push_back(record);
        return true;
    }

    std::vector<InstructionRecord> records;
    std::vector<MemoryRecord> continuations;
    std::vector<uintptr_t> event_addresses;
};

RegisterSnapshot snapshot(std::initializer_list<std::pair<size_t, uint64_t>> values) {
    RegisterSnapshot result{};
    for (const auto &[index, value]: values) result.values[index] = value;
    return result;
}

InstructionView view(uintptr_t address, CachedInstruction *decoded) {
    return InstructionView{address, decoded};
}

void delays_the_first_instruction_and_completes_it_at_the_next_pre() {
    CachedInstruction add{};
    std::strcpy(add.mnemonic, "add");
    add.read_gpr_mask = (1ULL << 1U) | (1ULL << 2U);
    add.write_gpr_mask = 1ULL;
    std::strcpy(add.write_register_names[0], "X0");
    std::strcpy(add.read_register_names[1], "X1");
    std::strcpy(add.read_register_names[2], "X2");

    CachedInstruction ret{};
    std::strcpy(ret.mnemonic, "ret");
    ret.read_gpr_mask = 1ULL << 30U;
    ret.flags = InstructionFlags::Branch | InstructionFlags::Return;
    std::strcpy(ret.read_register_names[30], "LR");

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0x1000);
    assert(collector.begin(view(0x1010, &add), snapshot({{1, 2}, {2, 3}, {5, 99}})));
    assert(sink.records.empty());

    assert(collector.begin(view(0x1014, &ret), snapshot({{0, 5}, {1, 88}})));
    assert(sink.records.size() == 1);
    assert(sink.records[0].sequence == 1);
    assert(sink.records[0].pc == 0x1010);
    assert(sink.records[0].module_base == 0x1000);
    assert(sink.records[0].reads.count == 2);
    assert(sink.records[0].reads.values[0] == 2);
    assert(sink.records[0].reads.values[1] == 3);
    assert(sink.records[0].writes.count == 1);
    assert(sink.records[0].writes.values[0] == 5);

    assert(collector.finish_last(snapshot({{0, 9}, {30, 0xfeed}})));
    assert(sink.records.size() == 2);
    assert(sink.records[1].sequence == 2);
    assert(sink.records[1].reads.count == 1);
    assert(sink.records[1].reads.values[0] == 0);
    assert(sink.records[1].writes.count == 0);
    assert(!collector.finish_last(snapshot({{0, 10}})));
    assert(sink.records.size() == 2);
}

void assigns_exact_sequence_numbers_across_a_branch() {
    CachedInstruction first{};
    first.write_gpr_mask = 1ULL << 0U;
    CachedInstruction branch{};
    branch.read_gpr_mask = 1ULL << 3U;
    branch.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;
    branch.pc_relative_displacement = 16;
    CachedInstruction last{};
    last.write_gpr_mask = 1ULL << 4U;

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0x2000);
    assert(collector.begin(view(0x2000, &first), snapshot({})));
    assert(collector.begin(view(0x2004, &branch), snapshot({{0, 1}, {3, 7}})));
    assert(collector.begin(view(0x2014, &last), snapshot({{4, 8}})));
    assert(collector.finish_last(snapshot({{4, 9}})));

    assert(sink.records.size() == 3);
    assert(sink.records[0].sequence == 1);
    assert(sink.records[1].sequence == 2);
    assert(sink.records[2].sequence == 3);
    assert(sink.records[1].decoded->pc_relative_displacement == 16);
    assert(sink.records[1].pc + sink.records[1].decoded->pc_relative_displacement == 0x2014);
}

void handles_zero_instruction_sequences() {
    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0);
    assert(!collector.finish_last(snapshot({{0, 1}})));
    assert(sink.records.empty());
}

void separates_previous_completion_from_current_rule_mutation() {
    CachedInstruction previous{};
    previous.write_gpr_mask = 1ULL << 0U;
    CachedInstruction current{};
    current.read_gpr_mask = 1ULL << 0U;

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0);
    assert(collector.begin(view(0x3000, &previous), snapshot({})));
    assert(collector.complete_pending(snapshot({{0, 7}})));
    assert(collector.begin(view(0x3004, &current), snapshot({{0, 9}})));
    assert(collector.finish_last(snapshot({})));

    assert(sink.records[0].writes.values[0] == 7);
    assert(sink.records[1].reads.values[0] == 9);
}

void truncates_w_register_aliases_to_their_architectural_width() {
    CachedInstruction instruction{};
    instruction.read_gpr_mask = 1ULL << 0U;
    instruction.write_gpr_mask = 1ULL << 1U;
    instruction.read_gpr_widths[0] = 4;
    instruction.write_gpr_widths[1] = 4;
    std::strcpy(instruction.read_register_names[0], "W0");
    std::strcpy(instruction.write_register_names[1], "W1");

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0);
    assert(collector.begin(view(0x4000, &instruction),
                           snapshot({{0, 0xaaaaaaaa12345678ULL}})));
    assert(collector.finish_last(snapshot({{1, 0xbbbbbbbb87654321ULL}})));
    assert(sink.records[0].reads.count == 1);
    assert(sink.records[0].reads.values[0] == 0x12345678);
    assert(sink.records[0].writes.count == 1);
    assert(sink.records[0].writes.values[0] == 0x87654321);
}

void stores_sparse_registers_densely_in_set_bit_order() {
    CachedInstruction instruction{};
    instruction.read_gpr_mask = (1ULL << 0U) | (1ULL << 8U) | (1ULL << 33U);
    instruction.write_gpr_mask = (1ULL << 1U) | (1ULL << 30U);

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0);
    assert(collector.begin(view(0x1000, &instruction),
                           snapshot({{0, 10}, {8, 20}, {33, 30}})));
    assert(collector.complete_pending(snapshot({{1, 40}, {30, 50}})));
    assert(sink.records[0].reads.count == 3);
    assert(sink.records[0].reads.values[0] == 10);
    assert(sink.records[0].reads.values[1] == 20);
    assert(sink.records[0].reads.values[2] == 30);
    assert(sink.records[0].writes.count == 2);
    assert(sink.records[0].writes.values[0] == 40);
    assert(sink.records[0].writes.values[1] == 50);
}

void rejects_register_masks_outside_the_trace_register_file() {
    CachedInstruction invalid_read{};
    invalid_read.read_gpr_mask = 1ULL << kTraceGprCount;
    CachedInstruction invalid_write{};
    invalid_write.write_gpr_mask = 1ULL << 63U;

    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0);
    assert(!collector.begin(view(0x1000, &invalid_read), snapshot({})));
    assert(!collector.has_pending());
    assert(!collector.begin(view(0x1004, &invalid_write), snapshot({})));
    assert(!collector.has_pending());
    assert(sink.records.empty());
}

void attaches_only_the_fixed_memory_prefix_without_reordering() {
    CachedInstruction instruction{};
    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0x1000);
    assert(collector.begin(view(0x1010, &instruction), snapshot({})));

    for (size_t index = 0; index < kMaxMemoryRecords; ++index) {
        MemoryRecord memory{};
        memory.address = 0x2000 + index;
        memory.value = index;
        assert(collector.append_memory(memory));
    }
    MemoryRecord overflow{};
    overflow.address = 0x2008;
    assert(!collector.append_memory(overflow));
    assert(collector.complete_pending(snapshot({})));
    assert(sink.records.size() == 1);
    assert(sink.records[0].memory_count == kMaxMemoryRecords);
    for (size_t index = 0; index < kMaxMemoryRecords; ++index) {
        assert(sink.records[0].memory[index].address == 0x2000 + index);
        assert(sink.records[0].memory[index].value == index);
    }
}

void emits_more_than_eight_accesses_as_lossless_ordered_continuations() {
    CachedInstruction instruction{};
    RecordingSink sink;
    PendingInstructionCollector collector(&sink, 0x1000);
    assert(collector.begin(view(0x1010, &instruction), snapshot({})));

    for (size_t index = 0; index < 11; ++index) {
        MemoryRecord memory{};
        memory.address = 0x3000 + index;
        memory.value = index;
        assert(collector.append_or_emit_memory(memory, snapshot({})));
    }
    assert(collector.complete_memory(snapshot({})));
    assert(sink.records.size() == 1);
    assert(sink.records[0].memory_count == kMaxMemoryRecords);
    assert(sink.continuations.size() == 3);
    assert(sink.event_addresses[0] == 0x1010);
    for (size_t index = 0; index < kMaxMemoryRecords; ++index) {
        assert(sink.records[0].memory[index].address == 0x3000 + index);
    }
    for (size_t index = 0; index < sink.continuations.size(); ++index) {
        assert(sink.continuations[index].address == 0x3008 + index);
        assert(sink.event_addresses[index + 1U] == 0x3008 + index);
    }
}

} // namespace

int main() {
    delays_the_first_instruction_and_completes_it_at_the_next_pre();
    assigns_exact_sequence_numbers_across_a_branch();
    handles_zero_instruction_sequences();
    separates_previous_completion_from_current_rule_mutation();
    truncates_w_register_aliases_to_their_architectural_width();
    stores_sparse_registers_densely_in_set_bit_order();
    rejects_register_masks_outside_the_trace_register_file();
    attaches_only_the_fixed_memory_prefix_without_reordering();
    emits_more_than_eight_accesses_as_lossless_ordered_continuations();
}
