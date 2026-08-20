#include "core/instruction_cache.h"

#include <cassert>
#include <cstring>

namespace {

void bounds_metadata_by_opcode_instead_of_distinct_program_counters() {
    InstructionCache cache(8192);
    CachedInstruction instruction{};
    instruction.opcode = 0xd503201fU;

    const CachedInstruction *first = cache.insert(instruction);
    assert(first != nullptr);
    constexpr uintptr_t kBasePc = 0x7100000000ULL;
    for (uint32_t pc_index = 0; pc_index < 100000; ++pc_index) {
        const InstructionView view{kBasePc + static_cast<uintptr_t>(pc_index) * 4U,
                                   cache.find(instruction.opcode)};
        assert(view.decoded == first);
    }

    assert(cache.metadata_entry_count() == 1);
    assert(cache.metadata_chunk_count() == 1);
    assert(cache.metrics().misses == 1);
    assert(cache.metrics().hits == 100000);
}

void converts_qbdi_arm64_branch_units_to_byte_displacements() {
    int32_t displacement = 0;
    assert(arm64_branch_displacement(4, &displacement));
    assert(displacement == 16);
    assert(arm64_branch_displacement(-4, &displacement));
    assert(displacement == -16);
    assert(!arm64_branch_displacement((static_cast<int64_t>(INT32_MAX) / 4) + 1,
                                      &displacement));
    assert(!arm64_branch_displacement(1, nullptr));
}

void decodes_every_common_arm64_pc_relative_encoding_without_a_location() {
    struct Case {
        uint32_t opcode;
        PcRelativeKind kind;
        int64_t displacement;
    };
    const Case cases[] = {
            {0x14000004U, PcRelativeKind::CurrentPc, 16},       // b
            {0x17ffffffU, PcRelativeKind::CurrentPc, -4},       // b backwards
            {0x54000080U, PcRelativeKind::CurrentPc, 16},       // b.cond
            {0xb4000080U, PcRelativeKind::CurrentPc, 16},       // cbz
            {0x58000080U, PcRelativeKind::CurrentPc, 16},       // ldr literal
            {0x36000080U, PcRelativeKind::CurrentPc, 16},       // tbz
            {0x70000900U, PcRelativeKind::CurrentPc, 0x123},    // adr
            {0xb0000000U, PcRelativeKind::CurrentPage, 0x1000}, // adrp
    };
    for (const Case &test : cases) {
        PcRelativeKind kind = PcRelativeKind::None;
        int64_t displacement = 0;
        assert(decode_arm64_pc_relative(test.opcode, &kind, &displacement));
        assert(kind == test.kind);
        assert(displacement == test.displacement);
    }

    CachedInstruction adrp{};
    adrp.pc_relative_kind = PcRelativeKind::CurrentPage;
    adrp.pc_relative_displacement = 0x1000;
    assert(adrp.absolute_branch_target(0x12345) == 0x13000);
}

void preserves_mixed_aliases_and_chooses_width_independently_of_operand_order() {
    CachedInstruction decoded{};
    cache_gpr_access(&decoded, 0, "W0", 4, true, false);
    cache_gpr_access(&decoded, 0, "X0", 8, true, false);
    cache_gpr_access(&decoded, 0, "W0", 4, false, true);
    assert(std::strcmp(decoded.read_register_names[0], "X0") == 0);
    assert(decoded.read_gpr_widths[0] == 8);
    assert(std::strcmp(decoded.write_register_names[0], "W0") == 0);
    assert(decoded.write_gpr_widths[0] == 4);

    CachedInstruction reversed{};
    cache_gpr_access(&reversed, 0, "X0", 8, true, false);
    cache_gpr_access(&reversed, 0, "W0", 4, true, false);
    assert(std::strcmp(reversed.read_register_names[0], "X0") == 0);
    assert(reversed.read_gpr_widths[0] == 8);
}

void reuses_same_opcode_at_every_program_counter() {
    InstructionCache cache(InstructionCache::kPreferredSlotCount);
    assert(cache.enabled());

    CachedInstruction instruction{};
    instruction.opcode = 0xd503201fU;
    const CachedInstruction *first = cache.insert(instruction);
    const CachedInstruction *second = cache.find(instruction.opcode);
    assert(first != nullptr);
    assert(second == first);
    assert(cache.metrics().misses == 1);
    assert(cache.metrics().hits == 1);
    assert(cache.metrics().collisions == 0);
}

} // namespace

int main() {
    InstructionCache cache(1);
    assert(cache.enabled());

    CachedInstruction branch{};
    branch.opcode = 0x14000001;
    std::strcpy(branch.mnemonic, "b");
    std::strcpy(branch.operands, "#0x4");
    branch.pc_relative_displacement = 4;
    branch.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;

    const CachedInstruction *stored = cache.insert(branch);
    assert(stored != nullptr);
    assert(cache.find(branch.opcode) == stored);
    assert(stored->absolute_branch_target(0x1000) == 0x1004);

    CachedInstruction collision = branch;
    collision.opcode = branch.opcode + 8;
    std::strcpy(collision.mnemonic, "bl");
    const CachedInstruction *replacement = cache.insert(collision);
    assert(replacement == stored);
    assert(cache.metrics().hits == 1);
    assert(cache.metrics().misses == 2);
    assert(cache.metrics().collisions == 1);
    assert(cache.find(branch.opcode) == nullptr);
    assert(cache.find(collision.opcode) == replacement);

    bounds_metadata_by_opcode_instead_of_distinct_program_counters();
    converts_qbdi_arm64_branch_units_to_byte_displacements();
    decodes_every_common_arm64_pc_relative_encoding_without_a_location();
    preserves_mixed_aliases_and_chooses_width_independently_of_operand_order();
    reuses_same_opcode_at_every_program_counter();
}
