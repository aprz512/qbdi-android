#include "core/instruction_cache.h"

#include <cassert>
#include <cstring>

namespace {

void multi_chunk_entries_resolve_through_the_fixed_index() {
    InstructionCache cache(8192);
    CachedInstruction instruction{};

    for (uint32_t opcode = 0; opcode <= 4096; ++opcode) {
        instruction.opcode = opcode;
        instruction.pc_relative_displacement = static_cast<int32_t>(opcode);
        assert(cache.insert(instruction) != nullptr);
    }

    assert(cache.metadata_chunk_count() == 2);
    assert(cache.find(0)->pc_relative_displacement == 0);
    assert(cache.find(4096)->pc_relative_displacement == 4096);
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

    multi_chunk_entries_resolve_through_the_fixed_index();
    converts_qbdi_arm64_branch_units_to_byte_displacements();
    preserves_mixed_aliases_and_chooses_width_independently_of_operand_order();
}
