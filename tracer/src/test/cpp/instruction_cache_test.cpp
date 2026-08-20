#include "core/instruction_cache.h"

#include <cassert>
#include <cstring>

namespace {

void allocates_multiple_metadata_chunks_under_hashed_indexing() {
    InstructionCache cache(8192);
    CachedInstruction instruction{};

    constexpr uintptr_t kBasePc = 0x7100000000ULL;
    for (uint32_t opcode = 1; opcode <= 65536 && cache.metadata_chunk_count() < 2; ++opcode) {
        instruction.opcode = opcode;
        instruction.pc_relative_displacement = static_cast<int32_t>(opcode);
        assert(cache.insert(kBasePc + (static_cast<uintptr_t>(opcode) * 4U), instruction) != nullptr);
    }

    assert(cache.metadata_chunk_count() == 2);
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

void distinguishes_same_opcode_at_pcs_with_matching_index_low_bits() {
    InstructionCache cache(InstructionCache::kPreferredSlotCount);
    assert(cache.enabled());

    CachedInstruction instruction{};
    instruction.opcode = 0xd503201fU;
    constexpr uintptr_t kFirstPc = 0x7100000000ULL;
    constexpr uintptr_t kSecondPc = kFirstPc + (1ULL << 22U);

    const CachedInstruction *first = cache.insert(kFirstPc, instruction);
    const CachedInstruction *second = cache.insert(kSecondPc, instruction);
    assert(first != nullptr);
    assert(second != nullptr);
    assert(second != first);
    assert(cache.metrics().misses == 2);
    assert(cache.metrics().hits == 0);
    assert(cache.metrics().collisions == 0);

    assert(cache.find(kFirstPc, instruction.opcode) == first);
    assert(cache.find(kSecondPc, instruction.opcode) == second);
    assert(cache.metrics().hits == 2);
    assert(cache.metrics().misses == 2);
    assert(cache.metrics().collisions == 0);
}

} // namespace

int main() {
    InstructionCache cache(1);
    assert(cache.enabled());
    constexpr uintptr_t kBranchPc = 0x1000;

    CachedInstruction branch{};
    branch.opcode = 0x14000001;
    std::strcpy(branch.mnemonic, "b");
    std::strcpy(branch.operands, "#0x4");
    branch.pc_relative_displacement = 4;
    branch.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;

    const CachedInstruction *stored = cache.insert(kBranchPc, branch);
    assert(stored != nullptr);
    assert(cache.find(kBranchPc, branch.opcode) == stored);
    assert(stored->absolute_branch_target(0x1000) == 0x1004);

    CachedInstruction collision = branch;
    collision.opcode = branch.opcode + 8;
    std::strcpy(collision.mnemonic, "bl");
    const CachedInstruction *replacement = cache.insert(kBranchPc, collision);
    assert(replacement == stored);
    assert(cache.metrics().hits == 1);
    assert(cache.metrics().misses == 2);
    assert(cache.metrics().collisions == 1);
    assert(cache.find(kBranchPc, branch.opcode) == nullptr);
    assert(cache.find(kBranchPc, collision.opcode) == replacement);

    allocates_multiple_metadata_chunks_under_hashed_indexing();
    converts_qbdi_arm64_branch_units_to_byte_displacements();
    preserves_mixed_aliases_and_chooses_width_independently_of_operand_order();
    distinguishes_same_opcode_at_pcs_with_matching_index_low_bits();
}
