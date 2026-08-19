#include "core/instruction_cache.h"

#include <cassert>
#include <cstring>

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
}
