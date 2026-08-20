#include "events/trace_dictionary.h"

#include <cassert>

namespace {

void assigns_stable_run_local_ids_and_resets() {
    TraceDictionary dictionary(8);
    uint32_t id = UINT32_MAX;
    bool needs_definition = false;
    assert(dictionary.resolve(0x14000001U, &id, &needs_definition));
    assert(id == 0 && needs_definition);
    assert(dictionary.commit_instruction_definition(0x14000001U, id));
    assert(dictionary.resolve(0x14000001U, &id, &needs_definition));
    assert(id == 0 && !needs_definition);

    assert(dictionary.resolve(0xd503201fU, &id, &needs_definition));
    assert(id == 1 && needs_definition);
    assert(dictionary.commit_instruction_definition(0xd503201fU, id));

    dictionary.reset();
    assert(dictionary.resolve(0xd503201fU, &id, &needs_definition));
    assert(id == 0 && needs_definition);
}

void open_addressing_preserves_colliding_entries_until_capacity() {
    TraceDictionary dictionary(2);
    uint32_t first = UINT32_MAX;
    uint32_t second = UINT32_MAX;
    bool needs = false;
    assert(dictionary.resolve(1U, &first, &needs) && needs);
    assert(dictionary.commit_instruction_definition(1U, first));
    assert(dictionary.resolve(3U, &second, &needs) && needs);
    assert(dictionary.commit_instruction_definition(3U, second));
    assert(first == 0 && second == 1);
    assert(dictionary.resolve(1U, &first, &needs) && !needs && first == 0);
    assert(dictionary.resolve(3U, &second, &needs) && !needs && second == 1);
    uint32_t rejected = UINT32_MAX;
    assert(!dictionary.resolve(5U, &rejected, &needs));
}

void supports_exact_protocol_boundary_without_large_allocations() {
    TraceDictionary dictionary(1U << 16U);
    bool needs = false;
    for (uint32_t opcode = 0; opcode < (1U << 16U); ++opcode) {
        uint32_t id = UINT32_MAX;
        assert(dictionary.resolve(opcode, &id, &needs));
        assert(needs && id == opcode);
        assert(dictionary.commit_instruction_definition(opcode, id));
    }
    uint32_t id = UINT32_MAX;
    assert(!dictionary.resolve(1U << 16U, &id, &needs));
}

void rejects_non_power_of_two_capacity() {
    TraceDictionary dictionary(3);
    uint32_t id = 0;
    bool needs = false;
    assert(!dictionary.resolve(1U, &id, &needs));
}

} // namespace

int main() {
    assigns_stable_run_local_ids_and_resets();
    open_addressing_preserves_colliding_entries_until_capacity();
    supports_exact_protocol_boundary_without_large_allocations();
    rejects_non_power_of_two_capacity();
}
