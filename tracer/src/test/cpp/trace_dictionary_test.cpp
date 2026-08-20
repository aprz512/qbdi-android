#include "events/trace_dictionary.h"

#include <cassert>

namespace {

void commits_and_resets_instruction_definitions() {
    TraceDictionary dictionary(8);
    assert(dictionary.needs_instruction_definition(0x14000001U));
    assert(dictionary.needs_instruction_definition(0x14000001U));

    dictionary.commit_instruction_definition(0x14000001U);
    assert(!dictionary.needs_instruction_definition(0x14000001U));

    dictionary.reset();
    assert(dictionary.needs_instruction_definition(0x14000001U));
}

void direct_slot_collisions_repeat_displaced_definitions() {
    TraceDictionary dictionary(1);
    assert(dictionary.needs_instruction_definition(0x14000001U));
    dictionary.commit_instruction_definition(0x14000001U);
    assert(!dictionary.needs_instruction_definition(0x14000001U));

    assert(dictionary.needs_instruction_definition(0xd503201fU));
    dictionary.commit_instruction_definition(0xd503201fU);
    assert(!dictionary.needs_instruction_definition(0xd503201fU));
    assert(dictionary.needs_instruction_definition(0x14000001U));
}

void rejects_non_power_of_two_capacity_without_allocating_later() {
    TraceDictionary dictionary(3);
    assert(dictionary.needs_instruction_definition(1U));
    dictionary.commit_instruction_definition(1U);
    assert(dictionary.needs_instruction_definition(1U));
}

} // namespace

int main() {
    commits_and_resets_instruction_definitions();
    direct_slot_collisions_repeat_displaced_definitions();
    rejects_non_power_of_two_capacity_without_allocating_later();
}
