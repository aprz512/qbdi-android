#include "events/trace_dictionary.h"

#include <cstring>
#include <sys/mman.h>

TraceDictionary::TraceDictionary(uint32_t requested_slots) noexcept {
    if (!is_power_of_two(requested_slots)) return;

    uint32_t count = requested_slots;
    while (count != 0) {
        const std::size_t mapping_size = static_cast<std::size_t>(count) * sizeof(Slot);
        void *mapping = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping != MAP_FAILED) {
            slots_ = static_cast<Slot *>(mapping);
            slot_count_ = count;
            mapping_size_ = mapping_size;
            return;
        }
        count >>= 1U;
    }
}

TraceDictionary::~TraceDictionary() {
    if (slots_ != nullptr) munmap(slots_, mapping_size_);
}

bool TraceDictionary::needs_instruction_definition(uint32_t opcode) const noexcept {
    if (slots_ == nullptr) return true;
    const Slot &slot = slots_[slot_index(opcode)];
    return slot.occupied == 0 || slot.opcode != opcode;
}

void TraceDictionary::commit_instruction_definition(uint32_t opcode) noexcept {
    if (slots_ == nullptr) return;
    Slot &slot = slots_[slot_index(opcode)];
    slot.opcode = opcode;
    slot.occupied = 1;
}

void TraceDictionary::reset() noexcept {
    if (slots_ != nullptr) std::memset(slots_, 0, mapping_size_);
}

bool TraceDictionary::is_power_of_two(uint32_t value) noexcept {
    return value != 0 && (value & (value - 1U)) == 0;
}

uint32_t TraceDictionary::slot_index(uint32_t opcode) const noexcept {
    uint32_t mixed = opcode * 0x9e3779b1U;
    mixed ^= mixed >> 16U;
    return mixed & (slot_count_ - 1U);
}
