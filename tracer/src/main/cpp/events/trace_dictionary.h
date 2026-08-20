#pragma once

#include <cstddef>
#include <cstdint>

class TraceDictionary {
public:
    explicit TraceDictionary(uint32_t requested_slots = 1U << 16U) noexcept;
    ~TraceDictionary();

    TraceDictionary(const TraceDictionary &) = delete;
    TraceDictionary &operator=(const TraceDictionary &) = delete;

    bool resolve(uint32_t opcode, uint32_t *metadata_id,
                 bool *needs_definition) const noexcept;
    bool commit_instruction_definition(uint32_t opcode, uint32_t metadata_id) noexcept;
    void reset() noexcept;

private:
    struct Slot {
        uint32_t opcode;
        uint32_t metadata_id;
        uint32_t occupied;
    };

    static bool is_power_of_two(uint32_t value) noexcept;
    uint32_t slot_index(uint32_t opcode) const noexcept;

    Slot *slots_ = nullptr;
    uint32_t slot_count_ = 0;
    std::size_t mapping_size_ = 0;
    uint32_t entry_count_ = 0;
};
