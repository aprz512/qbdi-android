#pragma once

#include <cstddef>
#include <cstdint>

enum class InstructionFlags : uint32_t {
    None = 0,
    Branch = 1U << 0U,
    PcRelative = 1U << 1U,
    Call = 1U << 2U,
    Return = 1U << 3U,
};

constexpr InstructionFlags operator|(InstructionFlags left, InstructionFlags right) {
    return static_cast<InstructionFlags>(static_cast<uint32_t>(left) | static_cast<uint32_t>(right));
}

struct CachedInstruction {
    static constexpr size_t kGprCount = 34;
    static constexpr size_t kRegisterNameBytes = 16;

    uint32_t opcode = 0;
    uint64_t read_gpr_mask = 0;
    uint64_t write_gpr_mask = 0;
    uint8_t read_gpr_widths[kGprCount]{};
    uint8_t write_gpr_widths[kGprCount]{};
    int32_t pc_relative_displacement = 0;
    uint8_t condition = 0;
    InstructionFlags flags = InstructionFlags::None;
    char mnemonic[16]{};
    char operands[96]{};
    char disassembly[112]{};
    char read_register_names[kGprCount][kRegisterNameBytes]{};
    char write_register_names[kGprCount][kRegisterNameBytes]{};

    uintptr_t absolute_branch_target(uintptr_t pc) const;
};

bool arm64_branch_displacement(int64_t instruction_units, int32_t *byte_displacement) noexcept;
void cache_gpr_access(CachedInstruction *instruction, size_t index, const char *register_name,
                      uint8_t width_bytes, bool reads, bool writes) noexcept;

struct InstructionView {
    uintptr_t address = 0;
    const CachedInstruction *decoded = nullptr;
};

struct InstructionCacheMetrics {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t collisions = 0;
};

class InstructionCache {
public:
    static constexpr uint32_t kPreferredSlotCount = 1U << 22U;

    explicit InstructionCache(uint32_t requested_slot_count = kPreferredSlotCount) noexcept;
    ~InstructionCache();

    InstructionCache(const InstructionCache &) = delete;
    InstructionCache &operator=(const InstructionCache &) = delete;

    bool enabled() const { return slots_ != nullptr; }
    uint32_t slot_count() const { return slot_count_; }
    uint32_t metadata_chunk_count() const { return metadata_chunk_count_; }
    const InstructionCacheMetrics &metrics() const { return metrics_; }

    const CachedInstruction *find(uint32_t opcode) noexcept;
    const CachedInstruction *insert(const CachedInstruction &instruction) noexcept;

private:
    struct Slot {
        uint32_t opcode;
        uint32_t entry_plus_one;
    };

    struct MetadataChunk;

    static constexpr uint32_t kFallbackSlotCount = 1U << 20U;
    static constexpr uint32_t kMinimumSlotCount = 1U << 18U;
    static constexpr uint32_t kMetadataEntriesPerChunk = 4096;

    static bool is_power_of_two(uint32_t value);
    static uint32_t slot_index(uint32_t opcode, uint32_t mask);

    bool allocate_slots(uint32_t count) noexcept;
    CachedInstruction *allocate_entry() noexcept;
    CachedInstruction *entry(uint32_t entry_plus_one) noexcept;
    const CachedInstruction *entry(uint32_t entry_plus_one) const noexcept;

    Slot *slots_ = nullptr;
    uint32_t slot_count_ = 0;
    uint32_t next_entry_index_ = 0;
    std::size_t slots_mapping_size_ = 0;
    MetadataChunk **metadata_chunk_index_ = nullptr;
    uint32_t metadata_chunk_index_size_ = 0;
    uint32_t metadata_chunk_count_ = 0;
    std::size_t metadata_chunk_index_mapping_size_ = 0;
    InstructionCacheMetrics metrics_{};
};
