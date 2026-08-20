#include "core/instruction_cache.h"

#include <cstring>
#include <limits>
#include <sys/mman.h>

struct InstructionCache::MetadataChunk {
    std::size_t mapping_size;
    CachedInstruction entries[kMetadataEntriesPerChunk];
};

namespace {

void *map_zeroed(std::size_t size) noexcept {
    void *mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mapping == MAP_FAILED ? nullptr : mapping;
}

} // namespace

bool arm64_branch_displacement(int64_t instruction_units,
                               int32_t *byte_displacement) noexcept {
    if (byte_displacement == nullptr) return false;
    constexpr int64_t scale = 4;
    if (instruction_units < std::numeric_limits<int32_t>::min() / scale ||
        instruction_units > std::numeric_limits<int32_t>::max() / scale) {
        return false;
    }
    *byte_displacement = static_cast<int32_t>(instruction_units * scale);
    return true;
}

void cache_gpr_access(CachedInstruction *instruction, size_t index,
                      const char *register_name, uint8_t width_bytes, bool reads,
                      bool writes) noexcept {
    if (instruction == nullptr || index >= CachedInstruction::kGprCount) return;

    const auto update = [register_name, width_bytes](uint8_t &cached_width, char *cached_name) {
        if (cached_width != 0 && width_bytes <= cached_width) return;
        cached_width = width_bytes;
        if (register_name == nullptr) return;
        size_t character = 0;
        while (character + 1U < CachedInstruction::kRegisterNameBytes &&
               register_name[character] != '\0') {
            cached_name[character] = register_name[character];
            ++character;
        }
        cached_name[character] = '\0';
    };

    const uint64_t bit = 1ULL << index;
    if (reads) {
        instruction->read_gpr_mask |= bit;
        update(instruction->read_gpr_widths[index], instruction->read_register_names[index]);
    }
    if (writes) {
        instruction->write_gpr_mask |= bit;
        update(instruction->write_gpr_widths[index], instruction->write_register_names[index]);
    }
}

namespace {

int64_t sign_extend(uint64_t value, unsigned int bits) noexcept {
    const uint64_t sign = 1ULL << (bits - 1U);
    return static_cast<int64_t>((value ^ sign) - sign);
}

} // namespace

bool decode_arm64_pc_relative(uint32_t opcode, PcRelativeKind *kind,
                              int64_t *byte_displacement) noexcept {
    if (kind == nullptr || byte_displacement == nullptr) return false;
    *kind = PcRelativeKind::CurrentPc;
    if ((opcode & 0x7c000000U) == 0x14000000U) {
        *byte_displacement = sign_extend(opcode & 0x03ffffffU, 26) * 4;
        return true;
    }
    if ((opcode & 0xff000010U) == 0x54000000U ||
        (opcode & 0x7e000000U) == 0x34000000U ||
        (opcode & 0x3b000000U) == 0x18000000U) {
        *byte_displacement = sign_extend((opcode >> 5U) & 0x7ffffU, 19) * 4;
        return true;
    }
    if ((opcode & 0x7e000000U) == 0x36000000U) {
        *byte_displacement = sign_extend((opcode >> 5U) & 0x3fffU, 14) * 4;
        return true;
    }
    if ((opcode & 0x1f000000U) == 0x10000000U) {
        const uint64_t immediate = ((static_cast<uint64_t>(opcode) >> 5U) & 0x7ffffU) << 2U |
                                   ((static_cast<uint64_t>(opcode) >> 29U) & 0x3U);
        *byte_displacement = sign_extend(immediate, 21);
        if ((opcode & 0x80000000U) != 0) {
            *kind = PcRelativeKind::CurrentPage;
            *byte_displacement *= 4096;
        }
        return true;
    }
    *kind = PcRelativeKind::None;
    *byte_displacement = 0;
    return false;
}

InstructionCache::InstructionCache(uint32_t requested_slot_count) noexcept {
    if (!is_power_of_two(requested_slot_count)) return;

    if (requested_slot_count != kPreferredSlotCount) {
        allocate_slots(requested_slot_count);
        return;
    }

    if (allocate_slots(kPreferredSlotCount)) return;
    if (allocate_slots(kFallbackSlotCount)) return;
    allocate_slots(kMinimumSlotCount);
}

InstructionCache::~InstructionCache() {
    for (uint32_t index = 0; index < metadata_chunk_index_size_; ++index) {
        MetadataChunk *chunk = metadata_chunk_index_[index];
        if (chunk != nullptr) munmap(chunk, chunk->mapping_size);
    }
    if (metadata_chunk_index_ != nullptr) {
        munmap(metadata_chunk_index_, metadata_chunk_index_mapping_size_);
    }
    if (slots_ != nullptr) munmap(slots_, slots_mapping_size_);
}

const CachedInstruction *InstructionCache::find(uint32_t opcode) noexcept {
    if (!enabled()) {
        ++metrics_.misses;
        return nullptr;
    }

    const Slot &slot = slots_[slot_index(opcode, slot_count_ - 1U)];
    const CachedInstruction *cached = entry(slot.entry_plus_one);
    if (cached != nullptr && slot.opcode == opcode && cached->opcode == opcode) {
        ++metrics_.hits;
        return cached;
    }

    ++metrics_.misses;
    if (slot.entry_plus_one != 0) ++metrics_.collisions;
    return nullptr;
}

const CachedInstruction *InstructionCache::insert(
        const CachedInstruction &instruction) noexcept {
    if (!enabled()) {
        ++metrics_.misses;
        return nullptr;
    }

    Slot &slot = slots_[slot_index(instruction.opcode, slot_count_ - 1U)];
    const CachedInstruction *cached = entry(slot.entry_plus_one);
    if (cached != nullptr && slot.opcode == instruction.opcode &&
        cached->opcode == instruction.opcode) {
        ++metrics_.hits;
    } else {
        ++metrics_.misses;
        if (slot.entry_plus_one != 0) ++metrics_.collisions;
    }
    return store(instruction);
}

const CachedInstruction *InstructionCache::populate_after_miss(
        const CachedInstruction &instruction) noexcept {
    return enabled() ? store(instruction) : nullptr;
}

const CachedInstruction *InstructionCache::resolve(uint32_t opcode, Decoder decoder, void *decoder_data,
                                                   CachedInstruction *scratch) noexcept {
    if (const CachedInstruction *cached = find(opcode); cached != nullptr) return cached;
    if (decoder == nullptr || scratch == nullptr) return nullptr;

    *scratch = CachedInstruction{};
    scratch->opcode = opcode;
    if (!decoder(opcode, decoder_data, scratch)) return nullptr;
    scratch->opcode = opcode;
    if (const CachedInstruction *cached = populate_after_miss(*scratch); cached != nullptr) {
        return cached;
    }
    return scratch;
}

const CachedInstruction *InstructionCache::store(
        const CachedInstruction &instruction) noexcept {
    if (!enabled()) return nullptr;

    Slot &slot = slots_[slot_index(instruction.opcode, slot_count_ - 1U)];
    CachedInstruction *cached = nullptr;
    if (slot.entry_plus_one == 0) {
        cached = allocate_entry();
        if (cached == nullptr) return nullptr;
        slot.entry_plus_one = next_entry_index_;
    } else {
        cached = entry(slot.entry_plus_one);
    }

    if (cached == nullptr) return nullptr;
    *cached = instruction;
    slot.opcode = instruction.opcode;
    return cached;
}

bool InstructionCache::is_power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1U)) == 0;
}

uint32_t InstructionCache::slot_index(uint32_t opcode, uint32_t mask) {
    uint32_t mixed = opcode * 0x9e3779b1U;
    mixed ^= mixed >> 16U;
    return mixed & mask;
}

bool InstructionCache::allocate_slots(uint32_t count) noexcept {
    const std::size_t mapping_size = static_cast<std::size_t>(count) * sizeof(Slot);
    Slot *slots = static_cast<Slot *>(map_zeroed(mapping_size));
    if (slots == nullptr) return false;

    const uint32_t metadata_chunk_index_size = static_cast<uint32_t>(
            (static_cast<uint64_t>(count) + kMetadataEntriesPerChunk - 1U) / kMetadataEntriesPerChunk);
    const std::size_t metadata_chunk_index_mapping_size =
            static_cast<std::size_t>(metadata_chunk_index_size) * sizeof(MetadataChunk *);
    MetadataChunk **metadata_chunk_index =
            static_cast<MetadataChunk **>(map_zeroed(metadata_chunk_index_mapping_size));
    if (metadata_chunk_index == nullptr) {
        munmap(slots, mapping_size);
        return false;
    }

    slots_ = slots;
    slot_count_ = count;
    slots_mapping_size_ = mapping_size;
    metadata_chunk_index_ = metadata_chunk_index;
    metadata_chunk_index_size_ = metadata_chunk_index_size;
    metadata_chunk_index_mapping_size_ = metadata_chunk_index_mapping_size;
    return true;
}

CachedInstruction *InstructionCache::allocate_entry() noexcept {
    if (next_entry_index_ == UINT32_MAX) return nullptr;

    const uint32_t entry_index = next_entry_index_;
    const uint32_t chunk_index = entry_index / kMetadataEntriesPerChunk;
    const uint32_t entry_offset = entry_index % kMetadataEntriesPerChunk;
    if (chunk_index >= metadata_chunk_index_size_) return nullptr;
    MetadataChunk *chunk = metadata_chunk_index_[chunk_index];

    if (chunk == nullptr) {
        const std::size_t mapping_size = sizeof(MetadataChunk);
        chunk = static_cast<MetadataChunk *>(map_zeroed(mapping_size));
        if (chunk == nullptr) return nullptr;
        chunk->mapping_size = mapping_size;
        metadata_chunk_index_[chunk_index] = chunk;
        ++metadata_chunk_count_;
    }

    ++next_entry_index_;
    return &chunk->entries[entry_offset];
}

CachedInstruction *InstructionCache::entry(uint32_t entry_plus_one) noexcept {
    return const_cast<CachedInstruction *>(static_cast<const InstructionCache *>(this)->entry(entry_plus_one));
}

const CachedInstruction *InstructionCache::entry(uint32_t entry_plus_one) const noexcept {
    if (entry_plus_one == 0) return nullptr;
    const uint32_t entry_index = entry_plus_one - 1U;
    const uint32_t chunk_index = entry_index / kMetadataEntriesPerChunk;
    const uint32_t entry_offset = entry_index % kMetadataEntriesPerChunk;
    if (chunk_index >= metadata_chunk_index_size_) return nullptr;
    const MetadataChunk *chunk = metadata_chunk_index_[chunk_index];
    return chunk == nullptr ? nullptr : &chunk->entries[entry_offset];
}
