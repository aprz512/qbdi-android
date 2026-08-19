#include "core/instruction_cache.h"

#include <sys/mman.h>

struct InstructionCache::MetadataChunk {
    MetadataChunk *next;
    std::size_t mapping_size;
    CachedInstruction entries[kMetadataEntriesPerChunk];
};

namespace {

void *map_zeroed(std::size_t size) noexcept {
    void *mapping = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mapping == MAP_FAILED ? nullptr : mapping;
}

} // namespace

uintptr_t CachedInstruction::absolute_branch_target(uintptr_t pc) const {
    return static_cast<uintptr_t>(static_cast<intptr_t>(pc) + static_cast<intptr_t>(pc_relative_displacement));
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
    while (metadata_chunks_ != nullptr) {
        MetadataChunk *chunk = metadata_chunks_;
        metadata_chunks_ = chunk->next;
        munmap(chunk, chunk->mapping_size);
    }
    if (slots_ != nullptr) munmap(slots_, slots_mapping_size_);
}

const CachedInstruction *InstructionCache::find(uint32_t opcode) noexcept {
    if (!enabled()) {
        ++metrics_.misses;
        return nullptr;
    }

    const Slot &slot = slots_[slot_index(opcode, slot_count_ - 1U)];
    if (slot.entry_plus_one != 0 && slot.opcode == opcode) {
        ++metrics_.hits;
        return entry(slot.entry_plus_one);
    }

    ++metrics_.misses;
    if (slot.entry_plus_one != 0) ++metrics_.collisions;
    return nullptr;
}

const CachedInstruction *InstructionCache::insert(const CachedInstruction &instruction) noexcept {
    if (!enabled()) {
        ++metrics_.misses;
        return nullptr;
    }

    Slot &slot = slots_[slot_index(instruction.opcode, slot_count_ - 1U)];
    if (slot.entry_plus_one != 0 && slot.opcode == instruction.opcode) {
        ++metrics_.hits;
        CachedInstruction *cached = entry(slot.entry_plus_one);
        if (cached != nullptr) *cached = instruction;
        return cached;
    }

    ++metrics_.misses;
    CachedInstruction *cached = nullptr;
    if (slot.entry_plus_one == 0) {
        cached = allocate_entry();
        if (cached == nullptr) return nullptr;
        slot.entry_plus_one = next_entry_index_;
    } else {
        ++metrics_.collisions;
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
    return (opcode * 0x9E3779B1U) & mask;
}

bool InstructionCache::allocate_slots(uint32_t count) noexcept {
    const std::size_t mapping_size = static_cast<std::size_t>(count) * sizeof(Slot);
    Slot *slots = static_cast<Slot *>(map_zeroed(mapping_size));
    if (slots == nullptr) return false;

    slots_ = slots;
    slot_count_ = count;
    slots_mapping_size_ = mapping_size;
    return true;
}

CachedInstruction *InstructionCache::allocate_entry() noexcept {
    if (next_entry_index_ == UINT32_MAX) return nullptr;

    const uint32_t entry_index = next_entry_index_;
    const uint32_t chunk_index = entry_index / kMetadataEntriesPerChunk;
    const uint32_t entry_offset = entry_index % kMetadataEntriesPerChunk;
    MetadataChunk *chunk = metadata_chunks_;
    for (uint32_t index = 0; index < chunk_index && chunk != nullptr; ++index) chunk = chunk->next;

    if (chunk == nullptr) {
        const std::size_t mapping_size = sizeof(MetadataChunk);
        chunk = static_cast<MetadataChunk *>(map_zeroed(mapping_size));
        if (chunk == nullptr) return nullptr;
        chunk->mapping_size = mapping_size;
        if (metadata_chunks_ == nullptr) {
            metadata_chunks_ = chunk;
        } else {
            MetadataChunk *last_chunk = metadata_chunks_;
            while (last_chunk->next != nullptr) last_chunk = last_chunk->next;
            last_chunk->next = chunk;
        }
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
    const MetadataChunk *chunk = metadata_chunks_;
    for (uint32_t index = 0; index < chunk_index && chunk != nullptr; ++index) chunk = chunk->next;
    return chunk == nullptr ? nullptr : &chunk->entries[entry_offset];
}
