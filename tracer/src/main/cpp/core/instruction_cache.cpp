#include "core/instruction_cache.h"

#include <algorithm>
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

int64_t sign_extend(uint32_t value, unsigned int width) noexcept {
    const uint32_t sign = 1U << (width - 1U);
    const uint32_t mask = (1U << width) - 1U;
    value &= mask;
    if ((value & sign) == 0) return static_cast<int64_t>(value);
    return -static_cast<int64_t>(((~value) & mask) + 1U);
}

uint8_t memory_access_type(bool may_load, bool may_store) noexcept {
    return static_cast<uint8_t>((may_load ? 1U : 0U) | (may_store ? 2U : 0U));
}

MemoryOperand base_memory_operand(uint32_t opcode, bool may_load, bool may_store,
                                  uint32_t access_size) noexcept {
    MemoryOperand operand{};
    operand.base_reg = static_cast<uint8_t>((opcode >> 5U) & 0x1fU);
    operand.access_type = memory_access_type(may_load, may_store);
    operand.access_size = access_size;
    return operand;
}

} // namespace

size_t bounded_memory_capture_size(size_t access_size,
                                   size_t configured_limit) noexcept {
    return std::min(std::min(access_size, configured_limit), kMaxCapturedMemoryBytes);
}

void capture_memory_bytes(uintptr_t address, size_t access_size,
                          size_t configured_limit, MemoryReadFunction reader,
                          MemoryBytes *capture) noexcept {
    if (capture == nullptr) return;
    *capture = {};
    const size_t size = bounded_memory_capture_size(access_size, configured_limit);
    if (size == 0) return;
    if (reader == nullptr || !reader(address, capture->data.data(), size)) {
        capture->state = MemoryBytesState::Unavailable;
        return;
    }
    capture->size = static_cast<uint8_t>(size);
    capture->state = MemoryBytesState::Available;
}

uint64_t truncate_memory_value(uint64_t value, uint32_t access_size,
                               uint16_t access_flags) noexcept {
    constexpr uint16_t kUnknownSize = 1U;
    constexpr uint16_t kMinimumSize = 2U;
    if ((access_flags & (kUnknownSize | kMinimumSize)) != 0 || access_size == 0 ||
        access_size >= sizeof(value)) {
        return value;
    }
    const unsigned int bits = access_size * 8U;
    return value & ((1ULL << bits) - 1ULL);
}

bool MemoryOperand::try_effective_address(const RegisterSnapshot &registers,
                                          uintptr_t *address) const noexcept {
    if (address == nullptr || shift >= 64U) return false;
    if ((base_reg != kNoRegister && base_reg >= registers.values.size()) ||
        (index_reg != kNoRegister && index_reg >= registers.values.size())) {
        return false;
    }

    uint64_t result = base_reg == kNoRegister ? 0 : registers.values[base_reg];
    uint64_t index = index_reg == kNoRegister ? 0 : registers.values[index_reg];
    switch (extend) {
        case MemoryIndexExtend::None:
        case MemoryIndexExtend::Lsl:
        case MemoryIndexExtend::Sxtx:
            break;
        case MemoryIndexExtend::Uxtw:
            index = static_cast<uint32_t>(index);
            break;
        case MemoryIndexExtend::Sxtw:
            index = static_cast<uint64_t>(static_cast<int64_t>(
                    static_cast<int32_t>(static_cast<uint32_t>(index))));
            break;
    }
    if (address_mode != MemoryAddressMode::PostIndex) {
        result += index << shift;
        result += static_cast<uint64_t>(displacement);
    }
    *address = static_cast<uintptr_t>(result);
    return true;
}

uintptr_t MemoryOperand::effective_address(
        const RegisterSnapshot &registers) const noexcept {
    uintptr_t address = 0;
    return try_effective_address(registers, &address) ? address : 0;
}

uintptr_t MemoryOperand::writeback_address(
        const RegisterSnapshot &registers) const noexcept {
    if (!writeback || base_reg == kNoRegister ||
        base_reg >= registers.values.size()) {
        return effective_address(registers);
    }
    MemoryOperand update = *this;
    update.address_mode = MemoryAddressMode::Offset;
    return update.effective_address(registers);
}

bool cache_memory_operand(CachedInstruction *instruction,
                          const MemoryOperand &operand) noexcept {
    if (instruction == nullptr) return false;
    if (instruction->memory_operand_count >= CachedInstruction::kMaxMemoryOperands) {
        instruction->requires_slow_memory_path = true;
        return false;
    }
    instruction->memory_operands[instruction->memory_operand_count++] = operand;
    return true;
}

bool decode_arm64_memory_operands(CachedInstruction *instruction, uint32_t opcode,
                                  bool may_load, bool may_store,
                                  uint32_t load_size,
                                  uint32_t store_size) noexcept {
    if (instruction == nullptr || (!may_load && !may_store)) return false;
    instruction->memory_operand_count = 0;
    instruction->requires_slow_memory_path = false;
    const uint32_t access_size = std::max(load_size, store_size);
    if (access_size == 0) {
        instruction->requires_slow_memory_path = true;
        return false;
    }

    MemoryOperand operand = base_memory_operand(opcode, may_load, may_store,
                                                access_size);

    // Load literals use PC + sign_extend(imm19 << 2) and have no base register.
    if ((opcode & 0x3b000000U) == 0x18000000U) {
        operand.base_reg = 33;
        operand.displacement = sign_extend((opcode >> 5U) & 0x7ffffU, 19) * 4;
        return cache_memory_operand(instruction, operand);
    }

    // Load/store pairs use a signed imm7 scaled by one element. Keep one formula
    // for the contiguous architectural memory operand; QBDI may report it as one
    // access or split it into two accesses depending on element width.
    if ((opcode & 0x3a000000U) == 0x28000000U) {
        const uint32_t element_size = access_size / 2U;
        if (element_size == 0) {
            instruction->requires_slow_memory_path = true;
            return false;
        }
        operand.displacement =
                sign_extend((opcode >> 15U) & 0x7fU, 7) * element_size;
        const uint32_t mode = (opcode >> 23U) & 3U;
        if (mode == 1U) {
            operand.address_mode = MemoryAddressMode::PostIndex;
            operand.writeback = true;
        } else if (mode == 3U) {
            operand.address_mode = MemoryAddressMode::PreIndex;
            operand.writeback = true;
        } else if (mode != 2U) {
            instruction->requires_slow_memory_path = true;
            return false;
        }
        return cache_memory_operand(instruction, operand);
    }

    // Exclusive and acquire/release atomics use a single base register.
    if ((opcode & 0x3f000000U) == 0x08000000U ||
        (opcode & 0x3b200c00U) == 0x38200000U) {
        return cache_memory_operand(instruction, operand);
    }

    // Unsigned imm12 is scaled by the complete access width.
    if ((opcode & 0x3b000000U) == 0x39000000U) {
        operand.displacement = static_cast<int64_t>((opcode >> 10U) & 0xfffU) *
                               access_size;
        return cache_memory_operand(instruction, operand);
    }

    if ((opcode & 0x3b000000U) == 0x38000000U) {
        // Register offset: option encodes UXTW/LSL/SXTW/SXTX, while S selects
        // either no shift or log2(access_size).
        if ((opcode & 0x00200c00U) == 0x00200800U) {
            operand.index_reg = static_cast<uint8_t>((opcode >> 16U) & 0x1fU);
            if (operand.index_reg == 31U) operand.index_reg = MemoryOperand::kNoRegister;
            switch ((opcode >> 13U) & 7U) {
                case 2: operand.extend = MemoryIndexExtend::Uxtw; break;
                case 3: operand.extend = MemoryIndexExtend::Lsl; break;
                case 6: operand.extend = MemoryIndexExtend::Sxtw; break;
                case 7: operand.extend = MemoryIndexExtend::Sxtx; break;
                default:
                    instruction->requires_slow_memory_path = true;
                    return false;
            }
            if (((opcode >> 12U) & 1U) != 0) {
                uint8_t shift = 0;
                uint32_t scaled = access_size;
                while (scaled > 1U && (scaled & 1U) == 0) {
                    ++shift;
                    scaled >>= 1U;
                }
                if (scaled != 1U) {
                    instruction->requires_slow_memory_path = true;
                    return false;
                }
                operand.shift = shift;
            }
            return cache_memory_operand(instruction, operand);
        }

        operand.displacement = sign_extend((opcode >> 12U) & 0x1ffU, 9);
        switch ((opcode >> 10U) & 3U) {
            case 0:
            case 2:
                operand.address_mode = MemoryAddressMode::Offset;
                break;
            case 1:
                operand.address_mode = MemoryAddressMode::PostIndex;
                operand.writeback = true;
                break;
            case 3:
                operand.address_mode = MemoryAddressMode::PreIndex;
                operand.writeback = true;
                break;
        }
        return cache_memory_operand(instruction, operand);
    }

    // Advanced SIMD structure loads/stores access Rn and may post-index by the
    // complete transfer size (Rm == XZR) or by a register.
    if ((opcode & 0xbf000000U) == 0x0c000000U) {
        if (((opcode >> 23U) & 1U) != 0) {
            operand.address_mode = MemoryAddressMode::PostIndex;
            operand.writeback = true;
            const uint8_t update_reg = static_cast<uint8_t>((opcode >> 16U) & 0x1fU);
            if (update_reg == 31U) {
                operand.displacement = access_size;
            } else {
                operand.index_reg = update_reg;
                operand.extend = MemoryIndexExtend::Lsl;
            }
        }
        return cache_memory_operand(instruction, operand);
    }

    instruction->requires_slow_memory_path = true;
    return false;
}

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

const CachedInstruction *InstructionCache::resolve(uint32_t opcode, Decoder decoder,
                                                   void *decoder_data,
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
    return (opcode * 0x9E3779B1U) & mask;
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
