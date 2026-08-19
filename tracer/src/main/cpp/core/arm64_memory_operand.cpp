#include "core/arm64_memory_decoder.h"
#include "core/arm64_memory_operand.h"

#include "core/instruction_cache.h"

#include <algorithm>

namespace {

int64_t sign_extend(uint32_t value, unsigned int width) noexcept {
    const uint32_t sign = 1U << (width - 1U);
    const uint32_t mask = (1U << width) - 1U;
    value &= mask;
    if ((value & sign) == 0) return static_cast<int64_t>(value);
    return -static_cast<int64_t>(((~value) & mask) + 1U);
}

MemoryAccessKind memory_access_kind(bool may_load, bool may_store) noexcept {
    if (may_load && may_store) return MemoryAccessKind::ReadWrite;
    return may_store ? MemoryAccessKind::Write : MemoryAccessKind::Read;
}

MemoryOperand base_memory_operand(uint32_t opcode, bool may_load, bool may_store,
                                  uint32_t access_size) noexcept {
    MemoryOperand operand{};
    operand.base_reg = static_cast<uint8_t>((opcode >> 5U) & 0x1fU);
    operand.kind = memory_access_kind(may_load, may_store);
    operand.access_size = access_size;
    return operand;
}

bool decode_simd_structure(MemoryOperand *operand, uint32_t opcode,
                           uint32_t access_size) noexcept {
    if (operand == nullptr) return false;
    if (((opcode >> 23U) & 1U) == 0) return true;
    operand->address_mode = MemoryAddressMode::PostIndex;
    operand->writeback = true;
    const uint8_t update_reg = static_cast<uint8_t>((opcode >> 16U) & 0x1fU);
    if (update_reg == 31U) {
        operand->displacement = access_size;
    } else {
        operand->index_reg = update_reg;
        operand->extend = MemoryIndexExtend::Lsl;
    }
    return true;
}

} // namespace

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
    if (!writeback) {
        return base_reg != kNoRegister && base_reg < registers.values.size()
                       ? static_cast<uintptr_t>(registers.values[base_reg])
                       : effective_address(registers);
    }
    if (base_reg == kNoRegister || base_reg >= registers.values.size()) {
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

    if ((opcode & 0x3b000000U) == 0x18000000U) {
        operand.base_reg = 33;
        operand.displacement = sign_extend((opcode >> 5U) & 0x7ffffU, 19) * 4;
        return cache_memory_operand(instruction, operand);
    }

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
        } else if (mode != 0U && mode != 2U) {
            instruction->requires_slow_memory_path = true;
            return false;
        }
        return cache_memory_operand(instruction, operand);
    }

    if ((opcode & 0x3f000000U) == 0x08000000U ||
        (opcode & 0x3b200c00U) == 0x38200000U) {
        return cache_memory_operand(instruction, operand);
    }

    if ((opcode & 0x3b000000U) == 0x39000000U) {
        operand.displacement = static_cast<int64_t>((opcode >> 10U) & 0xfffU) *
                               access_size;
        return cache_memory_operand(instruction, operand);
    }

    if ((opcode & 0x3b000000U) == 0x38000000U) {
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

    // Multiple-structure and single-structure/lane transfers share Rn plus
    // optional immediate/register post-index semantics. QBDI's analysed
    // read/write size is the exact total transfer size for both classes.
    if ((opcode & 0xbf000000U) == 0x0c000000U ||
        (opcode & 0xbf000000U) == 0x0d000000U) {
        decode_simd_structure(&operand, opcode, access_size);
        return cache_memory_operand(instruction, operand);
    }

    instruction->requires_slow_memory_path = true;
    return false;
}
