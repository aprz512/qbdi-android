#include "core/qbdi_instruction_decoder.h"
#include "core/arm64_memory_decoder.h"
#include "core/safe_memory.h"

#include <cctype>
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace {

template <size_t Size>
void copy_bounded(char (&destination)[Size], const char *source) noexcept {
    if (source == nullptr) return;
    size_t index = 0;
    while (index + 1U < Size && source[index] != '\0') {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

void format_fallback(CachedInstruction *decoded, const char *mnemonic,
                     const char *operands = nullptr) noexcept {
    copy_bounded(decoded->mnemonic, mnemonic);
    if (operands != nullptr) copy_bounded(decoded->operands, operands);
    if (operands == nullptr || operands[0] == '\0') {
        copy_bounded(decoded->disassembly, mnemonic);
    } else {
        std::snprintf(decoded->disassembly, sizeof(decoded->disassembly), "%s %s",
                      mnemonic, operands);
    }
}

bool access_reads(QBDI::RegisterAccessType access) noexcept {
    return (static_cast<unsigned int>(access) &
            static_cast<unsigned int>(QBDI::REGISTER_READ)) != 0;
}

bool access_writes(QBDI::RegisterAccessType access) noexcept {
    return (static_cast<unsigned int>(access) &
            static_cast<unsigned int>(QBDI::REGISTER_WRITE)) != 0;
}

void copy_disassembly(const QBDI::InstAnalysis &analysis,
                      CachedInstruction &decoded) noexcept {
    copy_bounded(decoded.mnemonic, analysis.mnemonic);
    copy_bounded(decoded.disassembly, analysis.disassembly);
    if (analysis.disassembly == nullptr) return;

    const char *cursor = analysis.disassembly;
    while (*cursor != '\0' && !std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
    while (*cursor != '\0' && std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
    copy_bounded(decoded.operands, cursor);
}

void normalize_pc_relative_text(CachedInstruction &decoded) noexcept {
    char display_mnemonic[sizeof(decoded.mnemonic)]{};
    const char *mnemonic_end = decoded.disassembly;
    while (*mnemonic_end != '\0' &&
           !std::isspace(static_cast<unsigned char>(*mnemonic_end))) {
        ++mnemonic_end;
    }
    const size_t display_mnemonic_size = std::min(
            static_cast<size_t>(mnemonic_end - decoded.disassembly),
            sizeof(display_mnemonic) - 1U);
    std::memcpy(display_mnemonic, decoded.disassembly, display_mnemonic_size);

    char normalized_operands[sizeof(decoded.operands)]{};
    const char *last_comma = std::strrchr(decoded.operands, ',');
    size_t prefix_size = 0;
    if (last_comma != nullptr) {
        prefix_size = static_cast<size_t>(last_comma - decoded.operands) + 1U;
        prefix_size = std::min(prefix_size, sizeof(normalized_operands) - 2U);
        std::memcpy(normalized_operands, decoded.operands, prefix_size);
        normalized_operands[prefix_size++] = ' ';
    }
    std::snprintf(normalized_operands + prefix_size,
                  sizeof(normalized_operands) - prefix_size, "#%lld",
                  static_cast<long long>(decoded.pc_relative_displacement));
    copy_bounded(decoded.operands, normalized_operands);
    if (decoded.mnemonic[0] == '\0') {
        char opcode[24]{};
        std::snprintf(opcode, sizeof(opcode), "0x%08x", decoded.opcode);
        format_fallback(&decoded, ".inst", opcode);
        return;
    }
    std::snprintf(decoded.disassembly, sizeof(decoded.disassembly), "%s %s",
                  display_mnemonic[0] != '\0' ? display_mnemonic : decoded.mnemonic,
                  decoded.operands);
}

void copy_register_access(const QBDI::OperandAnalysis &operand,
                          CachedInstruction &decoded) noexcept {
    if (operand.type != QBDI::OPERAND_GPR || operand.regCtxIdx < 0 ||
        static_cast<size_t>(operand.regCtxIdx) >= CachedInstruction::kGprCount) {
        return;
    }
    cache_gpr_access(&decoded, static_cast<size_t>(operand.regCtxIdx), operand.regName,
                     operand.size, access_reads(operand.regAccess),
                     access_writes(operand.regAccess));
}

} // namespace

CachedInstruction decode_qbdi_instruction(uint32_t opcode,
                                          const QBDI::InstAnalysis &analysis,
                                          bool decode_memory) noexcept {
    CachedInstruction decoded{};
    decoded.opcode = opcode;
    decoded.condition = static_cast<uint8_t>(analysis.condition);
    copy_disassembly(analysis, decoded);

    if (analysis.isBranch) decoded.flags = decoded.flags | InstructionFlags::Branch;
    if (analysis.isCall) decoded.flags = decoded.flags | InstructionFlags::Call;
    if (analysis.isReturn) decoded.flags = decoded.flags | InstructionFlags::Return;

    bool saw_pc_relative_operand = false;
    if (analysis.operands != nullptr) {
        for (uint8_t index = 0; index < analysis.numOperands; ++index) {
            const QBDI::OperandAnalysis &operand = analysis.operands[index];
            copy_register_access(operand, decoded);
            const bool pc_relative =
                    (static_cast<unsigned int>(operand.flag) &
                     static_cast<unsigned int>(QBDI::OPERANDFLAG_PCREL)) != 0;
            saw_pc_relative_operand = saw_pc_relative_operand || pc_relative;
        }
    }

    if (decode_arm64_pc_relative(opcode, &decoded.pc_relative_kind,
                                 &decoded.pc_relative_displacement)) {
        decoded.flags = decoded.flags | InstructionFlags::PcRelative;
        normalize_pc_relative_text(decoded);
    } else if (saw_pc_relative_operand) {
        char operand[24]{};
        std::snprintf(operand, sizeof(operand), "0x%08x", opcode);
        format_fallback(&decoded, ".inst", operand);
    }

    constexpr size_t flags_index = QBDI::REG_FLAG;
    cache_gpr_access(&decoded, flags_index, "NZCV", sizeof(uint64_t),
                     access_reads(analysis.flagsAccess), access_writes(analysis.flagsAccess));
    if (decode_memory && (analysis.mayLoad || analysis.mayStore)) {
        decode_arm64_memory_operands(&decoded, opcode, analysis.mayLoad, analysis.mayStore,
                                     analysis.loadSize, analysis.storeSize);
    }
    return decoded;
}

CachedInstruction decode_arm64_fallback(uint32_t opcode, bool decode_memory) noexcept {
    CachedInstruction decoded{};
    decoded.opcode = opcode;

    if (opcode == 0xd503201fU) {
        format_fallback(&decoded, "nop");
        return decoded;
    }

    if ((opcode & 0x7c000000U) == 0x14000000U) {
        const bool call = (opcode & 0x80000000U) != 0;
        (void)decode_arm64_pc_relative(opcode, &decoded.pc_relative_kind,
                                      &decoded.pc_relative_displacement);
        decoded.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;
        if (call) decoded.flags = decoded.flags | InstructionFlags::Call;
        char operand[32]{};
        std::snprintf(operand, sizeof(operand), "#%lld",
                      static_cast<long long>(decoded.pc_relative_displacement));
        format_fallback(&decoded, call ? "bl" : "b", operand);
        return decoded;
    }

    if ((opcode & 0xfffffc1fU) == 0xd65f0000U) {
        decoded.flags = InstructionFlags::Branch | InstructionFlags::Return;
        const unsigned int reg = (opcode >> 5U) & 0x1fU;
        char operand[8]{};
        std::snprintf(operand, sizeof(operand), "x%u", reg);
        format_fallback(&decoded, "ret", operand);
        if (reg < CachedInstruction::kGprCount) {
            cache_gpr_access(&decoded, reg, operand, sizeof(uint64_t), true, false);
        }
        return decoded;
    }

    char operand[24]{};
    std::snprintf(operand, sizeof(operand), "0x%08x", opcode);
    format_fallback(&decoded, ".inst", operand);
    decoded.requires_slow_memory_path = decode_memory;
    return decoded;
}

Arm64InstructionResolver::Arm64InstructionResolver(const ModuleRange &retained_module,
                                                   Arm64OpcodeFallback fallback) noexcept
        : fallback_(fallback != nullptr ? fallback : safe_read_memory) {
    direct_range_count_ = std::min(retained_module.readable_executable_range_count,
                                   direct_ranges_.size());
    std::copy_n(retained_module.readable_executable_ranges.begin(), direct_range_count_,
                direct_ranges_.begin());
}

bool Arm64InstructionResolver::read_opcode(uintptr_t address, uint32_t *opcode) const noexcept {
    if (opcode == nullptr) return false;
    if ((address & (alignof(uint32_t) - 1U)) == 0) {
        for (size_t i = 0; i < direct_range_count_; ++i) {
            const AddressRange &range = direct_ranges_[i];
            if (range.start < range.end && range.end - range.start >= sizeof(uint32_t) &&
                address >= range.start && address <= range.end - sizeof(uint32_t)) {
                *opcode = *reinterpret_cast<volatile const uint32_t *>(address);
                return true;
            }
        }
    }
    return fallback_ != nullptr && fallback_(address, opcode, sizeof(*opcode));
}

InstructionView Arm64InstructionResolver::resolve(
        uintptr_t address, InstructionCache *cache, InstructionCache::Decoder decoder,
        void *decoder_data, CachedInstruction *scratch, bool decode_memory) noexcept {
    if (scratch == nullptr) return {address, nullptr};

    uint32_t opcode = 0;
    if (!read_opcode(address, &opcode)) {
        *scratch = CachedInstruction{};
        copy_bounded(scratch->mnemonic, "<unreadable>");
        copy_bounded(scratch->disassembly, "<unreadable>");
        scratch->requires_slow_memory_path = decode_memory;
        return {address, scratch};
    }

    if (opcode == 0 || cache == nullptr) {
        *scratch = CachedInstruction{};
        const bool decoded = decoder != nullptr && decoder(opcode, decoder_data, scratch);
        if (!decoded) *scratch = decode_arm64_fallback(opcode, decode_memory);
        scratch->opcode = opcode;
        return {address, scratch};
    }

    const CachedInstruction *resolved = cache->resolve(opcode, decoder, decoder_data, scratch);
    if (resolved != nullptr) return {address, resolved};
    *scratch = decode_arm64_fallback(opcode, decode_memory);
    return {address, scratch};
}

InstructionView resolve_arm64_instruction(
        uintptr_t address, InstructionCache *cache, InstructionCache::Decoder decoder,
        void *decoder_data, CachedInstruction *scratch, bool decode_memory) noexcept {
    const ModuleRange no_direct_range{};
    Arm64InstructionResolver resolver(no_direct_range);
    return resolver.resolve(address, cache, decoder, decoder_data, scratch, decode_memory);
}
