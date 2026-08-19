#include "core/qbdi_instruction_decoder.h"
#include "core/arm64_memory_decoder.h"
#include "core/safe_memory.h"

#include <cctype>
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

    if (analysis.operands != nullptr) {
        for (uint8_t index = 0; index < analysis.numOperands; ++index) {
            const QBDI::OperandAnalysis &operand = analysis.operands[index];
            copy_register_access(operand, decoded);
            const bool pc_relative =
                    (static_cast<unsigned int>(operand.flag) &
                     static_cast<unsigned int>(QBDI::OPERANDFLAG_PCREL)) != 0;
            if (operand.type == QBDI::OPERAND_IMM && pc_relative &&
                (analysis.isBranch || analysis.isCall) &&
                arm64_branch_displacement(operand.value,
                                          &decoded.pc_relative_displacement)) {
                decoded.flags = decoded.flags | InstructionFlags::PcRelative;
            }
        }
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
        const int32_t signed_immediate = static_cast<int32_t>(opcode << 6U) >> 6U;
        decoded.pc_relative_displacement = signed_immediate * 4;
        decoded.flags = InstructionFlags::Branch | InstructionFlags::PcRelative;
        if (call) decoded.flags = decoded.flags | InstructionFlags::Call;
        char operand[32]{};
        std::snprintf(operand, sizeof(operand), "#%d",
                      decoded.pc_relative_displacement);
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

InstructionView resolve_arm64_instruction(
        uintptr_t address, InstructionCache *cache, InstructionCache::Decoder decoder,
        void *decoder_data, CachedInstruction *scratch) noexcept {
    if (scratch == nullptr) return {address, nullptr};

    uint32_t opcode = 0;
    if (!safe_read_memory(address, &opcode, sizeof(opcode))) {
        *scratch = CachedInstruction{};
        copy_bounded(scratch->mnemonic, "<unreadable>");
        copy_bounded(scratch->disassembly, "<unreadable>");
        return {address, scratch};
    }

    if (opcode == 0 || cache == nullptr) {
        *scratch = CachedInstruction{};
        const bool decoded = decoder != nullptr && decoder(opcode, decoder_data, scratch);
        if (!decoded) *scratch = decode_arm64_fallback(opcode);
        scratch->opcode = opcode;
        return {address, scratch};
    }

    const CachedInstruction *resolved = cache->resolve(opcode, decoder, decoder_data, scratch);
    if (resolved != nullptr) return {address, resolved};
    *scratch = decode_arm64_fallback(opcode);
    return {address, scratch};
}
