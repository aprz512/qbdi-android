#include "core/qbdi_instruction_decoder.h"

#include <cctype>
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
                                          const QBDI::InstAnalysis &analysis) noexcept {
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
    return decoded;
}
