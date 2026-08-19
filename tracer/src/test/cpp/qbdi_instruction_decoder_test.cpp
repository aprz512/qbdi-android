#include "core/qbdi_instruction_decoder.h"

#include <QBDI/State.h>

#include <cassert>
#include <cstring>

namespace {

bool has_flag(InstructionFlags flags, InstructionFlags expected) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(expected)) != 0;
}

void decodes_scaled_branch_metadata_and_owned_strings() {
    char mnemonic[] = "B";
    char disassembly[] = "b #16";
    QBDI::OperandAnalysis operand{};
    operand.type = QBDI::OPERAND_IMM;
    operand.flag = QBDI::OPERANDFLAG_PCREL;
    operand.value = 4;

    QBDI::InstAnalysis analysis{};
    analysis.mnemonic = mnemonic;
    analysis.disassembly = disassembly;
    analysis.instSize = 4;
    analysis.isBranch = true;
    analysis.numOperands = 1;
    analysis.operands = &operand;

    CachedInstruction decoded = decode_qbdi_instruction(0x14000004, analysis);
    mnemonic[0] = 'x';
    disassembly[0] = 'x';
    assert(decoded.opcode == 0x14000004);
    assert(decoded.pc_relative_displacement == 16);
    assert(has_flag(decoded.flags, InstructionFlags::Branch));
    assert(has_flag(decoded.flags, InstructionFlags::PcRelative));
    assert(std::strcmp(decoded.mnemonic, "B") == 0);
    assert(std::strcmp(decoded.disassembly, "b #16") == 0);
    assert(std::strcmp(decoded.operands, "#16") == 0);
}

void maps_mixed_aliases_and_arm64_special_registers() {
    char w0[] = "W0";
    char x0[] = "X0";
    char lr[] = "LR";
    char sp[] = "SP";
    char pc[] = "PC";
    QBDI::OperandAnalysis operands[5]{};
    operands[0] = {QBDI::OPERAND_GPR, QBDI::OPERANDFLAG_NONE, 0, 4, 0, 0, w0,
                   QBDI::REGISTER_WRITE};
    operands[1] = {QBDI::OPERAND_GPR, QBDI::OPERANDFLAG_ADDR, 0, 8, 0, 0, x0,
                   QBDI::REGISTER_READ};
    operands[2] = {QBDI::OPERAND_GPR, QBDI::OPERANDFLAG_NONE, 0, 8, 0,
                   static_cast<int16_t>(QBDI::REG_LR), lr, QBDI::REGISTER_READ};
    operands[3] = {QBDI::OPERAND_GPR, QBDI::OPERANDFLAG_NONE, 0, 8, 0,
                   static_cast<int16_t>(QBDI::REG_SP), sp, QBDI::REGISTER_READ};
    operands[4] = {QBDI::OPERAND_GPR, QBDI::OPERANDFLAG_NONE, 0, 8, 0,
                   static_cast<int16_t>(QBDI::REG_PC), pc, QBDI::REGISTER_WRITE};

    QBDI::InstAnalysis analysis{};
    analysis.isCall = true;
    analysis.isReturn = true;
    analysis.flagsAccess = QBDI::REGISTER_READ_WRITE;
    analysis.numOperands = 5;
    analysis.operands = operands;

    const CachedInstruction decoded = decode_qbdi_instruction(1, analysis);
    assert(std::strcmp(decoded.read_register_names[0], "X0") == 0);
    assert(decoded.read_gpr_widths[0] == 8);
    assert(std::strcmp(decoded.write_register_names[0], "W0") == 0);
    assert(decoded.write_gpr_widths[0] == 4);
    assert(std::strcmp(decoded.read_register_names[QBDI::REG_LR], "LR") == 0);
    assert(std::strcmp(decoded.read_register_names[QBDI::REG_SP], "SP") == 0);
    assert(std::strcmp(decoded.write_register_names[QBDI::REG_FLAG], "NZCV") == 0);
    assert(std::strcmp(decoded.write_register_names[QBDI::REG_PC], "PC") == 0);
    assert(has_flag(decoded.flags, InstructionFlags::Call));
    assert(has_flag(decoded.flags, InstructionFlags::Return));
}

} // namespace

int main() {
    decodes_scaled_branch_metadata_and_owned_strings();
    maps_mixed_aliases_and_arm64_special_registers();
}
