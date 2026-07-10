#include "rules/code_rule_context.h"

#include "core/safe_memory.h"

#include <cstring>

namespace {
    constexpr uint64_t kArm64ZeroFlag = 1ULL << 30U;
    constexpr size_t kReturnRegister = 0;
    constexpr size_t kStackPointerRegister = 31;
}

CodeRuleContext::CodeRuleContext(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr,
                                 const QBDI::InstAnalysis *instruction, const TraceContext *trace,
                                 TextTraceWriter *writer)
        : vm_(vm), gpr_(gpr), fpr_(fpr), instruction_(instruction), trace_(trace),
          writer_(writer) {}

uintptr_t CodeRuleContext::address() const {
    return instruction_ != nullptr ? instruction_->address : 0;
}

uintptr_t CodeRuleContext::module_base() const {
    return trace_ != nullptr ? trace_->module_base : 0;
}

uintptr_t CodeRuleContext::offset() const {
    uintptr_t base = module_base();
    uintptr_t current = address();
    return current >= base ? current - base : 0;
}

bool CodeRuleContext::at_offset(uintptr_t expected_offset) const {
    return offset() == expected_offset;
}

const char *CodeRuleContext::mnemonic() const {
    return instruction_ != nullptr && instruction_->mnemonic != nullptr ? instruction_->mnemonic
                                                                        : "";
}

const char *CodeRuleContext::disassembly() const {
    if (instruction_ == nullptr) return "";
    if (instruction_->disassembly != nullptr) return instruction_->disassembly;
    return instruction_->mnemonic != nullptr ? instruction_->mnemonic : "";
}

bool CodeRuleContext::is_call() const {
    return instruction_ != nullptr && instruction_->isCall;
}

bool CodeRuleContext::is_branch() const {
    return instruction_ != nullptr && instruction_->isBranch;
}

bool CodeRuleContext::is_return() const {
    return instruction_ != nullptr && instruction_->isReturn;
}

QBDI::ConditionType CodeRuleContext::condition() const {
    return instruction_ != nullptr ? instruction_->condition : QBDI::CONDITION_NONE;
}

uint64_t CodeRuleContext::reg(size_t index) const {
    if (gpr_ == nullptr || index > QBDI::REG_PC) return 0;
    if (index == QBDI::REG_PC) return gpr_->pc;
    if (index == QBDI::REG_FLAG) return gpr_->nzcv;
    return QBDI_GPR_GET(gpr_, index);
}

bool CodeRuleContext::set_reg(size_t index, uint64_t value) {
    if (gpr_ == nullptr || index > QBDI::REG_PC) return false;
    if (index == QBDI::REG_PC) {
        gpr_->pc = value;
        return true;
    }
    if (index == QBDI::REG_FLAG) {
        gpr_->nzcv = value;
        return true;
    }
    QBDI_GPR_SET(gpr_, index, value);
    return true;
}

uint64_t CodeRuleContext::arg(size_t index) const {
    return index < 8 ? reg(index) : 0;
}

bool CodeRuleContext::set_arg(size_t index, uint64_t value) {
    return index < 8 && set_reg(index, value);
}

uint64_t CodeRuleContext::return_value() const {
    return reg(kReturnRegister);
}

void CodeRuleContext::set_return_value(uint64_t value) {
    set_reg(kReturnRegister, value);
}

uint64_t CodeRuleContext::pc() const {
    return gpr_ != nullptr ? gpr_->pc : 0;
}

void CodeRuleContext::set_pc(uint64_t value) {
    if (gpr_ != nullptr) gpr_->pc = value;
}

uint64_t CodeRuleContext::lr() const {
    return gpr_ != nullptr ? gpr_->lr : 0;
}

uint64_t CodeRuleContext::sp() const {
    return reg(kStackPointerRegister);
}

uint64_t CodeRuleContext::nzcv() const {
    return gpr_ != nullptr ? gpr_->nzcv : 0;
}

void CodeRuleContext::set_nzcv(uint64_t value) {
    if (gpr_ != nullptr) gpr_->nzcv = value;
}

bool CodeRuleContext::zero_flag() const {
    return (nzcv() & kArm64ZeroFlag) != 0;
}

void CodeRuleContext::set_zero_flag(bool enabled) {
    uint64_t flags = nzcv();
    flags = enabled ? (flags | kArm64ZeroFlag) : (flags & ~kArm64ZeroFlag);
    set_nzcv(flags);
}

uintptr_t CodeRuleContext::absolute(uintptr_t target_offset) const {
    return module_base() + target_offset;
}

bool CodeRuleContext::read_memory(uintptr_t address, void *buffer, size_t size) const {
    return safe_read_memory(address, buffer, size);
}

bool CodeRuleContext::write_memory(uintptr_t address, const void *buffer, size_t size) const {
    return safe_write_memory(address, buffer, size);
}

bool CodeRuleContext::write_c_string(uintptr_t address, const std::string &value) const {
    return write_memory(address, value.c_str(), value.size() + 1U);
}

void CodeRuleContext::trace_rule(const std::string &name, const std::string &detail) const {
    if (writer_ != nullptr) writer_->rule(name, detail);
}
