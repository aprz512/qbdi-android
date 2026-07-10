#pragma once

#include "events/text_trace_writer.h"
#include "events/trace_event.h"

#include <QBDI.h>
#include <QBDI/InstAnalysis.h>
#include <QBDI/State.h>

#include <cstddef>
#include <cstdint>
#include <string>

class CodeRuleContext {
public:
    CodeRuleContext(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr,
                    const QBDI::InstAnalysis *instruction, const TraceContext *trace,
                    TextTraceWriter *writer);

    QBDI::VM *vm() const { return vm_; }
    QBDI::GPRState *gpr() const { return gpr_; }
    QBDI::FPRState *fpr() const { return fpr_; }
    const QBDI::InstAnalysis *instruction() const { return instruction_; }

    uintptr_t address() const;
    uintptr_t module_base() const;
    uintptr_t offset() const;
    bool at_offset(uintptr_t expected_offset) const;

    const char *mnemonic() const;
    const char *disassembly() const;
    bool is_call() const;
    bool is_branch() const;
    bool is_return() const;
    QBDI::ConditionType condition() const;

    uint64_t reg(size_t index) const;
    bool set_reg(size_t index, uint64_t value);
    uint64_t arg(size_t index) const;
    bool set_arg(size_t index, uint64_t value);
    uint64_t return_value() const;
    void set_return_value(uint64_t value);

    uint64_t pc() const;
    void set_pc(uint64_t value);
    uint64_t lr() const;
    uint64_t sp() const;
    uint64_t nzcv() const;
    void set_nzcv(uint64_t value);
    bool zero_flag() const;
    void set_zero_flag(bool enabled);

    uintptr_t absolute(uintptr_t target_offset) const;
    bool read_memory(uintptr_t address, void *buffer, size_t size) const;
    bool write_memory(uintptr_t address, const void *buffer, size_t size) const;
    bool write_c_string(uintptr_t address, const std::string &value) const;

    void trace_rule(const std::string &name, const std::string &detail) const;

private:
    QBDI::VM *vm_ = nullptr;
    QBDI::GPRState *gpr_ = nullptr;
    QBDI::FPRState *fpr_ = nullptr;
    const QBDI::InstAnalysis *instruction_ = nullptr;
    const TraceContext *trace_ = nullptr;
    TextTraceWriter *writer_ = nullptr;
};
