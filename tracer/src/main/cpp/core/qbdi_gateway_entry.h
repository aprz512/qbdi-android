#pragma once

#include "rules/code_rule.h"

// Trampolines relocate instructions to different PCs. Evaluate the logical entry
// policy before any of them executes. This notification has no decoded instruction
// and does not fabricate an instruction record.
inline QBDI::VMAction evaluate_qbdi_gateway_entry(
        CodeRuleEngine &rules, QBDI::VM *vm, QBDI::GPRState *gpr,
        QBDI::FPRState *fpr, uintptr_t logical_entry, uintptr_t execution_entry,
        const TraceContext *trace, TraceSink *sink) {
    InstructionView entry{};
    entry.address = logical_entry;
    gpr->pc = logical_entry;
    CodeRuleContext context(vm, gpr, fpr, &entry, trace, sink);
    const QBDI::VMAction action = rules.on_pre_instruction(context);
    if (gpr->pc == logical_entry) gpr->pc = execution_entry;
    return action;
}
