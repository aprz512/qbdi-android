#include "core/qbdi_runner.h"
#include "core/logging.h"
#include "handlers/call_handlers.h"
#include "rules/code_rule.h"

#include <QBDI.h>
#include <QBDI/State.h>
#include <chrono>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

struct RunnerState {
    TraceContext context;
    SceneConfig scene;
    TextTraceWriter writer;
    CodeRuleEngine code_rules;
    uint64_t sequence = 0;
};

static QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access : accesses) {
        MemoryAccessText mem;
        mem.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
        mem.address = access.accessAddress;
        mem.size = access.size;
        mem.value = access.value;
        state->writer.memory(state->context, gpr->pc, mem);
    }
    return QBDI::CONTINUE;
}

static QBDI::VMAction on_pre_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    CodeRuleContext rule_context(vm, gpr, fpr, analysis, &state->context, &state->writer);
    QBDI::VMAction rule_action = state->code_rules.on_pre_instruction(rule_context);
    if (rule_action != QBDI::CONTINUE) return rule_action;

    InstructionText inst;
    inst.sequence = ++state->sequence;
    inst.pc = analysis->address;
    inst.disassembly = analysis->disassembly != nullptr ? analysis->disassembly : analysis->mnemonic;

    std::ostringstream reads;
    for (uint8_t i = 0; i < analysis->numOperands; ++i) {
        const auto &op = analysis->operands[i];
        if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0 &&
            (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE)) {
            reads << op.regName << "=0x" << std::hex << QBDI_GPR_GET(gpr, op.regCtxIdx) << " ";
        }
    }
    inst.reads = reads.str();

    if (analysis->isCall || analysis->isBranch) {
        for (uint8_t i = 0; i < analysis->numOperands; ++i) {
            const auto &op = analysis->operands[i];
            if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0 &&
                (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE)) {
                uintptr_t target = QBDI_GPR_GET(gpr, op.regCtxIdx);
                emit_possible_external_call(gpr, target, &state->writer);
                break;
            }
        }
    }

    state->writer.instruction(state->context, inst);
    return QBDI::CONTINUE;
}

static QBDI::VMAction on_post_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    CodeRuleContext rule_context(vm, gpr, fpr, analysis, &state->context, &state->writer);
    return state->code_rules.on_post_instruction(rule_context);
}

uint64_t run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    RunnerState state;
    state.context.package_name = config.package_name;
    state.context.scene_name = invocation.scene.name;
    state.context.target_so = config.target_so;
    state.context.module_base = invocation.module.start;
    state.context.target_offset = invocation.scene.offset;
    state.context.target_address = invocation.target_address;
    state.scene = invocation.scene;
    state.context.pid = getpid();
    state.context.tid = static_cast<int>(syscall(SYS_gettid));
    register_user_code_rules(state.code_rules);

    if (!state.writer.open(state.context)) {
        QTRACE_E("open trace file failed");
        return 0;
    }
    state.writer.begin(state.context);

    auto started = std::chrono::steady_clock::now();
    QBDI::VM vm;
    QBDI::GPRState *gpr = vm.getGPRState();
    for (int i = 0; i < 8; ++i) QBDI_GPR_SET(gpr, i, invocation.args[i]);
    gpr->pc = invocation.target_address;

    vm.addInstrumentedModuleFromAddr(invocation.module.start);
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    vm.addCodeCB(QBDI::PREINST, on_pre_instruction, &state);
    vm.addCodeCB(QBDI::POSTINST, on_post_instruction, &state);
    vm.addMemAccessCB(QBDI::MEMORY_READ_WRITE, on_memory, &state);

    QBDI::rword retVal = 0;
    std::vector<QBDI::rword> args;
    args.reserve(invocation.args.size());
    for (uint64_t arg : invocation.args) args.push_back(arg);
    bool ok = vm.call(&retVal, invocation.target_address, args);
    auto ended = std::chrono::steady_clock::now();
    long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
    state.writer.end(retVal, ok, elapsed);
    QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(), state.writer.path().c_str());
    return retVal;
}
