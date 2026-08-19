#include "core/qbdi_runner.h"
#include "core/logging.h"
#include "handlers/call_handlers.h"
#include "rules/code_rule.h"

#include <QBDI.h>
#include <QBDI/State.h>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

struct RunnerState {
    explicit RunnerState(const TraceOptions &options) : writer(options, &metrics) {}

    TraceContext context;
    SceneConfig scene;
    TraceMetrics metrics;
    TextTraceWriter writer;
    CodeRuleEngine code_rules;
    ExecTransferMonitor exec_transfer;
    uint64_t sequence = 0;
    bool writer_failed = false;
};

constexpr uint32_t kQbdiVirtualStackSize = 0x1000000;

static long elapsed_ms_since(std::chrono::steady_clock::time_point started) {
    auto ended = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
}

static QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access: accesses) {
        MemoryRecord mem;
        mem.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
        mem.address = access.accessAddress;
        mem.size = access.size;
        mem.value = access.value;
        if (!state->writer.memory(state->context, gpr->pc, mem)) {
            state->writer_failed = true;
            return QBDI::STOP;
        }
    }
    return QBDI::CONTINUE;
}

static QBDI::VMAction
on_pre_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    CodeRuleContext rule_context(vm, gpr, fpr, analysis, &state->context, &state->writer);
    QBDI::VMAction rule_action = state->code_rules.on_pre_instruction(rule_context);
    if (state->writer.failed()) {
        state->writer_failed = true;
        return QBDI::STOP;
    }
    if (rule_action != QBDI::CONTINUE) return rule_action;

    CachedInstruction decoded{};
    const char *disassembly = analysis->disassembly != nullptr ? analysis->disassembly
                                                               : analysis->mnemonic;
    if (disassembly != nullptr) {
        std::snprintf(decoded.disassembly, sizeof(decoded.disassembly), "%s", disassembly);
    }

    InstructionRecord record{};
    record.sequence = ++state->sequence;
    record.pc = analysis->address;
    record.module_base = state->context.module_base;
    record.decoded = &decoded;
    for (uint8_t index = 0; index < analysis->numOperands; ++index) {
        const auto &operand = analysis->operands[index];
        if (operand.type != QBDI::OPERAND_GPR || operand.regCtxIdx < 0 ||
            static_cast<size_t>(operand.regCtxIdx) >= kTraceGprCount) {
            continue;
        }
        const uint64_t bit = 1ULL << static_cast<unsigned int>(operand.regCtxIdx);
        if (operand.regAccess == QBDI::REGISTER_READ ||
            operand.regAccess == QBDI::REGISTER_READ_WRITE) {
            decoded.read_gpr_mask |= bit;
            record.before[static_cast<size_t>(operand.regCtxIdx)] =
                QBDI_GPR_GET(gpr, operand.regCtxIdx);
        }
    }

    if (!state->writer.instruction(state->context, record)) {
        state->writer_failed = true;
        return QBDI::STOP;
    }
    return QBDI::CONTINUE;
}

static QBDI::VMAction
on_post_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    CodeRuleContext rule_context(vm, gpr, fpr, analysis, &state->context, &state->writer);
    const QBDI::VMAction action = state->code_rules.on_post_instruction(rule_context);
    if (state->writer.failed()) {
        state->writer_failed = true;
        return QBDI::STOP;
    }
    return action;
}

static QBDI::VMAction
on_exec_transfer(QBDI::VM *, const QBDI::VMState *vm_state, QBDI::GPRState *gpr,
                 QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    emit_exec_transfer_event(&state->exec_transfer, vm_state, gpr, &state->writer);
    if (state->writer.failed()) {
        state->writer_failed = true;
        return QBDI::STOP;
    }
    return QBDI::CONTINUE;
}

uint64_t run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    RunnerState state(config.trace);
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
    if (!state.writer.begin(state.context)) {
        state.writer.close();
        QTRACE_E("begin trace failed");
        return 0;
    }

    auto started = std::chrono::steady_clock::now();
    QBDI::VM vm;
    QBDI::GPRState *gpr = vm.getGPRState();

    uint8_t *fakestack = nullptr;
    if (!QBDI::allocateVirtualStack(gpr, kQbdiVirtualStackSize, &fakestack)) {
        state.writer.error("allocateVirtualStack failed");
        state.writer.end(0, false, elapsed_ms_since(started));
        state.writer.close();
        QTRACE_E("allocateVirtualStack failed");
        return 0;
    }

    for (int i = 0; i < 8; ++i) QBDI_GPR_SET(gpr, i, invocation.args[i]);
    gpr->x8 = invocation.indirect_result;
    gpr->pc = invocation.target_address;

    if (invocation.scene.end_offset > 0) {
        uintptr_t range_start = invocation.module.start + invocation.scene.offset;
        uintptr_t range_end = invocation.module.start + invocation.scene.end_offset;
        vm.addInstrumentedRange(range_start, range_end);
    } else if (!vm.addInstrumentedModuleFromAddr(invocation.target_address)) {
        std::ostringstream error;
        error << "addInstrumentedModuleFromAddr failed address=0x" << std::hex
              << invocation.target_address;
        state.writer.error(error.str());
        state.writer.end(0, false, elapsed_ms_since(started));
        state.writer.close();
        QTRACE_E("addInstrumentedModuleFromAddr 0x%lx failed",
                 static_cast<unsigned long>(invocation.target_address));
        QBDI::alignedFree(fakestack);
        return 0;
    }
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    vm.addCodeCB(QBDI::PREINST, on_pre_instruction, &state);
    vm.addCodeCB(QBDI::POSTINST, on_post_instruction, &state);
    vm.addMemAccessCB(QBDI::MEMORY_READ_WRITE, on_memory, &state);
    vm.addVMEventCB(QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN, on_exec_transfer,
                    &state);

    QBDI::rword retVal = 0;
    std::vector<QBDI::rword> args;
    args.reserve(invocation.args.size());
    for (uint64_t arg: invocation.args) args.push_back(arg);

    bool ok = vm.call(&retVal, invocation.target_address, args);

    ok = ok && !state.writer_failed;
    const bool end_ok = state.writer.end(retVal, ok, elapsed_ms_since(started));
    const bool close_ok = state.writer.close();
    QBDI::alignedFree(fakestack);
    if (end_ok && close_ok) {
        QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    } else {
        QTRACE_E("trace %s write failed path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    }
    return retVal;
}
