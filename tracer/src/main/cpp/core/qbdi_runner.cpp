#include "core/qbdi_runner.h"
#include "core/logging.h"
#include "handlers/call_handlers.h"
#include "rules/code_rule.h"

#include <QBDI.h>
#include <QBDI/State.h>
#include <chrono>
#include <csignal>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

struct RunnerState {
    TraceContext context;
    SceneConfig scene;
    TextTraceWriter writer;
    CodeRuleEngine code_rules;
    ExecTransferMonitor exec_transfer;
    uint64_t sequence = 0;
};

constexpr uint32_t kQbdiVirtualStackSize = 0x1000000;

static thread_local TextTraceWriter *t_active_writer = nullptr;
static struct sigaction s_prev_sigsegv;
static struct sigaction s_prev_sigabrt;

static void on_crash_signal(int sig, siginfo_t *, void *) {
    if (t_active_writer) {
        t_active_writer->flush();
        t_active_writer->write_crash_marker(sig);
        t_active_writer = nullptr;
    }
    struct sigaction *prev = (sig == SIGSEGV) ? &s_prev_sigsegv : &s_prev_sigabrt;
    sigaction(sig, prev, nullptr);
    raise(sig);
}

static void install_crash_handlers() {
    struct sigaction sa{};
    sa.sa_sigaction = on_crash_signal;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &s_prev_sigsegv);
    sigaction(SIGABRT, &sa, &s_prev_sigabrt);
}

static void remove_crash_handlers() {
    sigaction(SIGSEGV, &s_prev_sigsegv, nullptr);
    sigaction(SIGABRT, &s_prev_sigabrt, nullptr);
}

static long elapsed_ms_since(std::chrono::steady_clock::time_point started) {
    auto ended = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
}

static QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access: accesses) {
        MemoryAccessText mem;
        mem.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
        mem.address = access.accessAddress;
        mem.size = access.size;
        mem.value = access.value;
        state->writer.memory(state->context, gpr->pc, mem);
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
    if (rule_action != QBDI::CONTINUE) return rule_action;

    InstructionText inst;
    inst.sequence = ++state->sequence;
    inst.pc = analysis->address;
    inst.disassembly =
            analysis->disassembly != nullptr ? analysis->disassembly : analysis->mnemonic;

    std::ostringstream reads;
    for (uint8_t i = 0; i < analysis->numOperands; ++i) {
        const auto &op = analysis->operands[i];
        if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0 &&
            (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE)) {
            reads << op.regName << "=0x" << std::hex << QBDI_GPR_GET(gpr, op.regCtxIdx) << " ";
        }
    }
    inst.reads = reads.str();

    state->writer.instruction(state->context, inst);
    return QBDI::CONTINUE;
}

static QBDI::VMAction
on_post_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *fpr, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
            QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);

    CodeRuleContext rule_context(vm, gpr, fpr, analysis, &state->context, &state->writer);
    return state->code_rules.on_post_instruction(rule_context);
}

static QBDI::VMAction
on_exec_transfer(QBDI::VM *, const QBDI::VMState *vm_state, QBDI::GPRState *gpr,
                 QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    emit_exec_transfer_event(&state->exec_transfer, vm_state, gpr, &state->writer);
    return QBDI::CONTINUE;
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

    uint8_t *fakestack = nullptr;
    if (!QBDI::allocateVirtualStack(gpr, kQbdiVirtualStackSize, &fakestack)) {
        state.writer.error("allocateVirtualStack failed");
        state.writer.end(0, false, elapsed_ms_since(started));
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

    t_active_writer = &state.writer;
    install_crash_handlers();
    bool ok = vm.call(&retVal, invocation.target_address, args);
    remove_crash_handlers();
    t_active_writer = nullptr;

    state.writer.end(retVal, ok, elapsed_ms_since(started));
    QBDI::alignedFree(fakestack);
    QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(),
             state.writer.path().c_str());
    return retVal;
}
