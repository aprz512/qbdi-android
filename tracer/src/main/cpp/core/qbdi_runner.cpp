#include "core/qbdi_runner.h"
#include "core/instruction_collector.h"
#include "core/instruction_cache.h"
#include "core/logging.h"
#include "core/trace_run_session.h"
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
    explicit RunnerState(const TraceOptions &options) : writer(options, &metrics) {}

    TraceContext context;
    SceneConfig scene;
    TraceMetrics metrics;
    TextTraceWriter writer;
    CodeRuleEngine code_rules;
    ExecTransferMonitor exec_transfer;
    TraceRunSessionOutcome session;
};

constexpr uint32_t kQbdiVirtualStackSize = 0x1000000;

static long elapsed_ms_since(std::chrono::steady_clock::time_point started) {
    auto ended = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
}

static QBDI::VMAction
on_exec_transfer(QBDI::VM *, const QBDI::VMState *vm_state, QBDI::GPRState *gpr,
                 QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    TraceCallbackGate *gate = state->session.callback_gate();
    gate->observe_failure(state->writer.failed());
    return gate->trace(QBDI::CONTINUE, [&] {
        emit_exec_transfer_event(&state->exec_transfer, vm_state, gpr, &state->writer);
        return !state->writer.failed();
    });
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
        state.session.observe_trace_setup(false);
        QTRACE_E("open trace file failed");
    } else if (!state.writer.begin(state.context)) {
        state.session.observe_trace_setup(false);
        QTRACE_E("begin trace failed");
    } else {
        state.session.observe_trace_setup(true);
    }

    auto started = std::chrono::steady_clock::now();
    InstructionCache instruction_cache;
    InstructionCollector collector(&instruction_cache, &state.writer, &state.code_rules,
                                   &state.context, state.session.callback_gate(), config.trace);
    QBDI::VM vm;
    QBDI::GPRState *gpr = vm.getGPRState();

    uint8_t *fakestack = nullptr;
    bool execution_setup_ok =
            QBDI::allocateVirtualStack(gpr, kQbdiVirtualStackSize, &fakestack);
    if (!execution_setup_ok) {
        state.writer.error("allocateVirtualStack failed");
    }

    if (execution_setup_ok) {
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
            execution_setup_ok = false;
        }
    }
    state.session.observe_execution_setup(execution_setup_ok);

    TraceTargetOutcome target{};
    if (state.session.target_should_run()) {
        vm.addCodeCB(QBDI::PREINST, InstructionCollector::pre_callback, &collector);
        if (state.code_rules.requires_immediate_post()) {
            vm.addCodeCB(QBDI::POSTINST, InstructionCollector::post_callback, &collector);
        }
        if (config.trace.memory_enabled()) {
            const bool recording = vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
            const uint32_t callback = recording
                                              ? vm.addMemAccessCB(
                                                        QBDI::MEMORY_READ_WRITE,
                                                        InstructionCollector::memory_callback,
                                                        &collector)
                                              : QBDI::INVALID_EVENTID;
            const bool callback_valid = callback != QBDI::INVALID_EVENTID;
            state.session.observe_memory_instrumentation(true, recording,
                                                         callback_valid);
            if (!recording || !callback_valid) {
                state.writer.error("QBDI memory instrumentation unavailable");
            }
        } else {
            state.session.observe_memory_instrumentation(false, false, false);
        }
        vm.addVMEventCB(QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN,
                        on_exec_transfer, &state);

        QBDI::rword retVal = 0;
        std::vector<QBDI::rword> args;
        args.reserve(invocation.args.size());
        for (uint64_t arg: invocation.args) args.push_back(arg);

        target.ran = true;
        target.succeeded = vm.call(&retVal, invocation.target_address, args);
        target.return_value = retVal;
        collector.finish_last(*gpr);
    }
    state.metrics.cache_hits = instruction_cache.metrics().hits;
    state.metrics.cache_misses = instruction_cache.metrics().misses;

    state.session.observe_target_call(target, state.writer.failed());
    const TraceRunFinalization finalization =
            state.session.finalize(state.writer, elapsed_ms_since(started));
    if (fakestack != nullptr) QBDI::alignedFree(fakestack);
    if (finalization.should_log_success) {
        QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    } else {
        QTRACE_E("trace %s write failed path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    }
    return finalization.outward_return_value;
}
