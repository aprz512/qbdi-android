#include "core/qbdi_runner.h"
#include "core/crash_marker.h"
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
    CrashMarkerSession crash_marker;
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

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
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

    bool trace_setup_ok = true;
#ifndef NDEBUG
    if (config.test_fail_setup) {
        trace_setup_ok = false;
        state.session.observe_trace_setup(false);
        QTRACE_E("test-injected trace setup failure");
    } else
#endif
    if (!state.writer.prepare(state.context)) {
        trace_setup_ok = false;
        state.session.observe_trace_setup(false);
        QTRACE_E("prepare trace artifact failed");
    } else if (!state.crash_marker.open(state.writer.path())) {
        trace_setup_ok = false;
        state.session.observe_trace_setup(false);
        QTRACE_E("open crash marker failed");
    } else if (!state.writer.open_prepared()) {
        trace_setup_ok = false;
        state.session.observe_trace_setup(false);
        QTRACE_E("open trace file failed");
    } else if (!state.writer.begin(state.context)) {
        trace_setup_ok = false;
        state.session.observe_trace_setup(false);
        QTRACE_E("begin trace failed");
    } else {
        state.session.observe_trace_setup(true);
    }

    auto started = std::chrono::steady_clock::now();
    InstructionCache instruction_cache;
    InstructionCollector collector(&instruction_cache, &state.writer, &state.code_rules,
                                   &state.context, state.session.callback_gate(), config.trace,
                                   invocation.module);
    QBDI::VM vm;
    QBDI::GPRState *gpr = vm.getGPRState();

    uint8_t *fakestack = nullptr;
    bool execution_setup_ok = trace_setup_ok && gpr != nullptr &&
            QBDI::allocateVirtualStack(gpr, kQbdiVirtualStackSize, &fakestack);
    if (!execution_setup_ok) {
        state.writer.error("allocateVirtualStack failed");
    }

    if (execution_setup_ok) {
        for (int i = 0; i < 8; ++i) QBDI_GPR_SET(gpr, i, invocation.args[i]);
        gpr->x8 = invocation.indirect_result;
        const uintptr_t execution_address = invocation.execution_address != 0
                                                    ? invocation.execution_address
                                                    : invocation.target_address;
        gpr->pc = execution_address;

        if (invocation.scene.end_offset > 0) {
            uintptr_t range_start = 0;
            uintptr_t range_end = 0;
            if (!module_offset_address(invocation.module, invocation.scene.offset, false,
                                       &range_start) ||
                !module_offset_address(invocation.module, invocation.scene.end_offset, true,
                                       &range_end) ||
                range_end <= range_start) {
                state.writer.error("scene instrumentation range is outside retained module");
                execution_setup_ok = false;
            } else {
                vm.addInstrumentedRange(range_start, range_end);
            }
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
        bool callback_setup_ok =
                vm.addCodeCB(QBDI::PREINST, InstructionCollector::pre_callback,
                             &collector) != QBDI::INVALID_EVENTID;
        if (state.code_rules.requires_immediate_post()) {
            callback_setup_ok =
                    vm.addCodeCB(QBDI::POSTINST, InstructionCollector::post_callback,
                                 &collector) != QBDI::INVALID_EVENTID &&
                    callback_setup_ok;
        }
        callback_setup_ok =
                vm.addVMEventCB(QBDI::EXEC_TRANSFER_CALL | QBDI::EXEC_TRANSFER_RETURN,
                                on_exec_transfer, &state) != QBDI::INVALID_EVENTID &&
                callback_setup_ok;
        if (!callback_setup_ok) {
            state.writer.error("QBDI callback registration failed");
            state.session.observe_execution_setup(false);
        }
    }

    if (state.session.target_should_run()) {
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

        if (state.session.target_should_run()) {
            QBDI::rword retVal = 0;
            std::vector<QBDI::rword> args;
            args.reserve(invocation.args.size());
            for (uint64_t arg: invocation.args) args.push_back(arg);

            const uintptr_t execution_address = invocation.execution_address != 0
                                                        ? invocation.execution_address
                                                        : invocation.target_address;
            target.succeeded = vm.call(&retVal, execution_address, args);
            target.ran = target.succeeded;
            target.return_value = retVal;
            if (target.ran) collector.finish_last(*gpr);
        }
    }
    state.metrics.cache_hits = instruction_cache.metrics().hits;
    state.metrics.cache_misses = instruction_cache.metrics().misses;
    state.metrics.cache_collisions = instruction_cache.metrics().collisions;

    state.session.observe_target_call(target, state.writer.failed());
    const TraceRunFinalization finalization =
            state.session.finalize(state.writer, elapsed_ms_since(started));
    const bool crash_marker_finished = state.crash_marker.finish();
    if (fakestack != nullptr) QBDI::alignedFree(fakestack);
    if (finalization.should_log_success && crash_marker_finished) {
        QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    } else {
        QTRACE_E("trace %s write failed path=%s", invocation.scene.name.c_str(),
                 state.writer.path().c_str());
    }
    return {finalization.target_ran, finalization.outward_return_value};
}
