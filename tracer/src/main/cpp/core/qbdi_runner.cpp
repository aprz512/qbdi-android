#include "core/qbdi_runner.h"
#include "core/crash_marker.h"
#include "core/instruction_collector.h"
#include "core/instruction_cache.h"
#include "core/logging.h"
#include "core/qbdi_runner_lifecycle.h"
#include "core/trace_process_lifecycle.h"
#include "core/trace_run_session.h"
#include "handlers/call_handlers.h"
#include "rules/code_rule.h"

#include <QBDI.h>
#include <QBDI/State.h>
#include <chrono>
#include <memory>
#include <new>
#include <sstream>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

struct RunnerState {
    RunnerState(const TraceConfig &config, const TraceInvocation &invocation)
        : writer(config.trace, &metrics) {
        context.package_name = config.package_name;
        context.scene_name = invocation.scene->name;
        context.target_so = config.target_so;
        context.module_base = invocation.module->start;
        context.target_offset = invocation.scene->offset;
        context.target_address = invocation.target_address;
        context.pid = getpid();
        context.tid = static_cast<int>(syscall(SYS_gettid));
        register_user_code_rules(code_rules);
    }

    TraceContext context;
    TraceMetrics metrics;
    BinaryTraceWriter writer;
    CodeRuleEngine code_rules;
    ExecTransferMonitor exec_transfer;
    TraceRunSessionOutcome session;
    CrashMarkerSession crash_marker;
};

struct RunnerRuntime {
    RunnerRuntime(const TraceConfig &config, const TraceInvocation &invocation)
        : state(config, invocation),
          collector(&instruction_cache, &state.writer, &state.code_rules, &state.context,
                    state.session.callback_gate(), config.trace, *invocation.module),
          call_arguments(invocation.args.begin(), invocation.args.end()) {}

    ~RunnerRuntime() {
        if (fakestack != nullptr) QBDI::alignedFree(fakestack);
    }

    RunnerState state;
    InstructionCache instruction_cache;
    InstructionCollector collector;
    QBDI::VM vm;
    std::vector<QBDI::rword> call_arguments;
    uint8_t *fakestack = nullptr;
};

struct QbdiCallRequest {
    QBDI::VM *vm = nullptr;
    uintptr_t address = 0;
    std::vector<QBDI::rword> *arguments = nullptr;
};

bool call_qbdi_target(void *opaque, uint64_t *return_value) {
    auto *request = static_cast<QbdiCallRequest *>(opaque);
    if (request == nullptr || request->vm == nullptr || request->arguments == nullptr ||
        return_value == nullptr) {
        return false;
    }
    QBDI::rword value = 0;
    const bool succeeded = request->vm->call(&value, request->address, *request->arguments);
    *return_value = static_cast<uint64_t>(value);
    return succeeded;
}

constexpr uint32_t kQbdiVirtualStackSize = 0x1000000;

static long elapsed_ms_since(std::chrono::steady_clock::time_point started) {
    auto ended = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
}

static QBDI::VMAction
on_exec_transfer(QBDI::VM *, const QBDI::VMState *vm_state, QBDI::GPRState *gpr,
                 QBDI::FPRState *, void *data) {
    if (trace_process_child_detached()) return QBDI::CONTINUE;
    auto *state = static_cast<RunnerState *>(data);
    TraceCallbackGate *gate = state->session.callback_gate();
    gate->observe_failure(state->writer.failed());
    return gate->trace(QBDI::CONTINUE, [&] {
        emit_exec_transfer_event(&state->exec_transfer, vm_state, gpr, &state->writer);
        return !state->writer.failed();
    });
}

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    if (invocation.scene == nullptr || invocation.module == nullptr) return {};
    std::unique_ptr<RunnerRuntime> runtime(
            new (std::nothrow) RunnerRuntime(config, invocation));
    if (runtime == nullptr) return {};
    RunnerState &state = runtime->state;
    InstructionCache &instruction_cache = runtime->instruction_cache;
    InstructionCollector &collector = runtime->collector;
    QBDI::VM &vm = runtime->vm;

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
    QBDI::GPRState *gpr = vm.getGPRState();

    bool execution_setup_ok = trace_setup_ok && gpr != nullptr &&
            QBDI::allocateVirtualStack(gpr, kQbdiVirtualStackSize, &runtime->fakestack);
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

        if (invocation.scene->end_offset > 0) {
            uintptr_t range_start = 0;
            uintptr_t range_end = 0;
            if (!module_offset_address(*invocation.module, invocation.scene->offset, false,
                                       &range_start) ||
                !module_offset_address(*invocation.module, invocation.scene->end_offset, true,
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
            const uintptr_t execution_address = invocation.execution_address != 0
                                                        ? invocation.execution_address
                                                        : invocation.target_address;
            QbdiCallRequest request{&vm, execution_address, &runtime->call_arguments};
            const QbdiTargetCallResult call =
                    run_qbdi_target_call(call_qbdi_target, &request, &state.writer);
            if (call.child_detached) {
                const TraceRunResult child_result{call.succeeded, call.return_value};
                (void)runtime.release();
                return child_result;
            }
            target.succeeded = call.succeeded;
            target.ran = call.succeeded;
            target.return_value = call.return_value;
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
    if (finalization.should_log_success && crash_marker_finished) {
        QTRACE_I("trace %s complete path=%.*s", invocation.scene->name.c_str(),
                 static_cast<int>(state.writer.path().size()), state.writer.path().data());
    } else {
        QTRACE_E("trace %s write failed path=%.*s", invocation.scene->name.c_str(),
                 static_cast<int>(state.writer.path().size()), state.writer.path().data());
    }
    return {finalization.target_ran, finalization.outward_return_value};
}
