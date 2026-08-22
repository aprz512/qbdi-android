#include "core/qbdi_runner.h"
#include "core/crash_marker.h"
#include "core/logging.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_process_lifecycle.h"
#include "core/trace_run_session.h"

#include <chrono>
#include <memory>
#include <new>
#include <sys/syscall.h>
#include <unistd.h>

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
    }

    TraceContext context;
    TraceMetrics metrics;
    BinaryTraceWriter writer;
    TraceRunSessionOutcome session;
    CrashMarkerSession crash_marker;
};

static long elapsed_ms_since(std::chrono::steady_clock::time_point started) {
    auto ended = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
}

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    if (invocation.scene == nullptr || invocation.module == nullptr) return {};
    std::unique_ptr<RunnerState> state(
            new (std::nothrow) RunnerState(config, invocation));
    if (state == nullptr) return {};

    bool trace_setup_ok = true;
#ifndef NDEBUG
    if (config.test_fail_setup) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        QTRACE_E("test-injected trace setup failure");
    } else
#endif
    if (!state->writer.prepare(state->context)) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        QTRACE_E("prepare trace artifact failed");
    } else if (!state->crash_marker.open(state->writer.path())) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        QTRACE_E("open crash marker failed");
    } else if (!state->writer.open_prepared()) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        QTRACE_E("open trace file failed");
    } else if (!state->writer.begin(state->context)) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        QTRACE_E("begin trace failed");
    } else {
        state->session.observe_trace_setup(true);
    }

    auto started = std::chrono::steady_clock::now();
    std::unique_ptr<QbdiThreadSession> qbdi;
    if (trace_setup_ok) {
        qbdi.reset(QbdiThreadSession::create_normal(
                config, invocation, &state->context, &state->writer,
                state->session.callback_gate(), &state->writer));
    }
    const bool execution_setup_ok = qbdi != nullptr && qbdi->ready();
    if (!execution_setup_ok && trace_setup_ok) {
        (void)state->writer.error("create QBDI thread session failed");
    }
    state->session.observe_execution_setup(execution_setup_ok);

    TraceTargetOutcome target{};
    if (state->session.target_should_run()) {
        const uintptr_t execution_address = invocation.execution_address != 0
                                                    ? invocation.execution_address
                                                    : invocation.target_address;
        const TraceRunResult call = qbdi->call(
                execution_address, invocation.args.data(),
                invocation.indirect_result);
        if (trace_process_child_detached()) {
            state->writer.detach_after_fork_child();
            (void)qbdi.release();
            (void)state.release();
            return call;
        }
        target.succeeded = call.target_executed;
        target.ran = call.target_executed;
        target.return_value = call.value;
    }
    if (qbdi != nullptr) qbdi->copy_cache_metrics(&state->metrics);

    state->session.observe_target_call(target, state->writer.failed());
    const TraceRunFinalization finalization =
            state->session.finalize(state->writer, elapsed_ms_since(started));
    const bool crash_marker_finished = state->crash_marker.finish();
    if (finalization.should_log_success && crash_marker_finished) {
        QTRACE_I("trace %s complete path=%.*s", invocation.scene->name.c_str(),
                 static_cast<int>(state->writer.path().size()), state->writer.path().data());
    } else {
        QTRACE_E("trace %s write failed path=%.*s", invocation.scene->name.c_str(),
                 static_cast<int>(state->writer.path().size()), state->writer.path().data());
    }
    return {finalization.target_ran, finalization.outward_return_value};
}
