#include "core/qbdi_runner.h"
#include "core/crash_marker.h"
#include "core/logging.h"
#include "core/qbdi_runner_lifecycle.h"
#include "core/qbdi_thread_session.h"
#include "core/trace_process_lifecycle.h"
#include "core/trace_run_session.h"

#include <chrono>
#include <memory>
#include <new>
#include <sys/syscall.h>
#include <unistd.h>

static long elapsed_ms_since(std::chrono::steady_clock::time_point started);

struct RunnerState {
    RunnerState(const TraceConfig &config, const TraceInvocation &invocation)
        : writer(config.trace, &metrics),
          stop(&writer, invocation.runtime, invocation.admission, this,
               elapsed_stopped) {
        context.package_name = config.package_name;
        context.scene_name = invocation.scene->name;
        context.target_so = config.target_so;
        context.module_base = invocation.module->start;
        context.target_offset = invocation.scene->offset;
        context.target_address = invocation.target_address;
        context.pid = getpid();
        context.tid = static_cast<int>(syscall(SYS_gettid));
    }

    static bool seal_stopped(void *opaque, TraceStopReason reason) noexcept {
        auto *state = static_cast<RunnerState *>(opaque);
        return state->stop.seal(reason);
    }

    static void acknowledge_stopped(void *opaque, bool sealed) noexcept {
        auto *state = static_cast<RunnerState *>(opaque);
        state->stop.acknowledge(sealed);
    }

    static void snapshot_cache_metrics(void *opaque) noexcept {
        auto *state = static_cast<RunnerState *>(opaque);
        if (state->qbdi != nullptr) {
            state->qbdi->copy_cache_metrics(&state->metrics);
        }
    }

    static long elapsed_stopped(void *opaque) noexcept {
        const auto *state = static_cast<const RunnerState *>(opaque);
        return elapsed_ms_since(state->started);
    }

    QbdiStopControl stop_control() noexcept {
        if (!stop.enabled()) return {};
        QbdiStopControl control{
                stop.token(), this, seal_stopped, acknowledge_stopped};
        control.before_seal = snapshot_cache_metrics;
        return control;
    }

    TraceContext context;
    TraceMetrics metrics;
    BinaryTraceWriter writer;
    TraceRunSessionOutcome session;
    CrashMarkerSession crash_marker;
    QbdiNormalStopLifecycle stop;
    QbdiThreadSession *qbdi = nullptr;
    std::chrono::steady_clock::time_point started{};
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
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::TracePrepare);
        QTRACE_E("test-injected trace setup failure");
    } else
#endif
    if (!state->writer.prepare(state->context)) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::TracePrepare);
        QTRACE_E("prepare trace artifact failed");
    } else if (!state->crash_marker.open(state->writer.path())) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::CrashMarkerOpen);
        QTRACE_E("open crash marker failed");
    } else if (!state->writer.open_prepared()) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::TraceOpen);
        QTRACE_E("open trace file failed");
    } else if (!state->writer.begin(state->context)) {
        trace_setup_ok = false;
        state->session.observe_trace_setup(false);
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::TraceBegin);
        QTRACE_E("begin trace failed");
    } else {
        state->session.observe_trace_setup(true);
        (void)record_qbdi_normal_artifact(invocation.runtime,
                                          state->writer.path());
    }

    state->started = std::chrono::steady_clock::now();
    std::unique_ptr<QbdiThreadSession> qbdi;
    if (trace_setup_ok) {
        qbdi.reset(QbdiThreadSession::create_normal(
                config, invocation, &state->context, &state->writer,
                state->session.callback_gate(), &state->writer,
                state->stop_control()));
    }
    const bool execution_setup_ok = qbdi != nullptr && qbdi->ready();
    state->qbdi = qbdi.get();
    if (!execution_setup_ok && trace_setup_ok) {
        (void)state->writer.error("create QBDI thread session failed");
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::SessionCreate);
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
    state->qbdi = nullptr;

    state->session.observe_target_call(target, state->writer.failed());
    TraceRunFinalization finalization{};
    if (state->stop.stop_observed()) {
        finalization.target_ran = target.ran;
        finalization.outward_return_value = target.ran ? target.return_value : 0;
        const bool writer_closed = state->writer.close();
        if (!state->stop.sealed()) {
            record_qbdi_normal_error(invocation.runtime,
                                     QbdiNormalError::TraceSeal);
        }
        if (!writer_closed) {
            record_qbdi_normal_error(invocation.runtime,
                                     QbdiNormalError::TraceClose);
        }
        finalization.completion_success = state->stop.sealed() && writer_closed;
        finalization.should_log_success = finalization.completion_success;
    } else {
        finalization = state->session.finalize(
                state->writer, elapsed_ms_since(state->started));
        if (!finalization.completion_success) {
            record_qbdi_normal_error(invocation.runtime,
                                     QbdiNormalError::TraceFinalize);
        }
    }
    const bool crash_marker_finished = state->crash_marker.finish();
    if (!crash_marker_finished) {
        record_qbdi_normal_error(invocation.runtime,
                                 QbdiNormalError::CrashMarkerFinish);
    }
    state->stop.finish(finalization.completion_success &&
                       crash_marker_finished);
    if (finalization.should_log_success && crash_marker_finished) {
        QTRACE_I("trace %s %s path=%.*s", invocation.scene->name.c_str(),
                 state->stop.stop_observed() ? "stopped" : "complete",
                 static_cast<int>(state->writer.path().size()),
                 state->writer.path().data());
    } else {
        QTRACE_E("trace %s write failed path=%.*s", invocation.scene->name.c_str(),
                 static_cast<int>(state->writer.path().size()), state->writer.path().data());
    }
    TraceRunResult result{
            finalization.target_ran, finalization.outward_return_value};
    result.admission_finished = state->stop.admission_finished();
    return result;
}
