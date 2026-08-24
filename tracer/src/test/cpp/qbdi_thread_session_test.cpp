#include "core/qbdi_thread_session.h"
#include "core/qbdi_execution_control.h"

#include <QBDI/Callback.h>
#include <QBDI/State.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct FakeExecution {
    QbdiThreadSession *session = nullptr;
    uintptr_t entry = 0;
    uintptr_t control_start = 0;
    size_t execution_bytes = 0;
    std::array<uint64_t, 8> args{};
    uint64_t indirect_result = 0;
    uint64_t return_value = 0;
    size_t calls = 0;
    size_t gaps = 0;
    uintptr_t last_gap_pc = 0;
    bool saw_current_session = false;
    bool recurse = false;
    bool target_executed = true;
};

struct FakeControlApi {
    std::array<QbdiControlExtent, kQbdiControlExtentCapacity + 1> ranges{};
    size_t range_calls = 0;
    size_t observer_calls = 0;
    size_t lifecycle_begins = 0;
    bool fail_range = false;
    bool fail_observer = false;
};

struct SignalExecutionProbe {
    QBDI::GPRState gpr{};
    uint64_t epoch = 0;
    uint64_t first_epoch = 0;
    size_t activations = 0;
    size_t clears = 0;
    bool active = false;
    bool cleared_before_vm_return = false;
    TraceRunResult direct_result{};
};

uint64_t activate_signal_execution(void *opaque,
                                   QBDI::GPRState *) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    CHECK(!probe->active);
    probe->active = true;
    ++probe->activations;
    probe->epoch += 1U;
    if (probe->first_epoch == 0) probe->first_epoch = probe->epoch;
    return probe->epoch;
}

void clear_signal_execution(void *opaque) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    probe->active = false;
    ++probe->clears;
}

void observe_signal_target_post(void *opaque, const QBDI::GPRState *gpr,
                                uintptr_t return_address) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    if (gpr != nullptr && gpr->pc == return_address) probe->active = false;
}

QbdiVmExecutionLifecycle signal_lifecycle(SignalExecutionProbe *probe) {
    return {probe, activate_signal_execution, clear_signal_execution,
            observe_signal_target_post};
}

TraceRunResult execute_with_target_return_postinst(
        void *opaque, QbdiThreadSession *, uintptr_t, uintptr_t, size_t,
        const uint64_t[8], uint64_t) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    CHECK(probe->active);
    probe->gpr.pc = 42;
    observe_qbdi_vm_target_post(signal_lifecycle(probe), &probe->gpr, 42);
    probe->cleared_before_vm_return = !probe->active;
    return {true, true, 0x42};
}

TraceRunResult execute_with_fallback_clear(
        void *opaque, QbdiThreadSession *, uintptr_t, uintptr_t, size_t,
        const uint64_t[8], uint64_t) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    CHECK(probe->active);
    return probe->direct_result;
}

TraceRunResult execute_before_continuation(
        void *opaque, QbdiThreadSession *, uintptr_t, uintptr_t, size_t,
        const uint64_t[8], uint64_t) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    CHECK(probe->active);
    return {true, false, 0};
}

TraceRunResult continue_with_target_return_postinst(
        void *opaque, QbdiThreadSession *) noexcept {
    auto *probe = static_cast<SignalExecutionProbe *>(opaque);
    CHECK(probe->active);
    CHECK(probe->epoch > probe->first_epoch);
    probe->gpr.pc = 42;
    observe_qbdi_vm_target_post(signal_lifecycle(probe), &probe->gpr, 42);
    probe->cleared_before_vm_return = !probe->active;
    return {true, true, 0x43};
}

bool add_control_range(void *opaque, uintptr_t start, uintptr_t end) noexcept {
    auto *api = static_cast<FakeControlApi *>(opaque);
    if (api->range_calls < api->ranges.size()) {
        api->ranges[api->range_calls] = {start, end};
    }
    ++api->range_calls;
    return !api->fail_range;
}

bool add_control_observer(void *opaque, uintptr_t start,
                          uintptr_t end) noexcept {
    auto *api = static_cast<FakeControlApi *>(opaque);
    CHECK(api->range_calls != 0);
    CHECK(api->ranges[api->range_calls - 1] ==
          (QbdiControlExtent{start, end}));
    ++api->observer_calls;
    return !api->fail_observer;
}

bool publish_lifecycle(void *opaque, uint32_t tid, bool begin,
                       uint32_t creator_tid, uintptr_t start_routine) noexcept {
    auto *api = static_cast<FakeControlApi *>(opaque);
    CHECK(tid == 771);
    CHECK(creator_tid == 700);
    CHECK(start_routine == 0x76000080);
    if (begin) ++api->lifecycle_begins;
    return begin;
}

struct MultiSceneExecution {
    size_t calls = 0;
};

TraceRunResult execute_two_scenes(void *opaque, QbdiThreadSession *, uintptr_t,
                                  uintptr_t, size_t, const uint64_t[8],
                                  uint64_t) noexcept {
    auto *execution = static_cast<MultiSceneExecution *>(opaque);
    ++execution->calls;
    if (execution->calls == 1) return {true, true, 0x44};
    return {true, false, true, 0x1234};
}

TraceRunResult execute(void *opaque, QbdiThreadSession *session, uintptr_t entry,
                       uintptr_t control_start, size_t execution_bytes,
                       const uint64_t args[8], uint64_t indirect_result) noexcept {
    auto *execution = static_cast<FakeExecution *>(opaque);
    ++execution->calls;
    execution->session = session;
    execution->entry = entry;
    execution->control_start = control_start;
    execution->execution_bytes = execution_bytes;
    for (size_t index = 0; index < execution->args.size(); ++index) {
        execution->args[index] = args[index];
    }
    execution->indirect_result = indirect_result;
    execution->saw_current_session = current_qbdi_thread_session() == session;
    if (execution->recurse) {
        execution->recurse = false;
        const TraceRunResult nested = session->call(entry + 4U, args, indirect_result + 1U);
        CHECK(!nested.target_executed);
        CHECK(nested.value == 0);
        CHECK(current_qbdi_thread_session() == session);
    }
    return {execution->target_executed, execution->return_value};
}

void mark_gap(void *opaque, uint32_t tid, uintptr_t pc) noexcept {
    auto *execution = static_cast<FakeExecution *>(opaque);
    ++execution->gaps;
    execution->last_gap_pc = pc;
    CHECK(tid == 771);
    CHECK(pc != 0);
}

void forwards_entry_arguments_and_return_with_scoped_tls() {
    FakeExecution execution;
    execution.return_value = 0x8877665544332211ULL;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 19, execute, &execution, mark_gap, &execution);
    CHECK(session != nullptr);
    CHECK(session->ready());
    CHECK(session->tid() == 771);
    CHECK(session->module_generation() == 19);
    CHECK(current_qbdi_thread_session() == nullptr);

    const uint64_t args[8]{1, 2, 3, 4, 5, 6, 7, 8};
    const TraceRunResult result = session->call(0x71001234, args, 0xfeed);

    CHECK(result.target_executed);
    CHECK(result.value == execution.return_value);
    CHECK(execution.calls == 1);
    CHECK(execution.session == session);
    CHECK(execution.entry == 0x71001234);
    const std::array<uint64_t, 8> expected_args{1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(execution.args == expected_args);
    CHECK(execution.indirect_result == 0xfeed);
    CHECK(execution.saw_current_session);
    CHECK(current_qbdi_thread_session() == nullptr);
    CHECK(!session->running());
    delete session;
}

void rejects_recursive_running_vm_and_reports_a_permanent_gap() {
    FakeExecution execution;
    execution.return_value = 0x55;
    execution.recurse = true;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 21, execute, &execution, mark_gap, &execution);
    CHECK(session != nullptr);

    const uint64_t args[8]{9};
    const TraceRunResult result = session->call(0x72000080, args, 4);

    CHECK(result.target_executed);
    CHECK(result.value == 0x55);
    CHECK(execution.calls == 1);
    CHECK(execution.gaps == 1);
    CHECK(session->incomplete());
    CHECK(!session->running());
    CHECK(current_qbdi_thread_session() == nullptr);

    session->mark_coverage_gap(0x72000084);
    CHECK(execution.gaps == 2);
    CHECK(session->incomplete());
    delete session;
}

void failed_execution_reports_a_permanent_gap() {
    FakeExecution execution;
    execution.target_executed = false;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 22, execute, &execution, mark_gap, &execution);
    CHECK(session != nullptr);

    const uint64_t args[8]{};
    const TraceRunResult result = session->call(0x73000080, args, 0);

    CHECK(!result.target_executed);
    CHECK(execution.calls == 1);
    CHECK(execution.gaps == 1);
    CHECK(session->incomplete());
    CHECK(!session->running());
    delete session;
}

void gateway_separates_logical_and_trampoline_entries() {
    FakeExecution execution;
    execution.return_value = 0x66;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 23, execute, &execution, mark_gap, &execution);
    CHECK(session != nullptr);
    const uint64_t args[8]{3};

    const TraceRunResult first = session->call_gateway(
            0x74000100, 0x75000200, 0x75000000, 0x1000, args, 0x44);
    CHECK(first.target_executed);
    CHECK(first.value == 0x66);
    CHECK(execution.entry == 0x75000200);
    CHECK(execution.control_start == 0x75000000);
    CHECK(execution.execution_bytes == 0x1000);
    CHECK(execution.gaps == 0);

    execution.target_executed = false;
    const TraceRunResult failed = session->call_gateway(
            0x74000104, 0x75000204, 0x75000000, 0x1000, args, 0x45);
    CHECK(!failed.target_executed);
    CHECK(execution.entry == 0x75000204);
    CHECK(execution.gaps == 1);
    CHECK(execution.last_gap_pc == 0x74000104);
    delete session;
}

void pthread_exit_transfer_is_deferred_until_after_vm_return() {
    AddressRange hole{};
    CHECK(!make_pthread_exit_control_hole(0, &hole));
    CHECK(!make_pthread_exit_control_hole(
            std::numeric_limits<uintptr_t>::max() - 2U, &hole));
    CHECK(make_pthread_exit_control_hole(0x76000200, &hole));
    CHECK(hole.start == 0x76000200);
    CHECK(hole.end == 0x76000204);
    CHECK(0x760001ff < hole.start);
    CHECK(0x76000204 >= hole.end);

    TraceRunResult result{};
    CHECK(!recognize_deferred_pthread_exit(0x76000100, 0x76000200,
                                          0x55, &result));
    CHECK(!result.exit_requested);
    CHECK(recognize_deferred_pthread_exit(0x76000200, 0x76000200,
                                         0x88776655, &result));
    CHECK(result.target_executed);
    CHECK(!result.target_returned);
    CHECK(result.exit_requested);
    CHECK(result.value == 0x88776655);
}

void combined_basic_and_sequence_exit_defers_using_native_pc() {
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::BASIC_BLOCK_EXIT | QBDI::SEQUENCE_EXIT;
    state.basicBlockStart = 0x6dc2a6ec5c;
    state.basicBlockEnd = 0x6dc2a6ec64;
    state.sequenceStart = 0x6dc2a6ec5c;
    state.sequenceEnd = 0x6dc2a6ec64;
    gpr.pc = 0x707fabdef0;
    gpr.x16 = 0x707fabdef0;
    QBDI_GPR_SET(&gpr, 0, 0x1234);
    TraceRunResult result{};

    CHECK(classify_deferred_pthread_exit_event(
                  &state, &gpr, 0x707fabdef0, &result) == QBDI::STOP);
    CHECK(result.target_executed);
    CHECK(!result.target_returned);
    CHECK(result.exit_requested);
    CHECK(result.value == 0x1234);
}

void combined_exit_does_not_guess_destination_from_x16() {
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::BASIC_BLOCK_EXIT | QBDI::SEQUENCE_EXIT;
    gpr.pc = 0x6dc2a6ec60;
    gpr.x16 = 0x707fabdef0;
    TraceRunResult result{};

    CHECK(classify_deferred_pthread_exit_event(
                  &state, &gpr, 0x707fabdef0, &result) == QBDI::CONTINUE);
    CHECK(!result.exit_requested);
}

void exec_transfer_call_keeps_using_vmstate_destination() {
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::EXEC_TRANSFER_CALL;
    state.basicBlockStart = 0x707fabdef0;
    gpr.pc = 0x6dc2a6ec60;
    gpr.x16 = 0x6dc2a6ec60;
    QBDI_GPR_SET(&gpr, 0, 0x5678);
    TraceRunResult result{};

    CHECK(classify_deferred_pthread_exit_event(
                  &state, &gpr, 0x707fabdef0, &result) == QBDI::STOP);
    CHECK(result.exit_requested);
    CHECK(result.value == 0x5678);
}

void lifecycle_begin_is_not_republished_on_scene_reentry() {
    CHECK(!needs_thread_begin_publication(false, false));
    CHECK(needs_thread_begin_publication(true, false));
    CHECK(!needs_thread_begin_publication(true, true));
    CHECK(!needs_thread_begin_publication(false, true));
}

void exact_control_extents_register_each_scene_once() {
    FakeControlApi api;
    QbdiControlExtentSet extents;
    const QbdiControlExtentRegistration registration{
            &api, add_control_range, add_control_observer};

    CHECK(extents.ensure({0x76000000, 0x76000100}, registration) ==
          QbdiControlExtentResult::Added);
    CHECK(extents.ensure({0x76000000, 0x76000100}, registration) ==
          QbdiControlExtentResult::AlreadyPresent);
    CHECK(extents.ensure({0x77000000, 0x77000200}, registration) ==
          QbdiControlExtentResult::Added);
    CHECK(extents.size() == 2);
    CHECK(api.range_calls == 2);
    CHECK(api.observer_calls == 2);
    CHECK(api.ranges[0] == (QbdiControlExtent{0x76000000, 0x76000100}));
    CHECK(api.ranges[1] == (QbdiControlExtent{0x77000000, 0x77000200}));
}

void lifecycle_only_thread_reentry_registers_distinct_scene_controls() {
    FakeControlApi api;
    MultiSceneExecution execution;
    const QbdiControlExtentRegistration registration{
            &api, add_control_range, add_control_observer};
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 29, execute_two_scenes, &execution, nullptr, nullptr,
            publish_lifecycle, &api, nullptr, registration);
    CHECK(session != nullptr);
    CHECK(session->begin_thread(700, 0x76000080));
    CHECK(session->publish_native_thread_begin());
    CHECK(api.lifecycle_begins == 1);

    const uint64_t args[8]{};
    const TraceRunResult scene_a = session->call_gateway(
            0x71000100, 0x76000040, 0x76000000, 0x100, args, 0);
    const TraceRunResult scene_b = session->call_gateway(
            0x71000200, 0x77000080, 0x77000000, 0x200, args, 0);

    CHECK(scene_a.target_executed);
    CHECK(scene_a.target_returned);
    CHECK(scene_a.value == 0x44);
    CHECK(scene_b.target_executed);
    CHECK(!scene_b.target_returned);
    CHECK(scene_b.exit_requested);
    CHECK(scene_b.value == 0x1234);
    CHECK(execution.calls == 2);
    CHECK(api.range_calls == 2);
    CHECK(api.observer_calls == 2);
    CHECK(api.lifecycle_begins == 1);
    delete session;
}

void control_extent_failures_are_bounded_and_sticky() {
    FakeControlApi api;
    QbdiControlExtentSet extents;
    const QbdiControlExtentRegistration registration{
            &api, add_control_range, add_control_observer};
    for (size_t index = 0; index < kQbdiControlExtentCapacity; ++index) {
        const uintptr_t start = 0x78000000 + index * 0x100;
        CHECK(extents.ensure({start, start + 0x80}, registration) ==
              QbdiControlExtentResult::Added);
    }
    CHECK(extents.ensure({0x79000000, 0x79000080}, registration) ==
          QbdiControlExtentResult::CapacityExceeded);
    CHECK(api.range_calls == kQbdiControlExtentCapacity);
    CHECK(api.observer_calls == kQbdiControlExtentCapacity);

    FakeExecution capacity_execution;
    FakeControlApi capacity_api;
    QbdiThreadSession *capacity_session = QbdiThreadSession::create_for_test(
            771, 31, execute, &capacity_execution, mark_gap,
            &capacity_execution, nullptr, nullptr, nullptr,
            {&capacity_api, add_control_range, add_control_observer});
    CHECK(capacity_session != nullptr);
    const uint64_t args[8]{};
    for (size_t index = 0; index < kQbdiControlExtentCapacity; ++index) {
        const uintptr_t start = 0x7c000000 + index * 0x100;
        const TraceRunResult result = capacity_session->call_gateway(
                0x71000400, start + 0x40, start, 0x80, args, 0);
        CHECK(result.target_returned);
    }
    const TraceRunResult capacity_failed = capacity_session->call_gateway(
            0x71000400, 0x7d100040, 0x7d100000, 0x80, args, 0);
    CHECK(!capacity_failed.target_executed);
    CHECK(capacity_execution.calls == kQbdiControlExtentCapacity);
    CHECK(capacity_execution.gaps == 1);
    CHECK(capacity_session->incomplete());
    CHECK(capacity_api.range_calls == kQbdiControlExtentCapacity);
    CHECK(capacity_api.observer_calls == kQbdiControlExtentCapacity);
    delete capacity_session;

    FakeExecution execution;
    FakeControlApi failing_api;
    failing_api.fail_observer = true;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 30, execute, &execution, mark_gap, &execution,
            nullptr, nullptr, nullptr,
            {&failing_api, add_control_range, add_control_observer});
    CHECK(session != nullptr);
    const TraceRunResult failed = session->call_gateway(
            0x71000300, 0x7a000040, 0x7a000000, 0x100, args, 0);
    CHECK(!failed.target_executed);
    CHECK(execution.calls == 0);
    CHECK(execution.gaps == 1);
    CHECK(session->incomplete());
    CHECK(failing_api.range_calls == 1);
    CHECK(failing_api.observer_calls == 1);
    delete session;
}

void repeated_exact_execution_state_requests_periodic_yield() {
    QbdiNoProgressTracker tracker;
    QbdiExecutionState state{};
    state.words[QbdiExecutionState::kPcWord] = 0x7b000040;
    state.words[0] = 0x1234;
    CHECK(!tracker.observe(state));
    for (size_t repeat = 1;
         repeat < QbdiNoProgressTracker::kRepeatedStateYieldInterval; ++repeat) {
        CHECK(!tracker.observe(state));
    }
    CHECK(tracker.observe(state));

    state.words[16] = 0x8888;
    CHECK(!tracker.observe(state));
    for (size_t repeat = 0;
         repeat < QbdiNoProgressTracker::kRepeatedStateYieldInterval; ++repeat) {
        const bool yield = tracker.observe(state);
        CHECK(yield ==
              (repeat + 1 == QbdiNoProgressTracker::kRepeatedStateYieldInterval));
    }
}

void target_return_postinst_clears_before_injected_vm_run_returns() {
    SignalExecutionProbe probe;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 41, execute_with_target_return_postinst, &probe,
            nullptr, nullptr, nullptr, nullptr, nullptr, {},
            signal_lifecycle(&probe));
    CHECK(session != nullptr);
    const uint64_t args[8]{};

    const TraceRunResult result = session->call(0x71004000, args, 0);

    CHECK(result.target_returned);
    CHECK(probe.cleared_before_vm_return);
    CHECK(!probe.active);
    CHECK(probe.activations == 1);
    delete session;
}

void every_injected_vm_return_falls_back_to_an_inactive_epoch() {
    const std::array<TraceRunResult, 3> returns{{
            {false, false, 0},
            {true, true, 0x11},
            {true, false, true, 0x22},
    }};
    for (const TraceRunResult expected : returns) {
        SignalExecutionProbe probe;
        probe.direct_result = expected;
        QbdiThreadSession *session = QbdiThreadSession::create_for_test(
                771, 42, execute_with_fallback_clear, &probe,
                nullptr, nullptr, nullptr, nullptr, nullptr, {},
                signal_lifecycle(&probe));
        CHECK(session != nullptr);
        const uint64_t args[8]{};

        const TraceRunResult result = session->call(0x71004100, args, 0);

        CHECK(result.target_executed == expected.target_executed);
        CHECK(result.target_returned == expected.target_returned);
        CHECK(result.exit_requested == expected.exit_requested);
        CHECK(!probe.active);
        CHECK(probe.activations == 1);
        CHECK(probe.clears == 1);
        delete session;
    }
}

void continuation_reactivates_fresh_and_clears_at_target_postinst() {
    SignalExecutionProbe probe;
    QbdiThreadSession *session = QbdiThreadSession::create_for_test(
            771, 43, execute_before_continuation, &probe,
            nullptr, nullptr, nullptr, nullptr,
            continue_with_target_return_postinst, {},
            signal_lifecycle(&probe));
    CHECK(session != nullptr);
    const uint64_t args[8]{};

    const TraceRunResult result = session->call(0x71004200, args, 0);

    CHECK(result.target_returned);
    CHECK(probe.cleared_before_vm_return);
    CHECK(!probe.active);
    CHECK(probe.activations == 2);
    CHECK(probe.epoch == 2);
    delete session;
}

} // namespace

int main() {
    forwards_entry_arguments_and_return_with_scoped_tls();
    rejects_recursive_running_vm_and_reports_a_permanent_gap();
    failed_execution_reports_a_permanent_gap();
    gateway_separates_logical_and_trampoline_entries();
    pthread_exit_transfer_is_deferred_until_after_vm_return();
    combined_basic_and_sequence_exit_defers_using_native_pc();
    combined_exit_does_not_guess_destination_from_x16();
    exec_transfer_call_keeps_using_vmstate_destination();
    lifecycle_begin_is_not_republished_on_scene_reentry();
    exact_control_extents_register_each_scene_once();
    lifecycle_only_thread_reentry_registers_distinct_scene_controls();
    control_extent_failures_are_bounded_and_sticky();
    repeated_exact_execution_state_requests_periodic_yield();
    target_return_postinst_clears_before_injected_vm_run_returns();
    every_injected_vm_return_falls_back_to_an_inactive_epoch();
    continuation_reactivates_fresh_and_clears_at_target_postinst();
}
