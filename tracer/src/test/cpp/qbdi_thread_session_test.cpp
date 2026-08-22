#include "core/qbdi_thread_session.h"

#include <array>
#include <cstdio>
#include <cstdlib>

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

TraceRunResult execute(void *opaque, QbdiThreadSession *session, uintptr_t entry,
                       size_t execution_bytes,
                       const uint64_t args[8], uint64_t indirect_result) noexcept {
    auto *execution = static_cast<FakeExecution *>(opaque);
    ++execution->calls;
    execution->session = session;
    execution->entry = entry;
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
            0x74000100, 0x75000200, 64, args, 0x44);
    CHECK(first.target_executed);
    CHECK(first.value == 0x66);
    CHECK(execution.entry == 0x75000200);
    CHECK(execution.execution_bytes == 64);
    CHECK(execution.gaps == 0);

    execution.target_executed = false;
    const TraceRunResult failed = session->call_gateway(
            0x74000104, 0x75000204, 64, args, 0x45);
    CHECK(!failed.target_executed);
    CHECK(execution.entry == 0x75000204);
    CHECK(execution.gaps == 1);
    CHECK(execution.last_gap_pc == 0x74000104);
    delete session;
}

} // namespace

int main() {
    forwards_entry_arguments_and_return_with_scoped_tls();
    rejects_recursive_running_vm_and_reports_a_permanent_gap();
    failed_execution_reports_a_permanent_gap();
    gateway_separates_logical_and_trampoline_entries();
}
