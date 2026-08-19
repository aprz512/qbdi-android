#include "core/trace_callback_gate.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

enum class Action { Continue, Stop };

struct FailingWriter {
    bool fail_next = false;
    unsigned int writes = 0;

    bool write() {
        ++writes;
        if (!fail_next) return true;
        fail_next = false;
        return false;
    }
};

struct ExtractedRunnerPolicy {
    TraceCallbackGate trace;
    FailingWriter writer;
    Action rule_action = Action::Continue;
    unsigned int rule_callbacks = 0;
    unsigned int target_side_effects = 0;

    void start_trace(bool open_ok, bool begin_ok) {
        trace.observe_failure(!open_ok || !begin_ok);
    }

    Action callback() {
        ++rule_callbacks;
        if (rule_action != Action::Continue) return rule_action;
        return trace.trace(Action::Continue, [&] { return writer.write(); });
    }

    int run_target() {
        if (callback() == Action::Stop) return -1;
        ++target_side_effects;
        if (callback() == Action::Stop) return -1;
        ++target_side_effects;
        return 73;
    }
};

void writer_failure_preserves_actions_and_disables_later_writes() {
    TraceCallbackGate gate;
    unsigned int writes = 0;

    const Action first = gate.trace(Action::Continue, [&] {
        ++writes;
        return false;
    });
    CHECK(first == Action::Continue);
    CHECK(!gate.enabled());
    CHECK(writes == 1);

    const Action repeated = gate.trace(Action::Continue, [&] {
        ++writes;
        return true;
    });
    CHECK(repeated == Action::Continue);
    CHECK(writes == 1);

    const Action rule_action = gate.trace(Action::Stop, [&] {
        ++writes;
        return true;
    });
    CHECK(rule_action == Action::Stop);
    CHECK(writes == 1);
}

void observed_async_failure_disables_without_invoking_a_write() {
    TraceCallbackGate gate;
    gate.observe_failure(true);
    unsigned int writes = 0;
    CHECK(gate.trace(Action::Continue, [&] {
        ++writes;
        return true;
    }) == Action::Continue);
    CHECK(writes == 0);
}

void callback_write_failure_preserves_target_execution_and_later_rules() {
    ExtractedRunnerPolicy runner;
    runner.start_trace(true, true);
    runner.writer.fail_next = true;

    CHECK(runner.run_target() == 73);
    CHECK(runner.target_side_effects == 2);
    CHECK(runner.rule_callbacks == 2);
    CHECK(runner.writer.writes == 1);
    CHECK(!runner.trace.enabled());

    runner.rule_action = Action::Stop;
    CHECK(runner.callback() == Action::Stop);
    CHECK(runner.rule_callbacks == 3);
    CHECK(runner.writer.writes == 1);
}

void open_or_begin_failure_disables_trace_but_not_target_execution() {
    constexpr std::array failures{std::pair{false, false}, std::pair{true, false}};
    for (const auto &[open_ok, begin_ok] : failures) {
        ExtractedRunnerPolicy runner;
        runner.start_trace(open_ok, begin_ok);
        CHECK(runner.run_target() == 73);
        CHECK(runner.target_side_effects == 2);
        CHECK(runner.rule_callbacks == 2);
        CHECK(runner.writer.writes == 0);
    }
}

} // namespace

int main() {
    writer_failure_preserves_actions_and_disables_later_writes();
    observed_async_failure_disables_without_invoking_a_write();
    callback_write_failure_preserves_target_execution_and_later_rules();
    open_or_begin_failure_disables_trace_but_not_target_execution();
}
