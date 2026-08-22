#include "core/flight_transfer_event.h"

#include "events/trace_sink.h"

#include <QBDI/State.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

struct RecordingSink final : TraceSink {
    bool instruction(const TraceContext &, const InstructionRecord &) override {
        return true;
    }
    bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) override {
        return true;
    }
    bool call(const char *value_category, std::string_view value_name,
              std::string_view value_detail) override {
        ++calls;
        category = value_category;
        name = value_name;
        detail = value_detail;
        return true;
    }
    bool rule(const std::string &, const std::string &) override { return true; }
    bool error(const std::string &) override { return true; }
    bool failed() const noexcept override { return false; }

    std::string category;
    std::string name;
    std::string detail;
    size_t calls = 0;
};

void flight_transfer_preserves_source_target_selected_args_and_return() {
    RecordingSink sink;
    FlightTransferMonitor monitor;
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::EXEC_TRANSFER_CALL;
    state.basicBlockStart = 0x2000;
    state.sequenceStart = 0xDEAD;
    gpr.pc = 0x2000;
    QBDI_GPR_SET(&gpr, 0, 0x11);
    QBDI_GPR_SET(&gpr, 1, 0x22);
    QBDI_GPR_SET(&gpr, 2, 0x33);
    QBDI_GPR_SET(&gpr, 3, 0x44);
    gpr.x8 = 0x88;

    CHECK(emit_flight_transfer_event(&monitor, 0x1004, &state, &gpr, &sink));
    CHECK(sink.category == "transfer");
    CHECK(sink.name == "call");
    CHECK(sink.detail ==
          "source=0x1004 target=0x2000 x0=0x11 x1=0x22 x2=0x33 x3=0x44 x8=0x88");

    state.event = QBDI::EXEC_TRANSFER_RETURN;
    state.sequenceStart = 0xBEEF;
    gpr.pc = 0x1008;
    QBDI_GPR_SET(&gpr, 0, 0x55);
    CHECK(emit_flight_transfer_event(&monitor, 0x2004, &state, &gpr, &sink));
    CHECK(sink.category == "transfer");
    CHECK(sink.name == "return");
    CHECK(sink.detail == "source=0x1004 target=0x1008 ret=0x55");
}

void indirect_branch_uses_exec_broker_destination_not_source_pc() {
    RecordingSink sink;
    FlightTransferMonitor monitor;
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::EXEC_TRANSFER_CALL;
    state.basicBlockStart = 0x707fabdef0;
    state.basicBlockEnd = 0x707fabdef0;
    state.sequenceStart = 0x707fabdef0;
    state.sequenceEnd = 0x707fabdef0;
    gpr.pc = 0x71000004; // source BR x16 retained by the callback state
    gpr.x16 = state.basicBlockStart;
    QBDI_GPR_SET(&gpr, 0, 0x88776655);

    CHECK(qbdi_exec_transfer_call_destination(&state) == state.basicBlockStart);
    CHECK(emit_flight_transfer_event(&monitor, 0x71000000, &state, &gpr,
                                     &sink));
    CHECK(sink.detail ==
          "source=0x71000000 target=0x707fabdef0 x0=0x88776655 "
          "x1=0x0 x2=0x0 x3=0x0 x8=0x0");

    // A source PC that happens to equal pthread_exit must not be mistaken for
    // the broker destination.
    gpr.pc = 0x707fabdef0;
    state.basicBlockStart = 0x707fab0000;
    CHECK(qbdi_exec_transfer_call_destination(&state) == 0x707fab0000);
}

void external_control_transfers_do_not_enter_the_target_trace() {
    RecordingSink sink;
    FlightTransferMonitor monitor;
    QBDI::VMState state{};
    QBDI::GPRState gpr{};

    state.event = QBDI::EXEC_TRANSFER_CALL;
    gpr.pc = 0x9000;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 0);

    state.event = QBDI::EXEC_TRANSFER_RETURN;
    gpr.pc = 0x8004;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 0);

    state.event = QBDI::EXEC_TRANSFER_CALL;
    gpr.pc = 0xa000;
    CHECK(emit_flight_transfer_event(&monitor, 0x71000400, &state, &gpr,
                                     &sink));
    CHECK(monitor.last_published);
    CHECK(sink.calls == 1);

    // A call made by native control code is nested under the target-originated
    // transfer, but it and its paired return must remain control-only.
    gpr.pc = 0xb000;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 1);
    state.event = QBDI::EXEC_TRANSFER_RETURN;
    gpr.pc = 0xa004;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 1);

    gpr.pc = 0x71000404;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink));
    CHECK(monitor.last_published);
    CHECK(sink.calls == 2);
    CHECK(sink.name == "return");
    CHECK(sink.detail ==
          "source=0x71000400 target=0x71000404 ret=0x0");

    state.event = QBDI::EXEC_TRANSFER_CALL;
    gpr.pc = 0xc000;
    CHECK(emit_flight_transfer_event(&monitor, 0x71000500, &state, &gpr,
                                     &sink, false));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 2);
    state.event = QBDI::EXEC_TRANSFER_RETURN;
    gpr.pc = 0x71000504;
    CHECK(emit_flight_transfer_event(&monitor, 0, &state, &gpr, &sink,
                                     false));
    CHECK(!monitor.last_published);
    CHECK(sink.calls == 2);
}

} // namespace

int main() {
    flight_transfer_preserves_source_target_selected_args_and_return();
    indirect_branch_uses_exec_broker_destination_not_source_pc();
    external_control_transfers_do_not_enter_the_target_trace();
    return 0;
}
