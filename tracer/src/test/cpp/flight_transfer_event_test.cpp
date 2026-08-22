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
};

void flight_transfer_preserves_source_target_selected_args_and_return() {
    RecordingSink sink;
    FlightTransferMonitor monitor;
    QBDI::VMState state{};
    QBDI::GPRState gpr{};
    state.event = QBDI::EXEC_TRANSFER_CALL;
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

} // namespace

int main() {
    flight_transfer_preserves_source_target_selected_args_and_return();
    return 0;
}
