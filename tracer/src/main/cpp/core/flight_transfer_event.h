#pragma once

#include <QBDI/Callback.h>
#include <QBDI/State.h>

#include <array>
#include <cstddef>
#include <cstdint>

class TraceSink;

struct FlightTransferMonitor {
    std::array<uintptr_t, 32> call_sources{};
    size_t depth = 0;
};

bool emit_flight_transfer_event(FlightTransferMonitor *monitor,
                                uintptr_t last_target_pc,
                                const QBDI::VMState *vm_state,
                                const QBDI::GPRState *gpr,
                                TraceSink *sink) noexcept;
