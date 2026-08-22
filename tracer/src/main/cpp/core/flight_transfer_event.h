#pragma once

#include <QBDI/Callback.h>
#include <QBDI/State.h>

#include <array>
#include <cstddef>
#include <cstdint>

class TraceSink;

struct FlightTransferMonitor {
    std::array<uintptr_t, 32> call_sources{};
    std::array<bool, 32> target_sources{};
    size_t depth = 0;
    bool last_published = false;
};

// QBDI 0.12.1 passes the ExecBroker destination as the VM event currentPC,
// which signalEvent copies into basicBlockStart. On AArch64 the callback GPR
// PC may still identify the indirect branch source and must not be used as the
// destination.
uintptr_t qbdi_exec_transfer_call_destination(
        const QBDI::VMState *vm_state) noexcept;

bool emit_flight_transfer_event(FlightTransferMonitor *monitor,
                                uintptr_t last_target_pc,
                                const QBDI::VMState *vm_state,
                                const QBDI::GPRState *gpr,
                                TraceSink *sink,
                                bool publish = true) noexcept;
