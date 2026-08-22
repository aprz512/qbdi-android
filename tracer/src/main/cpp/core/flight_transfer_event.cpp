#include "core/flight_transfer_event.h"

#include "events/trace_sink.h"

#include <cstdio>
#include <string_view>

bool emit_flight_transfer_event(FlightTransferMonitor *monitor,
                                uintptr_t last_target_pc,
                                const QBDI::VMState *vm_state,
                                const QBDI::GPRState *gpr,
                                TraceSink *sink) noexcept {
    if (monitor == nullptr || vm_state == nullptr || gpr == nullptr ||
        sink == nullptr || sink->failed() || last_target_pc == 0) {
        return false;
    }
    char detail[256];
    const char *name = nullptr;
    int count = 0;
    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        if (monitor->depth >= monitor->call_sources.size()) return false;
        monitor->call_sources[monitor->depth++] = last_target_pc;
        name = "call";
        count = std::snprintf(
                detail, sizeof(detail),
                "source=0x%llx target=0x%llx x0=0x%llx x1=0x%llx "
                "x2=0x%llx x3=0x%llx x8=0x%llx",
                static_cast<unsigned long long>(last_target_pc),
                static_cast<unsigned long long>(gpr->pc),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 0)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 1)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 2)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 3)),
                static_cast<unsigned long long>(gpr->x8));
    } else if ((vm_state->event & QBDI::EXEC_TRANSFER_RETURN) != 0) {
        if (monitor->depth == 0) return false;
        const uintptr_t source = monitor->call_sources[--monitor->depth];
        name = "return";
        count = std::snprintf(
                detail, sizeof(detail),
                "source=0x%llx target=0x%llx ret=0x%llx",
                static_cast<unsigned long long>(source),
                static_cast<unsigned long long>(gpr->pc),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 0)));
    } else {
        return true;
    }
    if (count <= 0 || static_cast<size_t>(count) >= sizeof(detail)) return false;
    return sink->call("transfer", name,
                      std::string_view(detail, static_cast<size_t>(count)));
}
