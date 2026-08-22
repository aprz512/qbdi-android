#include "core/flight_transfer_event.h"

#include "events/trace_sink.h"

#include <cstdio>
#include <string_view>

uintptr_t qbdi_exec_transfer_call_destination(
        const QBDI::VMState *vm_state) noexcept {
    if (vm_state == nullptr ||
        (vm_state->event & QBDI::EXEC_TRANSFER_CALL) == 0) {
        return 0;
    }
    return vm_state->basicBlockStart;
}

bool emit_flight_transfer_event(FlightTransferMonitor *monitor,
                                uintptr_t last_target_pc,
                                const QBDI::VMState *vm_state,
                                const QBDI::GPRState *gpr,
                                TraceSink *sink, bool publish) noexcept {
    if (monitor == nullptr || vm_state == nullptr || gpr == nullptr ||
        sink == nullptr || sink->failed()) {
        return false;
    }
    monitor->last_published = false;
    char detail[256];
    const char *name = nullptr;
    int count = 0;
    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        if (monitor->depth >= monitor->call_sources.size()) return false;
        const size_t frame = monitor->depth++;
        monitor->call_sources[frame] = last_target_pc;
        monitor->target_sources[frame] = publish && last_target_pc != 0;
        if (!monitor->target_sources[frame]) return true;
        name = "call";
        const uintptr_t destination =
                qbdi_exec_transfer_call_destination(vm_state);
        count = std::snprintf(
                detail, sizeof(detail),
                "source=0x%llx target=0x%llx x0=0x%llx x1=0x%llx "
                "x2=0x%llx x3=0x%llx x8=0x%llx",
                static_cast<unsigned long long>(last_target_pc),
                static_cast<unsigned long long>(destination),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 0)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 1)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 2)),
                static_cast<unsigned long long>(QBDI_GPR_GET(gpr, 3)),
                static_cast<unsigned long long>(gpr->x8));
    } else if ((vm_state->event & QBDI::EXEC_TRANSFER_RETURN) != 0) {
        if (monitor->depth == 0) return true;
        const size_t frame = --monitor->depth;
        if (!publish || !monitor->target_sources[frame]) return true;
        const uintptr_t source = monitor->call_sources[frame];
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
    monitor->last_published = sink->call(
            "transfer", name,
            std::string_view(detail, static_cast<size_t>(count)));
    return monitor->last_published;
}
