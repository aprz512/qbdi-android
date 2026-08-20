#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"
#include "events/binary_trace_writer.h"

#include <array>
#include <cstdint>

using GenericTargetFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t);

struct TraceInvocation {
    // Hook-generation metadata is immutable after installation. The proxy runtime's
    // shared ownership keeps these allocation-free views alive for the whole call.
    const SceneConfig *scene = nullptr;
    const ModuleRange *module = nullptr;
    uintptr_t target_address = 0;
    // May select a retained hook-generation trampoline while target_address keeps
    // the logical scene address used by trace metadata and instrumentation ranges.
    uintptr_t execution_address = 0;
    std::array<uint64_t, 8> args{};
    uint64_t indirect_result = 0;
};

struct TraceRunResult {
    bool target_executed = false;
    uint64_t value = 0;
};

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation);
