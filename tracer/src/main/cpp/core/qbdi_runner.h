#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"
#include "core/trace_generation_runtime.h"
#include "events/binary_trace_writer.h"

#include <array>
#include <cstdint>
#include <memory>

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
    // Filled by the proxy admission gate. Keeping the generation alive here
    // makes its stop token and acknowledgement target valid for the complete
    // synchronous QBDI call.
    std::shared_ptr<TraceGenerationRuntime> runtime;
    TraceAdmission admission{};
};

struct TraceRunResult {
    bool target_executed = false;
    bool target_returned = false;
    bool exit_requested = false;
    uint64_t value = 0;

    constexpr TraceRunResult() noexcept = default;
    constexpr TraceRunResult(bool executed, uint64_t result) noexcept
            : target_executed(executed), target_returned(executed), value(result) {}
    constexpr TraceRunResult(bool executed, bool returned,
                             uint64_t result) noexcept
            : target_executed(executed), target_returned(returned), value(result) {}
    constexpr TraceRunResult(bool executed, bool returned, bool requested_exit,
                             uint64_t result) noexcept
            : target_executed(executed), target_returned(returned),
              exit_requested(requested_exit), value(result) {}
};

TraceRunResult run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation);
