#pragma once

#include "core/module_maps.h"
#include "core/trace_config.h"
#include "events/text_trace_writer.h"

#include <array>
#include <cstdint>

using GenericTargetFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t);

struct TraceInvocation {
    SceneConfig scene;
    ModuleRange module;
    uintptr_t target_address = 0;
    std::array<uint64_t, 8> args{};
};

uint64_t run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation);
