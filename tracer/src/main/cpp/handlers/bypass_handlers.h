#pragma once

#include "core/trace_config.h"
#include "events/text_trace_writer.h"

#include <QBDI.h>
#include <cstdint>

enum class BypassDecision {
    Continue,
    SkipInstruction,
};

void emit_scene_bypass_markers(const SceneConfig &scene, TextTraceWriter *writer);
BypassDecision maybe_bypass_external_call(const SceneConfig &scene, QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer);
