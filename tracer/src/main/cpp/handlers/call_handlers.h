#pragma once

#include "events/text_trace_writer.h"

#include <QBDI.h>
#include <cstdint>

void emit_possible_external_call(QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer);
