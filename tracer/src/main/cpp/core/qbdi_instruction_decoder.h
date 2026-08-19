#pragma once

#include "core/instruction_cache.h"

#include <QBDI/InstAnalysis.h>

CachedInstruction decode_qbdi_instruction(uint32_t opcode,
                                          const QBDI::InstAnalysis &analysis) noexcept;
