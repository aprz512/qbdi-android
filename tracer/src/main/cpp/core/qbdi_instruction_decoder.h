#pragma once

#include "core/instruction_cache.h"

#include <QBDI/InstAnalysis.h>

CachedInstruction decode_qbdi_instruction(uint32_t opcode,
                                          const QBDI::InstAnalysis &analysis,
                                          bool decode_memory = false) noexcept;

CachedInstruction decode_arm64_fallback(uint32_t opcode,
                                        bool decode_memory = false) noexcept;

InstructionView resolve_arm64_instruction(
        uintptr_t address, InstructionCache *cache, InstructionCache::Decoder decoder,
        void *decoder_data, CachedInstruction *scratch) noexcept;
