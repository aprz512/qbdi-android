#pragma once

#include "core/instruction_cache.h"
#include "core/module_maps.h"

#include <QBDI/InstAnalysis.h>

#include <array>

CachedInstruction decode_qbdi_instruction(uint32_t opcode,
                                          const QBDI::InstAnalysis &analysis,
                                          bool decode_memory = false) noexcept;

CachedInstruction decode_arm64_fallback(uint32_t opcode,
                                        bool decode_memory = false) noexcept;

using Arm64OpcodeFallback = bool (*)(uintptr_t address, void *buffer, size_t size);

// Resolves instruction metadata while hiding direct-read eligibility and safe fallback from callers.
class Arm64InstructionResolver {
public:
    explicit Arm64InstructionResolver(const ModuleRange &retained_module,
                                      Arm64OpcodeFallback fallback = nullptr) noexcept;

    InstructionView resolve(uintptr_t address, InstructionCache *cache,
                            InstructionCache::Decoder decoder, void *decoder_data,
                            CachedInstruction *scratch, bool decode_memory = false) noexcept;

private:
    bool read_opcode(uintptr_t address, uint32_t *opcode) const noexcept;

    std::array<AddressRange, ModuleRange::kMaxReadableExecutableRanges> direct_ranges_{};
    size_t direct_range_count_ = 0;
    Arm64OpcodeFallback fallback_ = nullptr;
};

InstructionView resolve_arm64_instruction(
        uintptr_t address, InstructionCache *cache, InstructionCache::Decoder decoder,
        void *decoder_data, CachedInstruction *scratch,
        bool decode_memory = false) noexcept;
