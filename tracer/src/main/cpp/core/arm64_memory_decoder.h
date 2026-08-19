#pragma once

#include "core/arm64_memory_operand.h"

#include <cstdint>

struct CachedInstruction;

bool cache_memory_operand(CachedInstruction *instruction,
                          const MemoryOperand &operand) noexcept;
bool decode_arm64_memory_operands(CachedInstruction *instruction, uint32_t opcode,
                                  bool may_load, bool may_store,
                                  uint32_t load_size,
                                  uint32_t store_size) noexcept;
