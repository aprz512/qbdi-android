#pragma once

#include "core/memory_types.h"

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kArm64RegisterCount = 34;

struct RegisterSnapshot {
    std::array<uint64_t, kArm64RegisterCount> values{};
};

enum class MemoryIndexExtend : uint8_t { None, Uxtw, Sxtw, Lsl, Sxtx };
enum class MemoryAddressMode : uint8_t { Offset, PreIndex, PostIndex };

struct MemoryOperand {
    static constexpr uint8_t kNoRegister = UINT8_MAX;

    uint8_t base_reg = kNoRegister;
    uint8_t index_reg = kNoRegister;
    MemoryIndexExtend extend = MemoryIndexExtend::None;
    MemoryAddressMode address_mode = MemoryAddressMode::Offset;
    uint8_t shift = 0;
    MemoryAccessKind kind = MemoryAccessKind::Read;
    uint32_t access_size = 0;
    int64_t displacement = 0;
    bool writeback = false;

    bool try_effective_address(const RegisterSnapshot &registers,
                               uintptr_t *address) const noexcept;
    uintptr_t effective_address(const RegisterSnapshot &registers) const noexcept;
    uintptr_t writeback_address(const RegisterSnapshot &registers) const noexcept;
};
