#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

constexpr size_t kMaxCapturedMemoryBytes = 64;

enum class MemoryAccessKind : uint8_t { Read = 1, Write = 2, ReadWrite = 3 };
enum class MemoryBytesState : uint8_t { NotCaptured, Available, Unavailable };

struct MemoryBytes {
    std::array<uint8_t, kMaxCapturedMemoryBytes> data{};
    uint8_t size = 0;
    MemoryBytesState state = MemoryBytesState::NotCaptured;
};
