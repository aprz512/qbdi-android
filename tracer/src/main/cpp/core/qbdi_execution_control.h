#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// One thread can execute every installed scene plus its pthread start control.
// Keep the registry fixed-size so adding a scene while a flight VM is live never
// allocates in the hooked execution path.
inline constexpr size_t kQbdiControlExtentCapacity = 257;

struct QbdiControlExtent {
    uintptr_t start = 0;
    uintptr_t end = 0;

    constexpr bool operator==(const QbdiControlExtent &) const noexcept = default;
};

using QbdiControlExtentRegistrar = bool (*)(void *opaque, uintptr_t start,
                                            uintptr_t end) noexcept;

struct QbdiControlExtentRegistration {
    void *opaque = nullptr;
    QbdiControlExtentRegistrar add_instrumented_range = nullptr;
    QbdiControlExtentRegistrar add_pre_observer = nullptr;
};

enum class QbdiControlExtentResult : uint8_t {
    Added,
    AlreadyPresent,
    Invalid,
    CapacityExceeded,
    InstrumentationFailed,
    ObserverFailed,
};

class QbdiControlExtentSet final {
public:
    QbdiControlExtentResult ensure(
            QbdiControlExtent extent,
            const QbdiControlExtentRegistration &registration) noexcept;

    size_t size() const noexcept { return size_; }

private:
    std::array<QbdiControlExtent, kQbdiControlExtentCapacity> extents_{};
    size_t size_ = 0;
};

// AArch64 QBDI exposes 31 X registers plus SP, NZCV, PC and two exclusive-
// monitor words. Keeping the complete fixed state prevents a changing register
// from being mistaken for a stuck PC without allocating in recovery code.
struct QbdiExecutionState {
    static constexpr size_t kWordCount = 36;
    static constexpr size_t kPcWord = 33;
    std::array<uint64_t, kWordCount> words{};

    constexpr bool operator==(const QbdiExecutionState &) const noexcept = default;
};

class QbdiNoProgressTracker final {
public:
    static constexpr size_t kRepeatedStateYieldInterval = 64;

    // Returns true when the caller should yield. It never authorizes a native
    // restart or a fabricated return after execution has been observed.
    bool observe(const QbdiExecutionState &state) noexcept;

private:
    QbdiExecutionState previous_{};
    size_t repeated_ = 0;
    bool observed_ = false;
};
