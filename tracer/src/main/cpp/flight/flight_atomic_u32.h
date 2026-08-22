#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

constexpr size_t kFlightAtomicU32Alignment = alignof(uint32_t);

static_assert(sizeof(uint32_t) == 4,
              "flight publication requires 4-byte uint32_t");
static_assert(kFlightAtomicU32Alignment == 4,
              "flight publication requires 4-byte uint32_t alignment");
static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr),
              "flight publication requires always-lock-free 32-bit atomics");

constexpr int flight_atomic_builtin_order(std::memory_order order) noexcept {
    switch (order) {
        case std::memory_order_relaxed:
            return __ATOMIC_RELAXED;
        case std::memory_order_consume:
            return __ATOMIC_CONSUME;
        case std::memory_order_acquire:
            return __ATOMIC_ACQUIRE;
        case std::memory_order_release:
            return __ATOMIC_RELEASE;
        case std::memory_order_acq_rel:
            return __ATOMIC_ACQ_REL;
        case std::memory_order_seq_cst:
            return __ATOMIC_SEQ_CST;
    }
    return __ATOMIC_SEQ_CST;
}

inline void flight_atomic_u32_store(uint32_t *destination, uint32_t value,
                                    std::memory_order order) noexcept {
    __atomic_store_n(destination, value, flight_atomic_builtin_order(order));
}

inline uint32_t flight_atomic_u32_load(const uint32_t *source,
                                       std::memory_order order) noexcept {
    return __atomic_load_n(source, flight_atomic_builtin_order(order));
}

inline uint32_t flight_atomic_u32_fetch_or(uint32_t *destination, uint32_t value,
                                           std::memory_order order) noexcept {
    return __atomic_fetch_or(destination, value, flight_atomic_builtin_order(order));
}

inline uint32_t flight_atomic_u32_fetch_and(uint32_t *destination, uint32_t value,
                                            std::memory_order order) noexcept {
    return __atomic_fetch_and(destination, value,
                              flight_atomic_builtin_order(order));
}

inline bool flight_atomic_u32_compare_exchange_strong(
        uint32_t *destination, uint32_t *expected, uint32_t desired,
        std::memory_order success, std::memory_order failure) noexcept {
    return __atomic_compare_exchange_n(
            destination, expected, desired, false,
            flight_atomic_builtin_order(success),
            flight_atomic_builtin_order(failure));
}

inline bool flight_atomic_u32_compare_exchange_weak(
        uint32_t *destination, uint32_t *expected, uint32_t desired,
        std::memory_order success, std::memory_order failure) noexcept {
    return __atomic_compare_exchange_n(
            destination, expected, desired, true,
            flight_atomic_builtin_order(success),
            flight_atomic_builtin_order(failure));
}
