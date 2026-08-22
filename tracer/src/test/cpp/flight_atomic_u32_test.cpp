#include "flight/flight_atomic_u32.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void atomic_u32_preserves_load_store_fetch_or_and_compare_exchange() {
    alignas(kFlightAtomicU32Alignment) uint32_t value = 0;

    flight_atomic_u32_store(&value, 0x10203040U, std::memory_order_release);
    CHECK(flight_atomic_u32_load(&value, std::memory_order_acquire) == 0x10203040U);
    CHECK(flight_atomic_u32_fetch_or(&value, 0x0000000fU,
                                     std::memory_order_acq_rel) == 0x10203040U);
    CHECK(flight_atomic_u32_load(&value, std::memory_order_relaxed) == 0x1020304fU);

    uint32_t expected = 0xaaaaaaaaU;
    CHECK(!flight_atomic_u32_compare_exchange_strong(
            &value, &expected, 7U, std::memory_order_acq_rel,
            std::memory_order_acquire));
    CHECK(expected == 0x1020304fU);
    CHECK(flight_atomic_u32_compare_exchange_strong(
            &value, &expected, 7U, std::memory_order_acq_rel,
            std::memory_order_acquire));
    CHECK(flight_atomic_u32_load(&value, std::memory_order_relaxed) == 7U);
}

void release_store_and_acquire_load_publish_prior_writes() {
    alignas(kFlightAtomicU32Alignment) uint32_t published = 0;
    uint32_t payload = 0;

    std::thread producer([&] {
        payload = 0xdecafbadU;
        flight_atomic_u32_store(&published, 1U, std::memory_order_release);
    });
    while (flight_atomic_u32_load(&published, std::memory_order_acquire) == 0) {
    }
    CHECK(payload == 0xdecafbadU);
    producer.join();
}

} // namespace

int main() {
    atomic_u32_preserves_load_store_fetch_or_and_compare_exchange();
    release_store_and_acquire_load_publish_prior_writes();
}
