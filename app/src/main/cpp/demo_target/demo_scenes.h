#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <jni.h>

#include "flight_acceptance_protocol.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type-c-linkage"
#endif

extern "C" {

__attribute__((visibility("hidden"))) uint64_t demo_init_stage();
__attribute__((visibility("hidden"))) std::string demo_jni_case(JNIEnv *env, jobject thiz);
__attribute__((visibility("hidden"))) std::string demo_libc_case();
__attribute__((visibility("hidden"))) uint64_t demo_algorithm_case(const uint8_t *data, size_t size);
__attribute__((visibility("hidden"))) std::string demo_integrity_case();
__attribute__((noinline, visibility("default"))) uint64_t demo_benchmark_case(uint64_t iterations,
                                                                                 uint64_t seed);
__attribute__((noinline, visibility("default"))) uint64_t
demo_timed_acceptance_case(uint64_t iterations, uint64_t seed) noexcept;
__attribute__((noinline, visibility("default"))) uint64_t
demo_signal_probe(uint64_t cookie);
__attribute__((visibility("hidden"))) void demo_flight_acceptance_init();
__attribute__((visibility("default"))) uint64_t
demo_flight_acceptance_start(uint64_t seed, uint32_t mode, uint32_t selected_worker);
__attribute__((visibility("default"))) int
demo_flight_acceptance_snapshot(DemoFlightAcceptanceSnapshot *snapshot);
__attribute__((visibility("default"))) int
demo_flight_acceptance_release(uint64_t generation);
__attribute__((noinline, visibility("default"))) uint64_t
demo_flight_acceptance_case(uint64_t seed, uint32_t mode, uint32_t selected_worker);
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
