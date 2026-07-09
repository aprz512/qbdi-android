#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <jni.h>

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

}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
