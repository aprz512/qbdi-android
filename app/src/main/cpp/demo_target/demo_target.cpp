#include "demo_scenes.h"
#include "integrity.h"

#include <jni.h>

#include <array>
#include <bit>
#include <cstdint>
#include <sstream>
#include <string>

namespace {

jstring to_jstring(JNIEnv *env, const std::string &value) {
    return env->NewStringUTF(value.c_str());
}

static jstring native_run_jni_case(JNIEnv *env, jobject thiz) {
    return to_jstring(env, demo_jni_case(env, thiz));
}

static jstring native_run_libc_case(JNIEnv *env, jobject /* thiz */) {
    return to_jstring(env, demo_libc_case());
}

static jstring native_run_algorithm_case(JNIEnv *env, jobject /* thiz */) {
    constexpr std::array<uint8_t, 24> data{
        0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
        0x6d, 0x2d, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x2d,
        0x71, 0x62, 0x64, 0x69, 0x2d, 0x32, 0x30, 0x32,
    };
    const uint64_t hash = demo_algorithm_case(data.data(), data.size());

    std::ostringstream summary;
    summary << "algorithm: size=" << data.size() << ", hash=0x" << std::hex << hash;
    return to_jstring(env, summary.str());
}

static jstring native_run_integrity_case(JNIEnv *env, jobject /* thiz */) {
    return to_jstring(env, demo_integrity_case());
}

static jstring native_run_benchmark_case(JNIEnv *env, jobject /* thiz */) {
    constexpr uint64_t kIterations = 256;
    constexpr uint64_t kSeed = 0x514244492d626173ULL;
    const uint64_t result = demo_benchmark_case(kIterations, kSeed);
    std::ostringstream summary;
    summary << "benchmark: iterations=" << kIterations << ", result=0x" << std::hex << result;
    return to_jstring(env, summary.str());
}

static jlong native_run_timed_acceptance(JNIEnv *, jobject, jlong iterations, jlong seed) {
    static_assert(sizeof(jlong) == sizeof(uint64_t));
    const uint64_t value = demo_timed_acceptance_case(
        static_cast<uint64_t>(iterations), static_cast<uint64_t>(seed));
    return std::bit_cast<jlong>(value);
}

static jlong native_get_last_timed_acceptance_entry_monotonic_ns(JNIEnv *, jobject) {
    static_assert(sizeof(jlong) == sizeof(uint64_t));
    return std::bit_cast<jlong>(demo_timed_acceptance_entry_monotonic_ns());
}

static jlong native_run_flight_acceptance(JNIEnv *, jobject, jlong seed, jint mode,
                                          jint selected_worker) {
    return static_cast<jlong>(demo_flight_acceptance_case(
        static_cast<uint64_t>(seed), static_cast<uint32_t>(mode),
        static_cast<uint32_t>(selected_worker)));
}

JNINativeMethod kNativeMethods[] = {
    {const_cast<char *>("runJniCase"), const_cast<char *>("()Ljava/lang/String;"),
     reinterpret_cast<void *>(native_run_jni_case)},
    {const_cast<char *>("runLibcCase"), const_cast<char *>("()Ljava/lang/String;"),
     reinterpret_cast<void *>(native_run_libc_case)},
    {const_cast<char *>("runAlgorithmCase"), const_cast<char *>("()Ljava/lang/String;"),
     reinterpret_cast<void *>(native_run_algorithm_case)},
    {const_cast<char *>("runIntegrityCase"), const_cast<char *>("()Ljava/lang/String;"),
     reinterpret_cast<void *>(native_run_integrity_case)},
    {const_cast<char *>("runBenchmarkCase"), const_cast<char *>("()Ljava/lang/String;"),
     reinterpret_cast<void *>(native_run_benchmark_case)},
    {const_cast<char *>("runTimedAcceptance"), const_cast<char *>("(JJ)J"),
     reinterpret_cast<void *>(native_run_timed_acceptance)},
    {const_cast<char *>("getLastTimedAcceptanceEntryMonotonicNs"),
     const_cast<char *>("()J"),
     reinterpret_cast<void *>(native_get_last_timed_acceptance_entry_monotonic_ns)},
    {const_cast<char *>("runFlightAcceptance"), const_cast<char *>("(JII)J"),
     reinterpret_cast<void *>(native_run_flight_acceptance)},
};

__attribute__((constructor)) void native_constructor() {
    integrity_capture_baseline();
    demo_init_stage();
}

} // namespace

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void * /* reserved */) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    jclass native_demo_class = env->FindClass("com/aprz/qbdiandroid/NativeDemo");
    if (native_demo_class == nullptr) {
        return JNI_ERR;
    }

    const jint result = env->RegisterNatives(native_demo_class, kNativeMethods,
                                             static_cast<jint>(std::size(kNativeMethods)));
    env->DeleteLocalRef(native_demo_class);

    if (result != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
