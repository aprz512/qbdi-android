#include "demo_scenes.h"

#include "integrity.h"

#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

namespace {

constexpr char kLogTag[] = "QBDI-DemoTarget";
constexpr std::array<uint8_t, 16> kInitSeed{
    0x51, 0x42, 0x44, 0x49, 0x2d, 0x41, 0x6e, 0x64,
    0x72, 0x6f, 0x69, 0x64, 0x2d, 0x64, 0x65, 0x6d,
};

std::string read_property(const char *name) {
    char value[PROP_VALUE_MAX]{};
    const int length = __system_property_get(name, value);
    if (length <= 0) {
        return "unknown";
    }
    return std::string(value, static_cast<size_t>(length));
}

__attribute__((noinline)) uint64_t benchmark_helper(uint64_t state) {
    state ^= state >> 29U;
    return state * 0x94d049bb133111ebULL;
}

} // namespace

extern "C" uint64_t demo_init_stage() {
    const uint64_t hash = demo_algorithm_case(kInitSeed.data(), kInitSeed.size());
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "init stage hash=0x%016llx",
                        static_cast<unsigned long long>(hash));
    return hash;
}

extern "C" std::string demo_jni_case(JNIEnv *env, jobject thiz) {
    if (env == nullptr || thiz == nullptr) {
        return "jni: invalid environment";
    }

    jclass object_class = env->GetObjectClass(thiz);
    if (object_class == nullptr) {
        return "jni: GetObjectClass failed";
    }

    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        env->DeleteLocalRef(object_class);
        return "jni: FindClass(java/lang/String) failed";
    }

    jmethodID length_method = env->GetMethodID(string_class, "length", "()I");
    if (length_method == nullptr) {
        env->DeleteLocalRef(string_class);
        env->DeleteLocalRef(object_class);
        return "jni: GetMethodID(String.length) failed";
    }

    jstring message = env->NewStringUTF("QBDI Android JNI scene");
    if (message == nullptr) {
        env->DeleteLocalRef(string_class);
        env->DeleteLocalRef(object_class);
        return "jni: NewStringUTF failed";
    }

    const char *chars = env->GetStringUTFChars(message, nullptr);
    if (chars == nullptr) {
        env->DeleteLocalRef(message);
        env->DeleteLocalRef(string_class);
        env->DeleteLocalRef(object_class);
        return "jni: GetStringUTFChars failed";
    }

    const jint length = env->CallIntMethod(message, length_method);
    const std::string text(chars);

    env->ReleaseStringUTFChars(message, chars);
    env->DeleteLocalRef(message);
    env->DeleteLocalRef(string_class);
    env->DeleteLocalRef(object_class);

    std::ostringstream summary;
    summary << "jni: class=NativeDemo, string='" << text << "', length=" << length;
    return summary.str();
}

extern "C" std::string demo_libc_case() {
    const char source[] = "QBDI libc scene";
    char copy[sizeof(source)]{};
    std::memcpy(copy, source, sizeof(source));

    const size_t length = std::strlen(copy);
    const int compare = std::memcmp(source, copy, sizeof(source));
    const int maps_access = access("/proc/self/maps", R_OK);
    const std::string sdk = read_property("ro.build.version.sdk");

    size_t maps_sample = 0;
    FILE *maps = std::fopen("/proc/self/maps", "re");
    if (maps != nullptr) {
        char line[256]{};
        if (std::fgets(line, sizeof(line), maps) != nullptr) {
            maps_sample = std::strlen(line);
        }
        std::fclose(maps);
    }

    std::ostringstream summary;
    summary << "libc: strlen=" << length
            << ", memcmp=" << compare
            << ", maps_access=" << maps_access
            << ", maps_sample=" << maps_sample
            << ", sdk=" << sdk;
    return summary.str();
}

extern "C" uint64_t demo_algorithm_case(const uint8_t *data, size_t size) {
    uint64_t state = 0x9e3779b185ebca87ULL ^ static_cast<uint64_t>(size);

    for (size_t index = 0; index < size; ++index) {
        const uint64_t value = data == nullptr ? 0U : data[index];
        state ^= value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
        state = (state << 13U) | (state >> 51U);
        state *= 0xff51afd7ed558ccdULL;
    }

    state ^= state >> 33U;
    state *= 0xc4ceb9fe1a85ec53ULL;
    state ^= state >> 29U;
    return state;
}

extern "C" uint64_t demo_benchmark_case(uint64_t iterations, uint64_t seed) {
    std::array<uint64_t, 512> working_set{};
    uint64_t state = seed ^ 0x9e3779b97f4a7c15ULL;

    for (uint64_t index = 0; index < iterations; ++index) {
        const size_t slot = static_cast<size_t>((state ^ index) & (working_set.size() - 1));
        const uint64_t loaded = working_set[slot];
        state ^= loaded + index + 0x9e3779b97f4a7c15ULL;
        state = (state << 17U) | (state >> 47U);
        if ((state & 1U) != 0U) {
            state ^= 0xff51afd7ed558ccdULL;
        } else {
            state += 0xc4ceb9fe1a85ec53ULL;
        }
        working_set[slot] = state;
        if ((index & 255U) == 255U) {
            state = benchmark_helper(state);
        }
    }

    return state ^ working_set[static_cast<size_t>(state & (working_set.size() - 1))];
}

extern "C" std::string demo_integrity_case() {
    if (!integrity_text_check()) {
        integrity_crash();
    }
    if (!integrity_maps_check()) {
        integrity_crash();
    }

    constexpr std::array<uint8_t, 8> data{0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74};
    const uint64_t hash = demo_algorithm_case(data.data(), data.size());

    std::ostringstream summary;
    summary << "integrity: text=ok, maps=ok, hash=0x" << std::hex << hash;
    return summary.str();
}
