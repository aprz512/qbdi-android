#include "demo_scenes.h"

#include "integrity.h"

#include <android/log.h>
#include <signal.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <atomic>
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

constexpr uint64_t kSignalProbeGuestCalled = 1U << 0U;
constexpr uint64_t kSignalProbeGuestPcOriginal = 1U << 1U;
constexpr uint64_t kSignalProbeRegisterCookie = 1U << 2U;
constexpr uint64_t kSignalProbeHandlerQueryHidden = 1U << 4U;
constexpr uint64_t kArm64RtSigaction = 134U;
constexpr uint64_t kArm64Tgkill = 131U;
constexpr size_t kKernelSignalSetBytes = 8U;
constexpr uint64_t kSignalProbeCookieRestoreMask = 0xa5a55a5af0f00f0fULL;

struct KernelSigaction {
    void (*handler)(int, siginfo_t *, void *) = nullptr;
    uint64_t flags = 0;
    void (*restorer)() = nullptr;
    uint64_t mask = 0;
};

volatile sig_atomic_t g_probe_handler_called = 0;
volatile sig_atomic_t g_probe_pc_original = 0;
volatile sig_atomic_t g_probe_register_cookie = 0;
std::atomic<uint64_t> g_probe_expected_pc{0};
std::atomic<uint64_t> g_probe_expected_cookie{0};

static_assert(std::atomic<uint64_t>::is_always_lock_free);
static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t));

__attribute__((always_inline)) inline uint64_t
load_published_signal_value(const std::atomic<uint64_t> &value) noexcept {
    uint64_t loaded = 0;
    __asm__ volatile("ldar %0, [%1]"
                     : "=r"(loaded)
                     : "r"(&value)
                     : "memory");
    return loaded;
}

long raw_rt_sigaction(int signal_number, const KernelSigaction *action,
                      KernelSigaction *old_action) noexcept {
    register uint64_t x0 __asm__("x0") = static_cast<uint64_t>(signal_number);
    register uint64_t x1 __asm__("x1") = reinterpret_cast<uintptr_t>(action);
    register uint64_t x2 __asm__("x2") = reinterpret_cast<uintptr_t>(old_action);
    register uint64_t x3 __asm__("x3") = kKernelSignalSetBytes;
    register uint64_t x8 __asm__("x8") = kArm64RtSigaction;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return static_cast<long>(x0);
}

long raw_tgkill_with_cookie(int process_id, int thread_id, int signal_number,
                            uint64_t cookie,
                            uint64_t *restored_cookie) noexcept {
    register uint64_t x0 __asm__("x0") = static_cast<uint64_t>(process_id);
    register uint64_t x1 __asm__("x1") = static_cast<uint64_t>(thread_id);
    register uint64_t x2 __asm__("x2") = static_cast<uint64_t>(signal_number);
    register uint64_t x8 __asm__("x8") = kArm64Tgkill;
    register uint64_t x19 __asm__("x19") = cookie;
    std::atomic<uint64_t> *expected_pc = &g_probe_expected_pc;
    __asm__ volatile("adr x9, 1f\n"
                     "stlr x9, [%[expected_pc]]\n"
                     "1: svc 0"
                     : "+r"(x0), "+r"(x19)
                     : "r"(x1), "r"(x2), "r"(x8),
                       [expected_pc] "r"(expected_pc)
                     : "x9", "memory", "cc");
    if (restored_cookie != nullptr) {
        *restored_cookie = x19;
    }
    return static_cast<long>(x0);
}

extern "C" __attribute__((noinline)) void
demo_signal_probe_handler(int signal_number, siginfo_t *,
                          void *opaque_context) {
    auto *context = static_cast<ucontext_t *>(opaque_context);
    g_probe_handler_called = signal_number == SIGUSR2;
    g_probe_pc_original = context->uc_mcontext.pc ==
                          load_published_signal_value(g_probe_expected_pc);
    g_probe_register_cookie =
        context->uc_mcontext.regs[19] ==
        load_published_signal_value(g_probe_expected_cookie);
    context->uc_mcontext.regs[19] ^= kSignalProbeCookieRestoreMask;
}

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

extern "C" uint64_t demo_signal_probe(uint64_t cookie) {
    g_probe_handler_called = 0;
    g_probe_pc_original = 0;
    g_probe_register_cookie = 0;
    g_probe_expected_pc.store(0, std::memory_order_relaxed);
    g_probe_expected_cookie.store(cookie, std::memory_order_release);

    KernelSigaction guest_action{};
    guest_action.handler = demo_signal_probe_handler;
    guest_action.flags = SA_SIGINFO;
    if (raw_rt_sigaction(SIGUSR2, &guest_action, nullptr) != 0) {
        return 0;
    }

    uint64_t restored_cookie = 0;
    (void)raw_tgkill_with_cookie(getpid(), gettid(), SIGUSR2, cookie,
                                 &restored_cookie);

    KernelSigaction visible_action{};
    const bool handler_query_hidden =
        raw_rt_sigaction(SIGUSR2, nullptr, &visible_action) == 0 &&
        visible_action.handler == demo_signal_probe_handler &&
        visible_action.flags == static_cast<uint64_t>(SA_SIGINFO);

    uint64_t result = 0;
    if (g_probe_handler_called != 0) {
        result |= kSignalProbeGuestCalled;
    }
    if (g_probe_pc_original != 0) {
        result |= kSignalProbeGuestPcOriginal;
    }
    if (g_probe_register_cookie != 0 &&
        restored_cookie == (cookie ^ kSignalProbeCookieRestoreMask)) {
        result |= kSignalProbeRegisterCookie;
    }
    if (handler_query_hidden) {
        result |= kSignalProbeHandlerQueryHidden;
    }
    return result;
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
