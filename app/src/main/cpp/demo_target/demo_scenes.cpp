#include "demo_scenes.h"

#include "integrity.h"

#include <android/log.h>
#include <dlfcn.h>
#include <signal.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
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
constexpr uint64_t kArm64Getpid = 172U;
constexpr uint64_t kArm64Gettid = 178U;
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
alignas(uint32_t) uint32_t g_probe_pause_handler_once = 0;
alignas(uint32_t) uint32_t g_probe_pause_after_handler_once = 0;

#ifndef NDEBUG
constexpr uint32_t kAcceptanceWorkers = 16;
constexpr uint32_t kAcceptanceRotations = 5;
constexpr uint32_t kAcceptanceMutationIterations = 2048;
constexpr uint32_t kAcceptanceExternalSigkill = 4;

struct AcceptanceWorker {
    pthread_t thread{};
    uint32_t index = 0;
    uint64_t observed_epoch = 0;
    alignas(64) std::array<uint64_t, 1024> memory{};
};

std::array<AcceptanceWorker, kAcceptanceWorkers> g_acceptance_workers{};
std::atomic<uint64_t> g_acceptance_epoch{0};
std::atomic<uint64_t> g_acceptance_seed{0};
std::atomic<uint32_t> g_acceptance_mode{0};
std::atomic<uint32_t> g_acceptance_selected{0};
std::atomic<uint32_t> g_acceptance_ready{0};
std::atomic<uint32_t> g_acceptance_probe_bits{0};
std::array<std::atomic<uint32_t>, kAcceptanceWorkers> g_acceptance_tids{};
std::array<std::atomic<uint32_t>, kAcceptanceWorkers> g_acceptance_rotations{};
std::atomic<bool> g_acceptance_started{false};
FlightAcceptanceProtocol g_acceptance_protocol;

extern "C" const char demo_flight_direct_tgkill_pc[];
extern "C" const char demo_flight_exit_group_pc[];
extern "C" const char demo_flight_sync_fault_pc[];
extern "C" const char demo_flight_target_sigkill_pc[];
extern "C" [[noreturn]] void demo_flight_direct_tgkill(int pid, int tid);
extern "C" [[noreturn]] void demo_flight_exit_group();
extern "C" [[noreturn]] void demo_flight_sync_fault();
extern "C" [[noreturn]] void demo_flight_target_sigkill(int pid, int tid);

__asm__(
    ".text\n"
    ".align 2\n"
    ".global demo_flight_direct_tgkill\n"
    ".type demo_flight_direct_tgkill,%function\n"
    "demo_flight_direct_tgkill:\n"
    "mov x2, #6\n"
    "mov x8, #131\n"
    ".global demo_flight_direct_tgkill_pc\n"
    "demo_flight_direct_tgkill_pc:\n"
    "svc #0\n"
    "mov x8, #94\n"
    "svc #0\n"
    ".size demo_flight_direct_tgkill, .-demo_flight_direct_tgkill\n"
    ".global demo_flight_exit_group\n"
    ".type demo_flight_exit_group,%function\n"
    "demo_flight_exit_group:\n"
    "mov x0, #86\n"
    "mov x8, #94\n"
    ".global demo_flight_exit_group_pc\n"
    "demo_flight_exit_group_pc:\n"
    "svc #0\n"
    "brk #0\n"
    ".size demo_flight_exit_group, .-demo_flight_exit_group\n"
    ".global demo_flight_sync_fault\n"
    ".type demo_flight_sync_fault,%function\n"
    "demo_flight_sync_fault:\n"
    ".global demo_flight_sync_fault_pc\n"
    "mov x0, #0\n"
    "demo_flight_sync_fault_pc:\n"
    "str xzr, [x0]\n"
    "brk #0\n"
    ".size demo_flight_sync_fault, .-demo_flight_sync_fault\n"
    ".global demo_flight_target_sigkill\n"
    ".type demo_flight_target_sigkill,%function\n"
    "demo_flight_target_sigkill:\n"
    "mov x2, #9\n"
    "mov x8, #131\n"
    ".global demo_flight_target_sigkill_pc\n"
    "demo_flight_target_sigkill_pc:\n"
    "svc #0\n"
    "mov x8, #94\n"
    "svc #0\n"
    ".size demo_flight_target_sigkill, .-demo_flight_target_sigkill\n");

uint64_t acceptance_mix(uint64_t value) noexcept {
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

__attribute__((noinline)) uint32_t acceptance_mutate(AcceptanceWorker &worker,
                                                     uint64_t seed) noexcept {
    uint64_t state = acceptance_mix(seed ^ worker.index);
    uint32_t completed_rotations = 0;
    const useconds_t delay = static_cast<useconds_t>(500U + (state & 0x3fffU));
    usleep(delay);
    for (uint32_t rotation = 0; rotation < kAcceptanceRotations; ++rotation) {
        for (uint32_t iteration = 0; iteration < kAcceptanceMutationIterations; ++iteration) {
            const size_t slot = static_cast<size_t>((state + iteration) & 1023U);
            const uint64_t loaded = worker.memory[slot];
            state = acceptance_mix(state + loaded + iteration + rotation);
            worker.memory[slot] = state;
        }
        ++completed_rotations;
    }
    return completed_rotations;
}

uintptr_t acceptance_pc(uint32_t mode) noexcept {
    switch (mode) {
        case 0: return reinterpret_cast<uintptr_t>(demo_flight_direct_tgkill_pc);
        case 1: return reinterpret_cast<uintptr_t>(demo_flight_exit_group_pc);
        case 2: return reinterpret_cast<uintptr_t>(demo_flight_sync_fault_pc);
        case 3: return reinterpret_cast<uintptr_t>(demo_flight_target_sigkill_pc);
        default: return 0;
    }
}

uintptr_t target_offset(uintptr_t address) noexcept {
    Dl_info info{};
    return dladdr(reinterpret_cast<const void *>(address), &info) != 0 &&
                   info.dli_fbase != nullptr
           ? address - reinterpret_cast<uintptr_t>(info.dli_fbase)
           : 0;
}

[[noreturn]] void acceptance_terminate(uint32_t mode) noexcept {
    const int pid = getpid();
    const int tid = static_cast<int>(syscall(SYS_gettid));
    switch (mode) {
        case 0: demo_flight_direct_tgkill(pid, tid);
        case 1: demo_flight_exit_group();
        case 2: demo_flight_sync_fault();
        case 3: demo_flight_target_sigkill(pid, tid);
        default: demo_flight_exit_group();
    }
}

void *acceptance_worker(void *opaque) noexcept {
    auto &worker = *static_cast<AcceptanceWorker *>(opaque);
    for (;;) {
        const uint64_t epoch = g_acceptance_epoch.load(std::memory_order_acquire);
        if (epoch == 0 || epoch == worker.observed_epoch) {
            usleep(1000);
            continue;
        }
        worker.observed_epoch = epoch;
        const uint64_t seed = g_acceptance_seed.load(std::memory_order_relaxed);
        const uint32_t mode = g_acceptance_mode.load(std::memory_order_relaxed);
        const uint32_t selected = g_acceptance_selected.load(std::memory_order_relaxed);
        const uint32_t completed_rotations = acceptance_mutate(worker, seed);
        g_acceptance_rotations[worker.index].store(
            completed_rotations, std::memory_order_release);
        if (worker.index == selected) {
            g_acceptance_probe_bits.store(
                static_cast<uint32_t>(demo_signal_probe(seed ^ worker.index)),
                std::memory_order_release);
        }
        g_acceptance_tids[worker.index].store(
            static_cast<uint32_t>(syscall(SYS_gettid)), std::memory_order_release);
        const uint32_t ready =
            g_acceptance_ready.fetch_add(1, std::memory_order_acq_rel) + 1U;
        if (ready == kAcceptanceWorkers) {
            std::array<uint32_t, kAcceptanceWorkers> tids{};
            uint32_t minimum_rotations = UINT32_MAX;
            for (uint32_t index = 0; index < kAcceptanceWorkers; ++index) {
                tids[index] = g_acceptance_tids[index].load(std::memory_order_acquire);
                minimum_rotations = std::min(
                    minimum_rotations,
                    g_acceptance_rotations[index].load(std::memory_order_acquire));
            }
            const uint32_t selected_tid = mode == kAcceptanceExternalSigkill
                                              ? 0
                                              : tids[selected];
            (void)g_acceptance_protocol.publish_ready(
                epoch, selected_tid, target_offset(acceptance_pc(mode)),
                g_acceptance_probe_bits.load(std::memory_order_acquire),
                minimum_rotations,
                tids.data(), tids.size());
        }
        while (g_acceptance_ready.load(std::memory_order_acquire) < kAcceptanceWorkers) {
            usleep(1000);
        }
        if (mode == kAcceptanceExternalSigkill) continue;
        if (worker.index != selected) {
            while (g_acceptance_epoch.load(std::memory_order_acquire) == epoch) usleep(1000);
            continue;
        }
        while (!g_acceptance_protocol.released(epoch)) usleep(1000);
        usleep(250000);
        acceptance_terminate(mode);
    }
}
#endif

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

__attribute__((always_inline)) inline uint32_t
load_pause_flag(const uint32_t *flag) noexcept {
    uint32_t loaded = 0;
    __asm__ volatile("ldar %w0, [%1]"
                     : "=r"(loaded)
                     : "r"(flag)
                     : "memory");
    return loaded;
}

__attribute__((always_inline)) inline void
store_pause_flag(uint32_t *flag, uint32_t value) noexcept {
    __asm__ volatile("stlr %w0, [%1]"
                     :
                     : "r"(value), "r"(flag)
                     : "memory");
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
                     "svc 0\n"
                     "1:"
                     : "+r"(x0), "+r"(x19)
                     : "r"(x1), "r"(x2), "r"(x8),
                       [expected_pc] "r"(expected_pc)
                     : "x9", "memory", "cc");
    if (restored_cookie != nullptr) {
        *restored_cookie = x19;
    }
    return static_cast<long>(x0);
}

__attribute__((always_inline)) inline void raw_stop_self() noexcept {
    register uint64_t process_id __asm__("x0");
    register uint64_t syscall_number __asm__("x8") = kArm64Getpid;
    __asm__ volatile("svc 0"
                     : "=r"(process_id)
                     : "r"(syscall_number)
                     : "memory", "cc");
    const uint64_t saved_process_id = process_id;

    register uint64_t thread_id __asm__("x0");
    syscall_number = kArm64Gettid;
    __asm__ volatile("svc 0"
                     : "=r"(thread_id)
                     : "r"(syscall_number)
                     : "memory", "cc");

    register uint64_t signal_process_id __asm__("x0") = saved_process_id;
    register uint64_t signal_thread_id __asm__("x1") = thread_id;
    register uint64_t signal_number __asm__("x2") = SIGSTOP;
    syscall_number = kArm64Tgkill;
    __asm__ volatile("svc 0"
                     : "+r"(signal_process_id)
                     : "r"(signal_thread_id), "r"(signal_number),
                       "r"(syscall_number)
                     : "memory", "cc");
}

extern "C" __attribute__((visibility("default"))) void
demo_signal_probe_pause_handler_once() noexcept {
    store_pause_flag(&g_probe_pause_handler_once, 1);
    store_pause_flag(&g_probe_pause_after_handler_once, 1);
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
    if (load_pause_flag(&g_probe_pause_handler_once) != 0) {
        store_pause_flag(&g_probe_pause_handler_once, 0);
        raw_stop_self();
    }
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
#ifndef NDEBUG
    demo_flight_acceptance_init();
#endif
    const uint64_t hash = demo_algorithm_case(kInitSeed.data(), kInitSeed.size());
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "init stage hash=0x%016llx",
                        static_cast<unsigned long long>(hash));
    return hash;
}

extern "C" void demo_flight_acceptance_init() {
#ifndef NDEBUG
    bool expected = false;
    if (!g_acceptance_started.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return;
    }
    for (uint32_t index = 0; index < kAcceptanceWorkers; ++index) {
        g_acceptance_workers[index].index = index;
        const int result = pthread_create(&g_acceptance_workers[index].thread, nullptr,
                                          acceptance_worker,
                                          &g_acceptance_workers[index]);
        if (result != 0) {
            __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                                "acceptance pthread_create index=%u error=%d", index,
                                result);
        }
    }
#endif
}

extern "C" uint64_t demo_flight_acceptance_start(uint64_t seed, uint32_t mode,
                                                   uint32_t selected_worker) {
#ifndef NDEBUG
    if (!g_acceptance_started.load(std::memory_order_acquire)) return 0;
    const uint64_t generation =
        g_acceptance_protocol.start(seed, mode, selected_worker);
    if (generation == 0) return 0;
    g_acceptance_seed.store(seed, std::memory_order_relaxed);
    g_acceptance_mode.store(mode, std::memory_order_relaxed);
    g_acceptance_selected.store(selected_worker, std::memory_order_relaxed);
    g_acceptance_probe_bits.store(0, std::memory_order_relaxed);
    g_acceptance_ready.store(0, std::memory_order_relaxed);
    for (auto &rotations : g_acceptance_rotations) {
        rotations.store(0, std::memory_order_relaxed);
    }
    g_acceptance_epoch.store(generation, std::memory_order_release);
    return generation;
#else
    (void)seed;
    (void)mode;
    (void)selected_worker;
    return 0;
#endif
}

extern "C" int demo_flight_acceptance_snapshot(
        DemoFlightAcceptanceSnapshot *snapshot) {
#ifndef NDEBUG
    return g_acceptance_protocol.snapshot(snapshot) ? 1 : 0;
#else
    (void)snapshot;
    return 0;
#endif
}

extern "C" int demo_flight_acceptance_release(uint64_t generation) {
#ifndef NDEBUG
    return g_acceptance_protocol.release(generation) ? 1 : 0;
#else
    (void)generation;
    return 0;
#endif
}

extern "C" uint64_t demo_flight_acceptance_case(uint64_t seed, uint32_t mode,
                                                  uint32_t selected_worker) {
#ifndef NDEBUG
    const uint64_t generation =
        demo_flight_acceptance_start(seed, mode, selected_worker);
    if (generation == 0) return 0;
    DemoFlightAcceptanceSnapshot snapshot{};
    while (demo_flight_acceptance_snapshot(&snapshot) == 0) {
        usleep(1000);
    }
    char tids[256]{};
    size_t used = 0;
    for (uint32_t index = 0; index < snapshot.worker_count; ++index) {
        const int written = std::snprintf(
            tids + used, sizeof(tids) - used, "%s%u", index == 0 ? "" : ",",
            snapshot.tids[index]);
        if (written <= 0 || static_cast<size_t>(written) >= sizeof(tids) - used) return 0;
        used += static_cast<size_t>(written);
    }
    constexpr const char *kModeNames[] = {
        "direct_tgkill", "exit_group", "sync_fault", "target_sigkill", "external_sigkill"
    };
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "QBDI_FLIGHT_WORKERS seed=%llu tids=%s rotations=%u",
                        static_cast<unsigned long long>(snapshot.seed), tids,
                        snapshot.rotations);
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "QBDI_FLIGHT_ORACLE seed=%llu mode=%s tid=%s pc=%s phase=ready probe=0x%x",
                        static_cast<unsigned long long>(snapshot.seed),
                        kModeNames[snapshot.mode],
                        snapshot.mode == kAcceptanceExternalSigkill ? "none" :
                            std::to_string(snapshot.selected_tid).c_str(),
                        snapshot.mode == kAcceptanceExternalSigkill ? "none" :
                            ("0x" + [&snapshot] { std::ostringstream value; value << std::hex << snapshot.original_pc; return value.str(); }()).c_str(),
                        snapshot.probe);
    if (demo_flight_acceptance_release(generation) == 0) return 0;
    for (;;) pause();
#else
    (void) seed;
    (void) mode;
    (void) selected_worker;
    return 0;
#endif
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
    if (load_pause_flag(&g_probe_pause_after_handler_once) != 0) {
        store_pause_flag(&g_probe_pause_after_handler_once, 0);
        // Normal post-handler code is outside signal context. Enter libc so
        // the stop syscall is native rather than another traced target SVC.
        (void)::raise(SIGSTOP);
    }

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
