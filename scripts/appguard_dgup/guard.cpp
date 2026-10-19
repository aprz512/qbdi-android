// DIGIMON UP 1.5.0 (55), arm64 only. See docs/research/2026-10-19-appguard-dgup.md.
#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdio>
#include <cstdint>
#include <cstring>

namespace {
constexpr const char *kTag = "QGUARD-PROBE";
constexpr const char *kPackage = "com.bandainamcoent.dgup_ww";
constexpr uintptr_t kReportOffset = 0x146c88;
constexpr uintptr_t kTerminationOffset = 0xc6114;
constexpr size_t kEngineSize = 0x184000;
constexpr unsigned char kMagic[] = {0x03, 0x25, 0x64, 0, 0, 0, 0, 0};
constexpr unsigned char kReportEntry[] = {
    0xfd, 0x7b, 0xba, 0xa9, 0xfc, 0x6f, 0x01, 0xa9,
    0xfa, 0x67, 0x02, 0xa9, 0xf8, 0x5f, 0x03, 0xa9};
constexpr unsigned char kTerminationEntry[] = {
    0xff, 0x03, 0x03, 0xd1, 0xfd, 0x7b, 0x0a, 0xa9,
    0xf4, 0x4f, 0x0b, 0xa9, 0xfd, 0x83, 0x02, 0x91};
constexpr uint32_t kJump[] = {0x58000050, 0xd61f0200}; // ldr x16, +8; br x16

using Report = int (*)(JNIEnv *, jobject, jint, jint, const void *, size_t);
Report original_report = nullptr;
pid_t owner = 0;
int selected_mode = 0;
int started = 0;
using InstallRegion = int (*)(const char *, uintptr_t, uintptr_t);
InstallRegion install_region = nullptr;

int report(JNIEnv *env, jobject engine, jint type, jint code,
           const void *data, size_t length) {
    if (getpid() == owner) {
        char hex[1025]{};
        size_t captured = data ? (length < 512 ? length : 512) : 0;
        const auto *bytes = static_cast<const unsigned char *>(data);
        for (size_t i = 0; i < captured; ++i) {
            snprintf(hex + i * 2, 3, "%02x", bytes[i]);
        }
        __android_log_print(ANDROID_LOG_INFO, kTag,
            "native-report type=%d code=%d size=%zu hex=%s", type, code, length, hex);
        const bool root = code == 34 && selected_mode != 5;
        const bool usb = code == 38 && (selected_mode == 8 || selected_mode == 13);
        if (type == 2 && (root || usb)) {
            __android_log_print(ANDROID_LOG_INFO, kTag,
                "blocked native policy report code=%d; return=1", code);
            return 1;
        }
    }
    return original_report(env, engine, type, code, data, length);
}

void *termination_worker(void *) {
    __android_log_print(ANDROID_LOG_INFO, kTag,
        "blocked delayed native termination worker +0xc6114");
    return nullptr;
}

void write_jump(unsigned char *entry, uintptr_t destination) {
    // Install only during startup, before either target is called. These are
    // version-checked, already writable anonymous mappings. This is not a
    // concurrent hot-patching API or a general ARM64 instruction relocator.
    memcpy(entry + 8, &destination, 8);
    memcpy(entry + 4, kJump + 1, 4);
    __atomic_store_n(reinterpret_cast<uint32_t *>(entry), kJump[0], __ATOMIC_RELEASE);
    __builtin___clear_cache(reinterpret_cast<char *>(entry),
                            reinterpret_cast<char *>(entry + 16));
}

bool install(uintptr_t base) {
    if (selected_mode == 14 || selected_mode == 15) {
        // Ordinary QBDI scenes temporarily unhook their entry. Two termination
        // workers can start concurrently; mode 14 keeps a persistent native
        // guard for that entry. Mode 15 reproduces the QBDI-only coverage gap.
        if (selected_mode == 14) {
            write_jump(reinterpret_cast<unsigned char *>(base + kTerminationOffset),
                       reinterpret_cast<uintptr_t>(termination_worker));
        }
        const int result = install_region("appguard-runtime.so", base, kEngineSize);
        __android_log_print(ANDROID_LOG_INFO, kTag,
            "QBDI region registration engine=%p result=%d mode=%d",
            reinterpret_cast<void *>(base), result, selected_mode);
        return result == 0; // Native JSON status must additionally say installed.
    }
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return false;
    auto *trampoline = static_cast<unsigned char *>(mmap(nullptr, page_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (trampoline == MAP_FAILED) return false;
    // The four copied instructions are SP-relative register stores, with no
    // PC-relative operand. Both entry signatures are verified before any write.
    memcpy(trampoline, kReportEntry, 16);
    memcpy(trampoline + 16, kJump, 8);
    uintptr_t resume = base + kReportOffset + 16;
    memcpy(trampoline + 24, &resume, 8);
    __builtin___clear_cache(reinterpret_cast<char *>(trampoline),
                            reinterpret_cast<char *>(trampoline + 32));
    original_report = reinterpret_cast<Report>(trampoline);
    if (selected_mode == 13) {
        write_jump(reinterpret_cast<unsigned char *>(base + kTerminationOffset),
                   reinterpret_cast<uintptr_t>(termination_worker));
    }
    write_jump(reinterpret_cast<unsigned char *>(base + kReportOffset),
               reinterpret_cast<uintptr_t>(report));
    __android_log_print(ANDROID_LOG_INFO, kTag,
        "installed engine=%p report=+0x146c88 termination=%s mode=%d",
        reinterpret_cast<void *>(base), selected_mode == 13 ? "+0xc6114" : "observe", selected_mode);
    return true;
}

void *wait_for_engine(void *) {
    // The mapping appears before all code has been decrypted. Wait for both
    // signatures rather than treating mapping creation as decryption completion.
    for (int attempt = 0; attempt < 2000 && getpid() == owner; ++attempt) {
        FILE *maps = fopen("/proc/self/maps", "re");
        if (!maps) break;
        char line[2048];
        while (fgets(line, sizeof(line), maps)) {
            unsigned long first = 0, last = 0;
            char permissions[8]{};
            int path = 0;
            if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %n",
                       &first, &last, permissions, &path) != 3) continue;
            if (last - first != kEngineSize || strncmp(permissions, "rwx", 3)) continue;
            if (line[path] && line[path] != '\n') continue;
            const auto *base = reinterpret_cast<const unsigned char *>(first);
            if (memcmp(base, kMagic, sizeof(kMagic)) ||
                memcmp(base + kReportOffset, kReportEntry, sizeof(kReportEntry)) ||
                memcmp(base + kTerminationOffset, kTerminationEntry, sizeof(kTerminationEntry))) continue;
            bool ok = install(first);
            fclose(maps);
            if (!ok) __android_log_print(ANDROID_LOG_ERROR, kTag, "policy/trace installation failed");
            return nullptr;
        }
        fclose(maps);
        usleep(5000);
    }
    __android_log_print(ANDROID_LOG_ERROR, kTag,
        "unsupported or undecrypted engine: no matching signatures within 10 seconds");
    return nullptr;
}
} // namespace

extern "C" __attribute__((visibility("default")))
int qguard_probe_start(const char *tracer_path, int mode) {
    if (mode != 5 && mode != 6 && mode != 8 && mode != 13 && mode != 14 && mode != 15) return -1;
    char command[128]{};
    FILE *cmdline = fopen("/proc/self/cmdline", "re");
    if (!cmdline) return -2;
    const size_t read = fread(command, 1, sizeof(command) - 1, cmdline);
    fclose(cmdline);
    if (read == 0 || strcmp(command, kPackage)) return -3;
    if (mode == 14 || mode == 15) {
        if (tracer_path == nullptr) return -6;
        void *tracer = dlopen(tracer_path, RTLD_NOW | RTLD_NOLOAD);
        if (tracer == nullptr) return -6;
        install_region = reinterpret_cast<InstallRegion>(dlsym(tracer, "qbdi_tracer_install_region"));
        if (install_region == nullptr) return -6;
    }
    if (__atomic_exchange_n(&started, 1, __ATOMIC_ACQ_REL)) return -4;
    owner = getpid();
    selected_mode = mode;
    pthread_t worker{};
    if (pthread_create(&worker, nullptr, wait_for_engine, nullptr)) return -5;
    pthread_detach(worker);
    __android_log_print(ANDROID_LOG_INFO, kTag, "native policy pending pid=%d mode=%d", owner, mode);
    return 0; // Pending; the log's "installed" receipt is the installation proof.
}
