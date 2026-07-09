#include "integrity.h"

#include "demo_scenes.h"

#include <android/log.h>

#include <array>
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace {

constexpr char kLogTag[] = "QBDI-DemoTarget";
constexpr size_t kTextSampleSize = 64;
constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

std::atomic<uint64_t> g_text_baseline{0};

uint64_t fnv1a64(const uint8_t *bytes, size_t size) {
    uint64_t hash = kFnvOffset;
    for (size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= kFnvPrime;
    }
    return hash;
}

uint64_t current_text_hash() {
    const auto *bytes = reinterpret_cast<const uint8_t *>(reinterpret_cast<const void *>(&demo_algorithm_case));
    return fnv1a64(bytes, kTextSampleSize);
}

bool contains_suspicious_name(std::string_view line) {
    constexpr std::array<std::string_view, 4> suspicious{
        "frida",
        "gum-js-loop",
        "libqbdi_tracer",
        "libQBDI",
    };

    for (const std::string_view marker : suspicious) {
        if (line.find(marker) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

bool is_demo_target_rx_map(std::string_view line) {
    if (line.find("libdemo_target.so") == std::string_view::npos) {
        return false;
    }

    const size_t space = line.find(' ');
    if (space == std::string_view::npos || space + 5U > line.size()) {
        return false;
    }

    const std::string_view perms = line.substr(space + 1U, 4U);
    return perms.size() == 4U && perms[0] == 'r' && perms[2] == 'x';
}

} // namespace

extern "C" void integrity_capture_baseline() {
    const uint64_t hash = current_text_hash();
    g_text_baseline.store(hash, std::memory_order_release);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "captured text baseline=0x%016" PRIx64, hash);
}

extern "C" bool integrity_text_check() {
    const uint64_t expected = g_text_baseline.load(std::memory_order_acquire);
    const uint64_t actual = current_text_hash();
    const bool ok = expected != 0U && expected == actual;
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, kLogTag,
                        "text integrity expected=0x%016" PRIx64 " actual=0x%016" PRIx64,
                        expected, actual);
    return ok;
}

extern "C" bool integrity_maps_check() {
    FILE *maps = std::fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "failed to open /proc/self/maps");
        return false;
    }

    bool found_demo_rx = false;
    bool suspicious = false;
    char line[512]{};

    while (std::fgets(line, sizeof(line), maps) != nullptr) {
        const std::string_view view(line, std::strlen(line));
        found_demo_rx = found_demo_rx || is_demo_target_rx_map(view);
        if (contains_suspicious_name(view)) {
            suspicious = true;
            __android_log_print(ANDROID_LOG_ERROR, kLogTag, "suspicious maps entry: %s", line);
        }
    }

    std::fclose(maps);

    const bool ok = found_demo_rx && !suspicious;
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, kLogTag,
                        "maps integrity demo_rx=%d suspicious=%d",
                        found_demo_rx ? 1 : 0, suspicious ? 1 : 0);
    return ok;
}

extern "C" void integrity_crash() {
    __android_log_print(ANDROID_LOG_FATAL, kLogTag, "integrity violation; crashing intentionally");
    volatile int *crash = nullptr;
    *crash = 0x51;
}
