#include "handlers/bypass_handlers.h"
#include "core/safe_memory.h"

#include <dlfcn.h>
#include <sstream>
#include <string>

static uintptr_t libc_symbol(const char *name) {
    void *handle = dlopen("libc.so", RTLD_NOW);
    void *symbol = handle != nullptr ? dlsym(handle, name) : nullptr;
    return reinterpret_cast<uintptr_t>(symbol);
}

static bool suspicious_needle(const std::string &needle) {
    return needle.find("frida") != std::string::npos ||
           needle.find("gum-js-loop") != std::string::npos ||
           needle.find("libqbdi_tracer") != std::string::npos ||
           needle.find("libQBDI") != std::string::npos ||
           needle.find("shadowhook") != std::string::npos;
}

void emit_scene_bypass_markers(const SceneConfig &scene, TextTraceWriter *writer) {
    if (writer == nullptr) return;
    if (scene.bypass_text) {
        writer->bypass("text_restore", "armed=true strategy=unhook_entry_before_qbdi_and_skip_text_memcmp");
    }
    if (scene.bypass_maps) {
        writer->bypass("maps_sanitize", "armed=true strategy=skip_suspicious_strstr_calls");
    }
}

BypassDecision maybe_bypass_external_call(const SceneConfig &scene, QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer) {
    static uintptr_t memcmp_addr = libc_symbol("memcmp");
    static uintptr_t strstr_addr = libc_symbol("strstr");
    static uintptr_t strcasestr_addr = libc_symbol("strcasestr");
    if (state == nullptr || writer == nullptr) return BypassDecision::Continue;

    if (scene.bypass_text && target == memcmp_addr) {
        uint64_t size = QBDI_GPR_GET(state, 2);
        if (size >= 16 && size <= 256) {
            QBDI_GPR_SET(state, 0, 0);
            std::ostringstream detail;
            detail << "target=memcmp size=" << std::dec << size << " forced_result=0";
            writer->bypass("text_hash_memcmp", detail.str());
            return BypassDecision::SkipInstruction;
        }
    }

    if (scene.bypass_maps && (target == strstr_addr || target == strcasestr_addr)) {
        uintptr_t needle_ptr = QBDI_GPR_GET(state, 1);
        std::string needle = preview_c_string(needle_ptr, 96);
        if (suspicious_needle(needle)) {
            QBDI_GPR_SET(state, 0, 0);
            writer->bypass("maps_sanitize", "needle=\"" + needle + "\" forced_result=null");
            return BypassDecision::SkipInstruction;
        }
    }

    return BypassDecision::Continue;
}
