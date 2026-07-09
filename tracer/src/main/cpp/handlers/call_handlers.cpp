#include "handlers/call_handlers.h"
#include "core/safe_memory.h"

#include <dlfcn.h>
#include <sstream>
#include <unordered_map>

static std::unordered_map<uintptr_t, const char *> libc_targets() {
    void *libc = dlopen("libc.so", RTLD_NOW);
    std::unordered_map<uintptr_t, const char *> result;
    const char *names[] = {"strlen", "memcpy", "memcmp", "access", "fopen", "__system_property_get"};
    for (const char *name : names) {
        void *addr = libc != nullptr ? dlsym(libc, name) : nullptr;
        if (addr != nullptr) result.emplace(reinterpret_cast<uintptr_t>(addr), name);
    }
    return result;
}

void emit_possible_external_call(QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer) {
    static std::unordered_map<uintptr_t, const char *> libc = libc_targets();
    if (writer == nullptr || state == nullptr) return;
    auto libc_it = libc.find(target);
    if (libc_it != libc.end()) {
        std::ostringstream detail;
        uintptr_t x0 = QBDI_GPR_GET(state, 0);
        detail << "x0=0x" << std::hex << x0 << " preview=\"" << preview_c_string(x0) << "\"";
        writer->call("libc", libc_it->second, detail.str());
    }
}
