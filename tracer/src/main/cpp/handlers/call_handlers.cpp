#include "handlers/call_handlers.h"

#include "core/module_maps.h"
#include "core/safe_memory.h"

#include <QBDI/State.h>
#include <dlfcn.h>

#include <array>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

namespace {
    struct JniSlot {
        size_t index;
        const char *name;
    };

    const std::array<JniSlot, 10> kJniSlots{{
                                                    {6, "FindClass"},
                                                    {33, "NewStringUTF"},
                                                    {64, "GetMethodID"},
                                                    {67, "CallIntMethod"},
                                                    {169, "GetObjectClass"},
                                                    {215, "GetStringUTFChars"},
                                                    {216, "ReleaseStringUTFChars"},
                                                    {23, "DeleteLocalRef"},
                                                    {167, "RegisterNatives"},
                                                    {168, "UnregisterNatives"},
                                            }};

    std::unordered_map<uintptr_t, const char *> known_libc_symbols() {
        void *libc = dlopen("libc.so", RTLD_NOW);
        std::unordered_map<uintptr_t, const char *> result;
        const char *names[] = {
                "strlen",
                "memcpy",
                "memcmp",
                "access",
                "fopen",
                "fgets",
                "fclose",
                "strstr",
                "strcasestr",
                "__system_property_get",
        };
        for (const char *name: names) {
            void *addr = libc != nullptr ? dlsym(libc, name) : nullptr;
            if (addr != nullptr) result.emplace(reinterpret_cast<uintptr_t>(addr), name);
        }
        return result;
    }

    const char *known_libc_name(uintptr_t address) {
        static std::unordered_map<uintptr_t, const char *> symbols = known_libc_symbols();
        auto it = symbols.find(address);
        return it != symbols.end() ? it->second : nullptr;
    }

    const char *jni_name_from_env(uintptr_t env, uintptr_t target) {
        uintptr_t table = 0;
        if (!safe_read_memory(env, &table, sizeof(table))) return nullptr;
        if (table == 0) return nullptr;

        for (const JniSlot &slot: kJniSlots) {
            uintptr_t candidate = 0;
            if (!safe_read_memory(table + slot.index * sizeof(uintptr_t), &candidate,
                                  sizeof(candidate)))
                continue;
            if (candidate == target) return slot.name;
        }
        return nullptr;
    }

    std::string symbol_name(uintptr_t target, const Dl_info &info) {
        const char *known = known_libc_name(target);
        if (known != nullptr) return known;
        if (info.dli_sname != nullptr) return info.dli_sname;
        std::ostringstream fallback;
        fallback << "0x" << std::hex << target;
        return fallback.str();
    }

    std::string module_name(const Dl_info &info) {
        if (info.dli_fname == nullptr) return "<unknown>";
        return basename_of(info.dli_fname);
    }

    PendingExecTransfer
    emit_call(uintptr_t target, QBDI::GPRState *state, TextTraceWriter *writer) {
        PendingExecTransfer pending;
        pending.target = target;
        if (state == nullptr || writer == nullptr) return pending;

        Dl_info info{};
        dladdr(reinterpret_cast<void *>(target), &info);

        if (const char *jni_name = jni_name_from_env(QBDI_GPR_GET(state, 0), target)) {
            std::ostringstream detail;
            detail << "target=0x" << std::hex << target;
            if (std::string(jni_name) == "FindClass") detail << " name=\"" << preview_c_string(
                        QBDI_GPR_GET(state, 1)) << "\"";
            if (std::string(jni_name) == "NewStringUTF") detail << " value=\"" << preview_c_string(
                        QBDI_GPR_GET(state, 1)) << "\"";
            writer->call("jni", jni_name, detail.str());
            pending.category = "jni";
            pending.name = jni_name;
            return pending;
        }

        const std::string module = module_name(info);
        const std::string name = symbol_name(target, info);

        if (module == "libc.so" || known_libc_name(target) != nullptr) {
            std::ostringstream detail;
            detail << "target=0x" << std::hex << target << " x0=0x" << QBDI_GPR_GET(state, 0)
                   << " preview=\"" << preview_c_string(QBDI_GPR_GET(state, 0)) << "\"";
            writer->call("libc", name, detail.str());
            pending.category = "libc";
            pending.name = name;
            return pending;
        }

        if (module == "libart.so") {
            std::ostringstream detail;
            detail << "target=0x" << std::hex << target << " module=" << module;
            writer->call("art", name, detail.str());
            pending.category = "art";
            pending.name = name;
        }

        return pending;
    }

    void emit_return(const PendingExecTransfer &pending, QBDI::GPRState *state,
                     TextTraceWriter *writer) {
        if (state == nullptr || writer == nullptr || pending.name.empty()) return;
        std::ostringstream detail;
        detail << pending.category << "." << pending.name << " target=0x" << std::hex
               << pending.target
               << " ret=0x" << QBDI_GPR_GET(state, 0);
        writer->call("return", pending.name, detail.str());
    }
}

void emit_exec_transfer_event(ExecTransferMonitor *monitor, const QBDI::VMState *vm_state,
                              QBDI::GPRState *state, TextTraceWriter *writer) {
    if (monitor == nullptr || vm_state == nullptr || state == nullptr || writer == nullptr) return;

    uintptr_t target = state->pc;
    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        PendingExecTransfer pending = emit_call(target, state, writer);
        if (!pending.name.empty()) monitor->pending.push_back(std::move(pending));
    }
    if ((vm_state->event & QBDI::EXEC_TRANSFER_RETURN) != 0) {
        if (!monitor->pending.empty()) {
            PendingExecTransfer pending = std::move(monitor->pending.back());
            monitor->pending.pop_back();
            emit_return(pending, state, writer);
        }
    }
}
