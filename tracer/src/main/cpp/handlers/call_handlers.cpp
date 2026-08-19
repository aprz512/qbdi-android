#include "handlers/call_handlers.h"

#include "core/logging.h"
#include "core/module_maps.h"
#include "core/safe_memory.h"
#include "jni/jni_formatter.h"
#include "jni/jni_function_table.h"
#include "jni/jni_state.h"

#include <QBDI/State.h>
#include <dlfcn.h>
#if !defined(__ANDROID__)
#include <execinfo.h>
#endif
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

// ── JNI 函数地址解析 ────────────────────────────────────────
namespace {

    // JNI 回溯配置
    static std::vector<std::string> g_bt_funcs;
    static std::mutex g_bt_lock;

    static JniAddressMap g_jni_map;
    static bool g_jni_map_built = false;
    static std::mutex g_jni_map_lock;

    void ensure_jni_map_built(uintptr_t env) {
        if (g_jni_map_built) return;
        std::lock_guard<std::mutex> guard(g_jni_map_lock);
        if (g_jni_map_built) return;

        auto table = build_jni_function_table();

        // ── 方法 1: dlsym 直接解析（优先，覆盖 JNIEnv + JavaVM 所有函数） ──
        for (auto &func: table) {
            void *addr = dlsym(RTLD_DEFAULT, func.name);
            if (addr != nullptr) {
                func.address = reinterpret_cast<uintptr_t>(addr);
                g_jni_map[func.address] = &func;
            }
        }
        size_t dlsym_count = g_jni_map.size();

        // ── 方法 2: JNIEnv vtable 兜底（dlsym 失败时，如被 strip 的 libart） ──
        uintptr_t vtable = 0;
        if (safe_read_memory(env, &vtable, sizeof(vtable)) && vtable > 0x1000) {
            constexpr int kMaxVtableSlots = 512;
            for (int i = 0; i < kMaxVtableSlots; ++i) {
                uintptr_t fn_addr = 0;
                if (!safe_read_memory(vtable + i * sizeof(uintptr_t), &fn_addr, sizeof(fn_addr)))
                    break;
                if (fn_addr == 0 || fn_addr < 0x1000) continue;

                Dl_info info{};
                if (dladdr(reinterpret_cast<void *>(fn_addr), &info) == 0 ||
                    info.dli_sname == nullptr)
                    continue;

                for (auto &func: table) {
                    if (func.address != 0) continue;
                    if (strcmp(info.dli_sname, func.name) == 0) {
                        func.address = fn_addr;
                        g_jni_map[fn_addr] = &func;
                        break;
                    }
                }
            }

            // 后备: 按标准 JNINativeInterface 顺序 (前4个保留槽)
            int std_index = 4;
            for (auto &func: table) {
                if (func.address != 0) { ++std_index; continue; }
                if (strcmp(func.struct_name, "JavaVM") == 0) { ++std_index; continue; }
                uintptr_t candidate = 0;
                if (safe_read_memory(vtable + std_index * sizeof(uintptr_t),
                                     &candidate, sizeof(candidate)) && candidate > 0x1000) {
                    func.address = candidate;
                    g_jni_map[candidate] = &func;
                }
                ++std_index;
            }
        }

        // ── 方法 3: JavaVM vtable 兜底（如果 env 正好是 JavaVM*） ──
        // JavaVM 的 JNIInvokeInterface 最多只有几个函数，已在方法1 dlsym 覆盖

        g_jni_map_built = true;
        QTRACE_I("jni map built: %zu/%zu resolved (dlsym=%zu)",
                 g_jni_map.size(), table.size(), dlsym_count);
    }

    // ── 已知 libc 符号 ──
    std::unordered_map<uintptr_t, const char *> known_libc_symbols() {
        void *libc = dlopen("libc.so", RTLD_NOW);
        std::unordered_map<uintptr_t, const char *> result;
        const char *names[] = {
                "strlen", "memcpy", "memcmp", "access", "fopen",
                "fgets", "fclose", "strstr", "strcasestr", "__system_property_get",
        };
        for (const char *name: names) {
            void *addr = libc != nullptr ? dlsym(libc, name) : nullptr;
            if (addr != nullptr) result.emplace(reinterpret_cast<uintptr_t>(addr), name);
        }
        return result;
    }

    const char *known_libc_name(uintptr_t address) {
        static auto symbols = known_libc_symbols();
        auto it = symbols.find(address);
        return it != symbols.end() ? it->second : nullptr;
    }

    // ── 相对时间 ──
    long elapsed_ms() {
        static auto s_start = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - s_start).count();
    }

    // ── JNI 调用记录（call/return 配对） ──
    struct ActiveJniCall {
        const JniFuncInfo *func = nullptr;
        uint64_t args[8] = {};
        int tid = 0;
        long enter_ms = 0;
    };

    // QBDI 是单线程执行的, 用 thread_local 存储当前活跃的 JNI 调用
    static thread_local ActiveJniCall t_active_jni;

    // ── JNI 状态更新 ──
    void update_jni_state(const JniFuncInfo &func, const uint64_t *args, uint64_t retval) {
        auto &state = jni_state();
        const char *name = func.name;

        if (strcmp(name, "FindClass") == 0) {
            std::string cn_str = preview_c_string(args[1], 256);
            if (!cn_str.empty()) state.on_find_class(retval, cn_str.c_str());
        } else if (strcmp(name, "DefineClass") == 0) {
            std::string cn_str = preview_c_string(args[1], 256);
            if (!cn_str.empty()) state.on_define_class(retval, cn_str.c_str());
        } else if (strcmp(name, "GetObjectClass") == 0) {
            state.on_get_object_class(args[1], retval);
        } else if (strcmp(name, "GetMethodID") == 0) {
            std::string mn_str = preview_c_string(args[2], 256);
            std::string ms_str = preview_c_string(args[3], 256);
            if (!mn_str.empty() && !ms_str.empty()) state.on_get_method_id(retval, mn_str.c_str(), ms_str.c_str());
        } else if (strcmp(name, "GetStaticMethodID") == 0) {
            std::string mn_str = preview_c_string(args[2], 256);
            std::string ms_str = preview_c_string(args[3], 256);
            if (!mn_str.empty() && !ms_str.empty()) state.on_get_static_method_id(retval, mn_str.c_str(), ms_str.c_str());
        } else if (strcmp(name, "GetFieldID") == 0) {
            std::string fn_str = preview_c_string(args[2], 256);
            std::string fs_str = preview_c_string(args[3], 256);
            if (!fn_str.empty() && !fs_str.empty()) state.on_get_field_id(retval, fn_str.c_str(), fs_str.c_str());
        } else if (strcmp(name, "GetStaticFieldID") == 0) {
            std::string fn_str = preview_c_string(args[2], 256);
            std::string fs_str = preview_c_string(args[3], 256);
            if (!fn_str.empty() && !fs_str.empty()) state.on_get_static_field_id(retval, fn_str.c_str(), fs_str.c_str());
        } else if (strcmp(name, "NewStringUTF") == 0) {
            std::string s_str = preview_c_string(args[1], 1024);
            if (!s_str.empty()) state.on_new_string_utf(retval, s_str.c_str());
        } else if (strcmp(name, "NewString") == 0) {
            std::string s_str = preview_c_string(args[1], 1024);
            if (!s_str.empty()) state.on_new_string(retval, s_str.c_str());
        } else if (strcmp(name, "NewGlobalRef") == 0) {
            state.on_new_global_ref(retval, args[1]);
        } else if (strcmp(name, "NewLocalRef") == 0) {
            state.on_new_local_ref(retval, args[1]);
        } else if (strcmp(name, "DeleteGlobalRef") == 0) {
            state.on_delete_global_ref(args[1]);
        } else if (strcmp(name, "DeleteLocalRef") == 0) {
            state.on_delete_local_ref(args[1]);
        } else if (strcmp(name, "NewWeakGlobalRef") == 0) {
            state.on_new_weak_global_ref(retval, args[1]);
        } else if (strcmp(name, "DeleteWeakGlobalRef") == 0) {
            state.on_delete_weak_global_ref(args[1]);
        }
    }

    // ── emit_jni_enter: 检测到 JNI 调用 → 格式化输出 enter ──
    void emit_jni_enter(uintptr_t target, QBDI::GPRState *gpr, TextTraceWriter *writer) {
        uintptr_t env = QBDI_GPR_GET(gpr, 0);
        ensure_jni_map_built(env);

        auto it = g_jni_map.find(target);
        if (it == g_jni_map.end()) return;

        t_active_jni.func = it->second;
        t_active_jni.tid = static_cast<int>(syscall(SYS_gettid));
        t_active_jni.enter_ms = elapsed_ms();

        for (int i = 0; i < 8; ++i)
            t_active_jni.args[i] = QBDI_GPR_GET(gpr, i + 1);

        JniFormatter fmt;
        int num_args = static_cast<int>(t_active_jni.func->args.size());
        std::string line = fmt.format_enter(t_active_jni.tid, t_active_jni.enter_ms,
                                             *t_active_jni.func, t_active_jni.args, num_args);
        writer->write_raw_line(line);

        // ── 回溯: 检查是否需要打印调用栈 ──
        bool need_bt = false;
        {
            std::lock_guard<std::mutex> guard(g_bt_lock);
            need_bt = std::find(g_bt_funcs.begin(), g_bt_funcs.end(),
                                std::string(t_active_jni.func->name)) != g_bt_funcs.end();
        }
        // Android NDK does not expose execinfo's backtrace APIs.
#if !defined(__ANDROID__)
        if (need_bt) {
            void *bt_buf[32];
            int n = backtrace(bt_buf, 32);
            char **symbols = backtrace_symbols(bt_buf, n);
            std::vector<std::string> frames;
            for (int i = 0; i < n; ++i) {
                if (symbols[i] == nullptr) continue;
                std::string sym(symbols[i]);
                // 跳过 tracer 自身的帧 (qbdi_tracer / QBDI 内部)
                if (sym.find("qbdi_tracer") != std::string::npos) continue;
                if (sym.find("libQBDI") != std::string::npos) continue;
                if (sym.find("libshadowhook") != std::string::npos) continue;
                frames.push_back(sym);
                if (frames.size() >= 16) break;
            }
            free(symbols);
            if (!frames.empty()) {
                writer->write_raw_line(JniFormatter::format_backtrace(frames));
            }
        }
#else
        (void) need_bt;
#endif
    }

    // ── emit_jni_leave: JNI 返回 → 格式化输出 leave + 更新状态 ──
    void emit_jni_leave(QBDI::GPRState *gpr, TextTraceWriter *writer) {
        if (t_active_jni.func == nullptr) return;

        uint64_t retval = QBDI_GPR_GET(gpr, 0);
        update_jni_state(*t_active_jni.func, t_active_jni.args, retval);

        JniFormatter fmt;
        std::string line = fmt.format_leave(t_active_jni.tid, t_active_jni.enter_ms,
                                             *t_active_jni.func, retval);
        writer->write_raw_line(line);

        t_active_jni = ActiveJniCall{};
    }

    // ── 非 JNI 调用（保持原有逻辑） ──
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
    emit_non_jni_call(uintptr_t target, QBDI::GPRState *state, TextTraceWriter *writer) {
        PendingExecTransfer pending;
        pending.target = target;

        Dl_info info{};
        dladdr(reinterpret_cast<void *>(target), &info);

        const std::string module = module_name(info);
        const std::string name = symbol_name(target, info);

        if (module == "libc.so" || known_libc_name(target) != nullptr) {
            std::ostringstream detail;
            detail << "target=0x" << std::hex << target << " x0=0x" << QBDI_GPR_GET(state, 0);
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

    void emit_non_jni_return(const PendingExecTransfer &pending, QBDI::GPRState *state,
                              TextTraceWriter *writer) {
        if (state == nullptr || writer == nullptr || pending.name.empty()) return;
        std::ostringstream detail;
        detail << pending.category << "." << pending.name << " target=0x" << std::hex
               << pending.target << " ret=0x" << QBDI_GPR_GET(state, 0);
        writer->call("return", pending.name, detail.str());
    }
}

// ── JNI 回溯配置接口 ──
void set_jni_backtrace_funcs(const std::vector<std::string> &funcs) {
    std::lock_guard<std::mutex> guard(g_bt_lock);
    g_bt_funcs = funcs;
}

// ── 公开接口 ──
void emit_exec_transfer_event(ExecTransferMonitor *monitor, const QBDI::VMState *vm_state,
                              QBDI::GPRState *state, TextTraceWriter *writer) {
    if (monitor == nullptr || vm_state == nullptr || state == nullptr || writer == nullptr) return;

    uintptr_t target = state->pc;

    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        // 1) 尝试 JNI 匹配 → 走 jnitrace 风格格式化
        emit_jni_enter(target, state, writer);
        if (t_active_jni.func != nullptr) {
            // JNI 调用已追踪，压一个占位 pending 用于配对 return
            PendingExecTransfer placeholder;
            placeholder.category = "jni";
            placeholder.name = t_active_jni.func->name;
            placeholder.target = target;
            monitor->pending.push_back(std::move(placeholder));
            return;
        }

        // 2) 非 JNI — 走原有逻辑
        PendingExecTransfer pending = emit_non_jni_call(target, state, writer);
        if (!pending.name.empty()) monitor->pending.push_back(std::move(pending));
    }

    if ((vm_state->event & QBDI::EXEC_TRANSFER_RETURN) != 0) {
        if (!monitor->pending.empty()) {
            PendingExecTransfer pending = std::move(monitor->pending.back());
            monitor->pending.pop_back();

            if (pending.category == "jni") {
                emit_jni_leave(state, writer);
            } else {
                emit_non_jni_return(pending, state, writer);
            }
        }
    }
}
