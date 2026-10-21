#include "handlers/call_handlers.h"

#include "core/logging.h"
#include "core/module_maps.h"
#include "core/safe_memory.h"
#include "jni/jni_call_resolver.h"
#include "jni/jni_formatter.h"
#include "jni/jni_state.h"
#include "jni/jni_state_updater.h"

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
#include <string_view>
#include <unordered_map>
#include <utility>

// ── JNI 函数地址解析 ────────────────────────────────────────
namespace {

    // JNI 回溯配置
    static std::vector<std::string> g_bt_funcs;
    static std::mutex g_bt_lock;

    JniCallResolver &jni_call_resolver() {
        static JniCallResolver resolver(safe_read_memory);
        return resolver;
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

    // ── emit_jni_enter: 检测到 JNI 调用 → 格式化输出 enter ──
    bool emit_jni_enter(uintptr_t target, QBDI::GPRState *gpr,
                        const QBDI::FPRState *fpr, TraceSink *writer,
                        PendingExecTransfer *pending) {
        uintptr_t env = QBDI_GPR_GET(gpr, 0);
        const JniFuncInfo *function = jni_call_resolver().resolve(env, target);
        if (function == nullptr) return false;

        // Each pending transfer owns its entry snapshot. A Java callback may
        // reenter traced native code and issue another JNI call on this pthread.
        auto &call = pending->jni;
        call.func = function;
        call.tid = static_cast<int>(syscall(SYS_gettid));
        call.enter_ms = elapsed_ms();
        pending->target = target;
        pending->category = "jni";
        pending->name = function->name;

        for (int i = 0; i < 7; ++i)
            call.args[i] = QBDI_GPR_GET(gpr, i + 1);
        // x8 is the indirect-result register, not an eighth ordinary argument.
        call.args[7] = 0;
        if (function->args.size() > 7)
            safe_read_memory(gpr->sp, &call.args[7], sizeof(uint64_t));

        Arm64JniArguments abi;
        for (size_t i = 0; i < abi.general.size(); ++i)
            abi.general[i] = QBDI_GPR_GET(gpr, i);
        abi.stack = gpr->sp;
        abi.has_floating = fpr != nullptr;
        if (fpr != nullptr) {
            for (size_t i = 0; i < abi.floating.size(); ++i)
                std::memcpy(&abi.floating[i], reinterpret_cast<const uint8_t *>(fpr) + 16 * i, 8);
        }

        JniFormatter fmt;
        int num_args = static_cast<int>(call.func->args.size());
        std::string line = fmt.format_enter(call.tid, call.enter_ms,
                                             *call.func, call.args.data(), num_args, &abi);
        writer->call("jni-enter", call.func->name, line);
        if (writer->failed()) return true;

        // ── 回溯: 检查是否需要打印调用栈 ──
        bool need_bt = false;
        {
            std::lock_guard<std::mutex> guard(g_bt_lock);
            need_bt = std::find(g_bt_funcs.begin(), g_bt_funcs.end(),
                                std::string(call.func->name)) != g_bt_funcs.end();
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
                writer->call("jni-backtrace", call.func->name,
                             JniFormatter::format_backtrace(frames));
            }
        }
#else
        (void) need_bt;
#endif
        return true;
    }

    // ── emit_jni_leave: JNI 返回 → 格式化输出 leave + 更新状态 ──
    void emit_jni_leave(const JniCallSnapshot &call, QBDI::GPRState *gpr,
                        const QBDI::FPRState *fpr, TraceSink *writer) {
        if (call.func == nullptr) return;

        uint64_t retval = QBDI_GPR_GET(gpr, 0);
        const bool floating_return = std::strcmp(call.func->ret_type, JniType::kFloat) == 0 ||
                                     std::strcmp(call.func->ret_type, JniType::kDouble) == 0;
        if (floating_return && fpr != nullptr) std::memcpy(&retval, fpr, sizeof(retval));
        update_jni_state(jni_state(), *call.func, call.args.data(), retval);

        JniFormatter fmt;
        std::string line = fmt.format_leave(call.tid, call.enter_ms,
                                             *call.func, retval, !floating_return || fpr != nullptr);
        writer->call("jni-leave", call.func->name, line);
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
    emit_non_jni_call(uintptr_t target, QBDI::GPRState *state, TraceSink *writer) {
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
                              TraceSink *writer) {
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
                              QBDI::GPRState *state, TraceSink *writer,
                              const QBDI::FPRState *floating) {
    if (monitor == nullptr || vm_state == nullptr || state == nullptr || writer == nullptr) return;
    if (writer->failed()) return;

    uintptr_t target = state->pc;

    if ((vm_state->event & QBDI::EXEC_TRANSFER_CALL) != 0) {
        // 1) 尝试 JNI 匹配 → 走 jnitrace 风格格式化
        PendingExecTransfer pending;
        if (emit_jni_enter(target, state, floating, writer, &pending)) {
            if (writer->failed()) return;
            monitor->pending.push_back(std::move(pending));
            return;
        }

        // 2) 非 JNI — 走原有逻辑
        pending = emit_non_jni_call(target, state, writer);
        if (writer->failed()) return;
        // Even an unrecognized native transfer must balance its own return.
        monitor->pending.push_back(std::move(pending));
    }

    if ((vm_state->event & QBDI::EXEC_TRANSFER_RETURN) != 0) {
        if (!monitor->pending.empty()) {
            PendingExecTransfer pending = std::move(monitor->pending.back());
            monitor->pending.pop_back();

            if (pending.category == "jni") {
                emit_jni_leave(pending.jni, state, floating, writer);
            } else {
                emit_non_jni_return(pending, state, writer);
            }
        }
    }
}
