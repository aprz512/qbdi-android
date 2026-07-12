#pragma once

#include "events/trace_event.h"
#include "jni/jni_function_table.h"

#include <cstdint>
#include <string>

// ── jnitrace 风格 JNI 调用格式化器 ──────────────────────────
//
// 输出格式对标 chame1eon/jnitrace:
//
//   [TID 12345]
//        0 ms [+] JNIEnv->FindClass
//                |- jclass:  0x7a1b2c3d  { java/lang/String }
//                |= jstring: 0x7e5f6a7b
//
// 线程着色由调用层通过 writer 实现（简化版用 TID 区分）

class JniFormatter {
public:
    JniFormatter() = default;

    // ── 生成一行格式化的 JNI 调用 ──
    // onEnter 调用:
    std::string format_enter(int tid, long elapsed_ms,
                             const JniFuncInfo &func,
                             const uint64_t *args, int num_args);

    // onLeave 调用:
    std::string format_leave(int tid, long elapsed_ms,
                             const JniFuncInfo &func,
                             uint64_t retval);

    // ── 辅助 ──
    static std::string format_arg(const char *type, uint64_t value, const char *meta = nullptr);
    static std::string format_ret(const char *type, uint64_t value, const char *meta = nullptr);

    // 格式化调用栈回溯（对标 jnitrace _print_backtrace）
    static std::string format_backtrace(const std::vector<std::string> &frames);

private:
    // 格式化一条数据行
    std::string format_data_line(long elapsed_ms, const char *sym,
                                  const char *type, uint64_t value,
                                  const char *meta = nullptr, int padding = 0);
};
