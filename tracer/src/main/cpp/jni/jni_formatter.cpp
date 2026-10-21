#include "jni/jni_formatter.h"
#include "jni/jni_state.h"
#include "core/safe_memory.h"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <string_view>
#include <vector>

// 标准 hexdump（对标 jnitrace hexdump 库输出格式）
// offset  | hex bytes (16列) | ASCII
static std::string hexdump_lines(uintptr_t ptr, size_t total_bytes = 32,
                                  size_t bytes_per_line = 16) {
    if (ptr < 0x1000 || total_bytes == 0) return "";
    std::vector<uint8_t> buf(total_bytes);
    if (!safe_read_memory(ptr, buf.data(), total_bytes)) return "";

    std::ostringstream out;
    for (size_t offset = 0; offset < total_bytes; offset += bytes_per_line) {
        char line[128];
        size_t pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "           :   %08zx  ", offset);

        // hex 部分
        for (size_t j = 0; j < bytes_per_line; ++j) {
            if (offset + j < total_bytes) {
                pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", buf[offset + j]);
            } else {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
            }
            if (j == 7) pos += snprintf(line + pos, sizeof(line) - pos, " ");
        }
        // ASCII 部分
        pos += snprintf(line + pos, sizeof(line) - pos, " |");
        for (size_t j = 0; j < bytes_per_line && (offset + j) < total_bytes; ++j) {
            uint8_t c = buf[offset + j];
            pos += snprintf(line + pos, sizeof(line) - pos, "%c",
                            (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "|");
        out << line << "\n";
    }
    return out.str();
}

// 是否需要 hexdump 的函数名判断
static bool has_buffer_return(const char *name) {
    return strncmp(name, "Get", 3) == 0 &&
           (strstr(name, "ArrayElements") || strstr(name, "ArrayCritical") ||
            strstr(name, "ArrayRegion"));
}

static std::string fmt_ptr(uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", static_cast<unsigned long>(value));
    return buf;
}

// 是否是对象/引用类型（hex 显示）
static bool is_ref_type(const char *type) {
    return std::string_view(type).ends_with("Array") ||
           strcmp(type, JniType::kObject)    == 0 ||
           strcmp(type, JniType::kClass)     == 0 ||
           strcmp(type, JniType::kString)    == 0 ||
           strcmp(type, JniType::kArray)     == 0 ||
           strcmp(type, JniType::kThrowable) == 0 ||
           strcmp(type, JniType::kWeak)      == 0 ||
           strcmp(type, JniType::kMethodID)  == 0 ||
           strcmp(type, JniType::kFieldID)   == 0 ||
           strcmp(type, JniType::kCString)   == 0 ||
           strcmp(type, JniType::kPointer)   == 0;
}

static std::string fmt_value(const char *type, uint64_t value) {
    if (is_ref_type(type)) return fmt_ptr(value);
    if (strcmp(type, JniType::kBoolean) == 0)
        return static_cast<uint8_t>(value) ? "true" : "false";
    char buf[96];
    if (strcmp(type, JniType::kFloat) == 0 || strcmp(type, JniType::kDouble) == 0) {
        double number;
        if (strcmp(type, JniType::kFloat) == 0) {
            const uint32_t bits = static_cast<uint32_t>(value);
            float narrow;
            std::memcpy(&narrow, &bits, sizeof(narrow));
            number = narrow;
            value = bits;
        } else {
            std::memcpy(&number, &value, sizeof(number));
        }
        snprintf(buf, sizeof(buf), "0x%llx (%.*g)", static_cast<unsigned long long>(value),
                 strcmp(type, JniType::kFloat) == 0 ? 9 : 17, number);
        return buf;
    }
    int64_t number;
    if (strcmp(type, JniType::kInt) == 0 || strcmp(type, JniType::kSize) == 0) {
        value = static_cast<uint32_t>(value);
        number = static_cast<int32_t>(value);
    } else if (strcmp(type, JniType::kByte) == 0) {
        value = static_cast<uint8_t>(value);
        number = static_cast<int8_t>(value);
    } else if (strcmp(type, JniType::kShort) == 0) {
        value = static_cast<uint16_t>(value);
        number = static_cast<int16_t>(value);
    } else if (strcmp(type, JniType::kChar) == 0) {
        value = static_cast<uint16_t>(value);
        number = static_cast<int64_t>(value);
    } else {
        number = static_cast<int64_t>(value);
    }
    snprintf(buf, sizeof(buf), "0x%llx (%lld)",
             static_cast<unsigned long long>(value), static_cast<long long>(number));
    return buf;
}

// ── 元数据解析 (对标 jnitrace enrich / metadata) ─────────────

// 为一个值解析最丰富的元数据字符串
// 返回的字符串包含所有可显示信息: 类名/方法签名/字符串值等
static std::string resolve_meta(const char *type, uint64_t value) {
    if (value == 0) return "";
    auto &state = jni_state();
    std::ostringstream meta;

    // ── jclass → 类名 ──
    if (strcmp(type, JniType::kClass) == 0) {
        const auto cn = state.class_name(value);
        if (cn) meta << *cn;
    }
    // jstring is an opaque handle. Only values captured from NewStringUTF are safe.
    else if (strcmp(type, JniType::kString) == 0) {
        const auto text = state.string_value(value);
        if (text) meta << '"' << *text << '"';
    }
    else if (strcmp(type, JniType::kCString) == 0) {
        const auto text = copy_c_string(value, 1024, true);
        if (text) meta << '"' << *text << '"';
    }
    // ── jobject/jthrowable/jweak → 对象类型 ──
    else if (strcmp(type, JniType::kObject)    == 0 ||
             strcmp(type, JniType::kThrowable) == 0 ||
             strcmp(type, JniType::kWeak)      == 0) {
        const auto ot = state.object_type(value);
        if (ot) {
            meta << *ot;
        } else {
            const auto cn = state.class_name(value);
            if (cn) meta << *cn;
        }
    }
    // ── jmethodID → name(sig) ──
    else if (strcmp(type, JniType::kMethodID) == 0) {
        const auto ms = state.method_sig(value);
        if (ms) meta << *ms;
    }
    // ── jfieldID → name:sig ──
    else if (strcmp(type, JniType::kFieldID) == 0) {
        const auto fs = state.field_sig(value);
        if (fs) meta << *fs;
    }
    return meta.str();
}

// ── 数据行生成 ──────────────────────────────────────────────

std::string JniFormatter::format_data_line(long elapsed_ms, const char *sym,
                                            const char *type, uint64_t value,
                                            const char *meta, int padding) {
    std::ostringstream out;
    out.width(7);
    out << elapsed_ms << " ms | ";
    out << sym << " ";
    if (padding > 0) out << std::string(padding, ' ');
    out.width(15);
    out << std::left << type;
    out << ": " << fmt_value(type, value);
    if (meta && meta[0]) out << "  { " << meta << " }";
    return out.str();
}

// ── 对外接口 ────────────────────────────────────────────────

std::string JniFormatter::format_arg(const char *type, uint64_t value, const char *meta) {
    std::ostringstream out;
    out << fmt_value(type, value);
    if (meta && meta[0]) out << "  { " << meta << " }";
    return out.str();
}

std::string JniFormatter::format_ret(const char *type, uint64_t value, const char *meta) {
    return format_arg(type, value, meta);
}

// ── format_enter: 入口 ──────────────────────────────────────

std::string JniFormatter::format_enter(int tid, long elapsed_ms,
                                        const JniFuncInfo &func,
                                        const uint64_t *args, int num_args,
                                        const Arm64JniArguments *abi) {
    auto &state = jni_state();
    std::ostringstream out;

    // TID
    out << "/* TID " << tid << " */\n";

    // 方法名
    out.width(7);
    out << elapsed_ms << " ms [+] " << func.struct_name << "->" << func.name << "\n";

    // Fixed JNI parameters have independent GP and FP register cursors too.
    JniDecodedArguments fixed;
    if (abi != nullptr) {
        fixed = decode_arm64_jni_fixed_arguments(func, *abi, safe_read_memory);
    } else {
        for (int i = 0; i < num_args && i < static_cast<int>(func.args.size()); ++i) {
            const char *type = func.args[i];
            if (strcmp(type, JniType::kVarArgs) == 0 || strcmp(type, JniType::kVaList) == 0) break;
            if (strcmp(type, JniType::kFloat) == 0 || strcmp(type, JniType::kDouble) == 0) {
                fixed.values.clear();
                fixed.error = "floating argument registers unavailable";
                break;
            }
            fixed.values.push_back({type, args[i]});
        }
    }
    if (!fixed.error.empty()) {
        out << "           |- <undecoded: " << fixed.error << ">\n";
    } else {
        for (const auto &argument : fixed.values) {
            const char *type = argument.type.c_str();
            const std::string meta = resolve_meta(type, argument.bits);
            out << "           "
                << format_data_line(elapsed_ms, "|-", type, argument.bits,
                                     meta.empty() ? nullptr : meta.c_str(), 0)
                << "\n";
        }
    }

    // ── 特殊处理: Call*Method → 展开 Java 参数 ──
    const std::string_view name(func.name);
    if ((name.starts_with("Call") && name.find("Method") != std::string_view::npos) ||
        name == "NewObject" || name == "NewObjectV" || name == "NewObjectA") {
        std::optional<std::string> signature;
        for (size_t index = 0; index < func.args.size() && index < static_cast<size_t>(num_args); ++index) {
            if (strcmp(func.args[index], JniType::kMethodID) == 0) signature = state.method_sig(args[index]);
        }
        JniDecodedArguments decoded;
        if (!signature) decoded.error = "method signature unavailable";
        else if (abi == nullptr) decoded.error = "arm64 argument state unavailable";
        else decoded = decode_arm64_jni_arguments(func, *abi, signature, safe_read_memory);
        if (!decoded.error.empty()) {
            out << "           :   <undecoded: " << decoded.error << ">\n";
        } else {
            for (const auto &argument : decoded.values) {
                const uint64_t pval = argument.bits;
                const char *ptype = argument.type.c_str();
                std::string pmeta = resolve_meta(ptype, pval);
                out << "           :   "
                    << format_data_line(elapsed_ms, ":", ptype, pval,
                                         pmeta.empty() ? nullptr : pmeta.c_str(), 0)
                    << "\n";
            }
        }
    }

    // ── 特殊处理: RegisterNatives → 展开 JNINativeMethod 数组 ──
    if (strcmp(func.name, "RegisterNatives") == 0) {
        uintptr_t methods_ptr = args[2];
        int nMethods = static_cast<int>(args[3]);
        if (methods_ptr > 0x1000 && nMethods > 0 && nMethods <= 1024) {
            for (int i = 0; i < nMethods; ++i) {
                uintptr_t offset = i * 24;
                uintptr_t name_ptr = 0, sig_ptr = 0, fn_ptr = 0;
                if (!safe_read_memory(methods_ptr + offset, &name_ptr, sizeof(name_ptr))) break;
                if (!safe_read_memory(methods_ptr + offset + 8, &sig_ptr, sizeof(sig_ptr))) break;
                if (!safe_read_memory(methods_ptr + offset + 16, &fn_ptr, sizeof(fn_ptr))) break;

                const auto name = copy_c_string(name_ptr, 512, true);
                const auto sig = copy_c_string(sig_ptr, 512, true);
                char line[512];
                if (name && sig) {
                    snprintf(line, sizeof(line), "           :   %-40s %-s  -> fnPtr=0x%lx\n",
                             name->c_str(), sig->c_str(), static_cast<unsigned long>(fn_ptr));
                } else if (name) {
                    snprintf(line, sizeof(line), "           :   %-40s <no sig>  -> fnPtr=0x%lx\n",
                             name->c_str(), static_cast<unsigned long>(fn_ptr));
                } else {
                    snprintf(line, sizeof(line), "           :   <no name>       <no sig>  -> fnPtr=0x%lx\n",
                             static_cast<unsigned long>(fn_ptr));
                }
                out << line;
            }
        }
    }

    // ── 特殊处理: buffer 参数 → hexdump ──
    // DefineClass: args[1]=name, args[3]=buf, args[4]=len
    if (strcmp(func.name, "DefineClass") == 0 && args[3] > 0x1000) {
        int buf_len = static_cast<int>(args[4]);
        if (buf_len > 0 && buf_len <= 65536)
            out << hexdump_lines(args[3], buf_len < 64 ? buf_len : 64);
    }
    // NewDirectByteBuffer: args[1]=address, args[2]=capacity
    if (strcmp(func.name, "NewDirectByteBuffer") == 0 && args[1] > 0x1000) {
        long cap = static_cast<long>(args[2]);
        if (cap > 0) out << hexdump_lines(args[1], cap < 64 ? cap : 64);
    }
    // Set*ArrayRegion: args[1]=array, args[2]=start, args[3]=len, args[4]=buf
    if (strncmp(func.name, "Set", 3) == 0 && strstr(func.name, "ArrayRegion") && args[4] > 0x1000) {
        int len = static_cast<int>(args[3]);
        if (len > 0 && len <= 65536)
            out << hexdump_lines(args[4], len < 64 ? len : 64);
    }

    return out.str();
}

// ── format_leave: 出口 ──────────────────────────────────────

std::string JniFormatter::format_leave(int tid, long elapsed_ms,
                                        const JniFuncInfo &func,
                                        uint64_t retval, bool value_available) {
    (void)tid;
    std::ostringstream out;

    if (strcmp(func.ret_type, JniType::kVoid) == 0) {
        out << "           "
            << format_data_line(elapsed_ms, "|=", func.ret_type, 0, nullptr, 0)
            << "\n";
        return out.str();
    }
    if (!value_available) {
        out << "           |= " << func.ret_type << ": <undecoded: floating return register unavailable>\n";
        return out.str();
    }

    std::string meta = resolve_meta(func.ret_type, retval);

    out << "           "
        << format_data_line(elapsed_ms, "|=", func.ret_type, retval,
                             meta.empty() ? nullptr : meta.c_str(), 0)
        << "\n";

    // ── 特殊: 返回值是 buffer → hexdump ──
    if (strcmp(func.ret_type, JniType::kPointer) == 0 && retval > 0x1000) {
        if (has_buffer_return(func.name)) {
            out << hexdump_lines(retval, 32);
        }
    }

    return out.str();
}

// ── format_backtrace: 调用栈回溯 ────────────────────────────
// 对标 jnitrace _print_backtrace
std::string JniFormatter::format_backtrace(const std::vector<std::string> &frames) {
    if (frames.empty()) return "";

    std::ostringstream out;
    out << "           |\n";
    out << "           |-> Backtrace " << std::string(40, '-') << "\n";

    for (size_t i = 0; i < frames.size(); ++i) {
        out << "           |-> " << frames[i] << "\n";
    }
    return out.str();
}
