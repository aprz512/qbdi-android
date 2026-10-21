#include "jni/jni_argument_decoder.h"

#include "jni/jni_state.h"

#include <cstring>
#include <limits>
#include <string_view>

namespace {

// AAPCS64 LP64 va_list. A structure larger than 16 bytes is passed indirectly.
// Decode a private copy; calling va_arg on the target's object would consume it.
struct Arm64VaList {
    uint64_t stack, general_top, floating_top;
    int32_t general_offset, floating_offset;
};
static_assert(sizeof(Arm64VaList) == 32);

bool descriptor_type(std::string_view text, size_t *position, bool allow_void) {
    size_t &index = *position;
    if (index >= text.size()) return false;
    bool array = false;
    while (index < text.size() && text[index] == '[') { array = true; ++index; }
    if (index >= text.size()) return false;
    const char kind = text[index++];
    if (kind == 'L') {
        const size_t end = text.find(';', index);
        if (end == std::string_view::npos || end == index) return false;
        for (; index < end; ++index) {
            if (text[index] == '(' || text[index] == ')' || text[index] == '[' || text[index] == '.') return false;
        }
        ++index;
        return true;
    }
    return (kind != '\0' && std::strchr("ZBCSIJFD", kind) != nullptr) ||
           (kind == 'V' && allow_void && !array);
}

bool valid_signature(const std::string &signature) {
    if (signature.find('\0') != std::string::npos) return false;
    const std::string_view text(signature);
    const size_t opening = text.find('(');
    if (opening == std::string_view::npos) return false;
    size_t index = opening + 1;
    size_t count = 0;
    while (index < text.size() && text[index] != ')') {
        if (++count > 255 || !descriptor_type(text, &index, false)) return false;
    }
    if (index >= text.size() || text[index++] != ')') return false;
    return descriptor_type(text, &index, true) && index == text.size();
}

bool floating_type(const std::string &type) {
    return type == JniType::kFloat || type == JniType::kDouble;
}

bool add_address(uintptr_t base, uint64_t offset, uintptr_t *result) {
    if (offset > std::numeric_limits<uintptr_t>::max() - base) return false;
    *result = base + offset;
    return true;
}

bool saved_register(uint64_t top, int32_t offset, uintptr_t *address) {
    const uint64_t distance = static_cast<uint64_t>(-int64_t(offset));
    if (top < distance) return false;
    *address = top - distance;
    return true;
}

} // namespace

JniDecodedArguments decode_arm64_jni_fixed_arguments(
        const JniFuncInfo &function, const Arm64JniArguments &arguments,
        JniArgumentMemoryReader read_memory) {
    JniDecodedArguments result;
    const auto fail = [&](const char *reason) {
        result.values.clear();
        result.error = reason;
        return result;
    };
    size_t general = 1, floating = 0;
    uintptr_t stack = arguments.stack;
    for (const char *type : function.args) {
        if (std::strcmp(type, JniType::kVarArgs) == 0 || std::strcmp(type, JniType::kVaList) == 0) break;
        const bool fp = floating_type(type);
        uint64_t bits = 0;
        if (fp && floating < arguments.floating.size()) {
            if (!arguments.has_floating) return fail("floating argument registers unavailable");
            bits = arguments.floating[floating++];
        } else if (!fp && general < arguments.general.size()) {
            bits = arguments.general[general++];
        } else {
            if (stack % 8) return fail("unaligned arm64 argument stack");
            uintptr_t next = 0;
            if (!read_memory || !add_address(stack, 8, &next) || !read_memory(stack, &bits, 8))
                return fail("unreadable JNI argument storage");
            stack = next;
        }
        if (std::strcmp(type, JniType::kFloat) == 0) bits &= UINT32_MAX;
        result.values.push_back({type, bits});
    }
    return result;
}

JniDecodedArguments decode_arm64_jni_arguments(
        const JniFuncInfo &function, const Arm64JniArguments &arguments,
        const std::optional<std::string> &signature,
        JniArgumentMemoryReader read_memory) {
    JniDecodedArguments result;
    const auto fail = [&](const char *reason) {
        result.values.clear();
        result.error = reason;
        return result;
    };
    if (!signature) return fail("method signature unavailable");
    if (!valid_signature(*signature)) return fail("invalid method signature");
    const auto params = JniState::parse_method_params(signature->c_str());
    if (params.empty()) return result;
    if (function.args.empty() || !read_memory) return fail("JNI argument layout unavailable");
    const std::string_view form(function.args.back());
    if (form != JniType::kVarArgs && form != JniType::kVaList && form != JniType::kPointer)
        return fail("unsupported JNI argument layout");
    const size_t fixed = function.args.size(); // Includes env, excludes the final argument marker.
    if (fixed >= arguments.general.size()) return fail("unsupported JNI fixed arguments");
    size_t general = fixed, floating = 0;
    uintptr_t stack = arguments.stack;
    const uintptr_t indirect = arguments.general[fixed];
    Arm64VaList list{};
    if (form == JniType::kVaList) {
        if (!read_memory(indirect, &list, sizeof(list))) return fail("unreadable va_list");
        // A nonnegative offset means the save area is exhausted. A forwarded
        // list may already have overflowed it while consuming earlier arguments.
        if (list.general_offset < -64 || list.general_offset % 8 ||
            list.floating_offset < -128 || list.floating_offset % 16 ||
            (list.general_offset < 0 && list.general_top % 8) ||
            (list.floating_offset < 0 && list.floating_top % 16))
            return fail("invalid arm64 va_list offsets");
        stack = list.stack;
    }
    for (size_t index = 0; index < params.size(); ++index) {
        const std::string &type = params[index];
        const bool fp = floating_type(type);
        uint64_t bits = 0;
        bool copied = false;
        uintptr_t address = 0;
        if (form == JniType::kPointer) {
            copied = add_address(indirect, index * 8, &address) && read_memory(address, &bits, 8);
        } else if (form == JniType::kVarArgs && fp && floating < 8) {
            if (!arguments.has_floating) return fail("floating argument registers unavailable");
            bits = arguments.floating[floating++];
            copied = true;
        } else if (form == JniType::kVarArgs && !fp && general < 8) {
            bits = arguments.general[general++];
            copied = true;
        } else if (form == JniType::kVaList && (fp ? list.floating_offset : list.general_offset) < 0) {
            int32_t &offset = fp ? list.floating_offset : list.general_offset;
            copied = saved_register(fp ? list.floating_top : list.general_top, offset, &address) &&
                     read_memory(address, &bits, 8);
            offset += fp ? 16 : 8;
        } else {
            if (stack % 8) return fail("unaligned arm64 argument stack");
            copied = add_address(stack, 8, &address) && read_memory(stack, &bits, 8);
            stack = address;
        }
        if (!copied) return fail("unreadable Java argument storage");
        // C default argument promotions apply to ordinary and V calls, while
        // jvalue arrays store jfloat directly in the low four bytes.
        if (type == JniType::kFloat && form != JniType::kPointer) {
            double promoted;
            std::memcpy(&promoted, &bits, sizeof(promoted));
            const float value = static_cast<float>(promoted);
            uint32_t narrow;
            std::memcpy(&narrow, &value, sizeof(narrow));
            bits = narrow;
        }
        result.values.push_back({type, bits});
    }
    return result;
}
