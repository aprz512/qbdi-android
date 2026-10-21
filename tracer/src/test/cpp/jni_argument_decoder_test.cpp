#include "jni/jni_argument_decoder.h"
#include "jni/jni_formatter.h"
#include "core/safe_memory.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #expression); std::abort(); \
} } while (false)

namespace {
uint64_t bits(double value) {
    uint64_t result;
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

JniFuncInfo function(const char *name, const char *form, bool nonvirtual = false) {
    JniFuncInfo result{name, JniType::kLong, "JNIEnv", {JniType::kObject}};
    if (nonvirtual) result.args.push_back(JniType::kClass);
    result.args.push_back(JniType::kMethodID);
    result.args.push_back(form);
    return result;
}

constexpr const char *signature = "mixed(IJDF[BIIIIIIIDDDDDDDD)J";
const uint64_t integers[] = {5, uint32_t(-6), 7, uint32_t(-8), 9, uint32_t(-10), 11};
const double doubles[] = {0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5};

struct Fixture {
    Arm64JniArguments frame;
    uint64_t stack[7]{};
    alignas(16) std::array<std::array<uint64_t, 2>, 8> floating{};
    uint64_t array[20]{};
    struct VaList {
        uint64_t stack, general_top, floating_top;
        int32_t general_offset, floating_offset;
    } list;

    Fixture() {
        frame.general = {0x1111, 0x2222, 0x3333, 0xbad0bad0ffffffef,
                         uint64_t(-81985529216486895LL), 0x4444, integers[0], integers[1]};
        frame.has_floating = true;
        frame.floating[0] = bits(-2.5);
        frame.floating[1] = bits(1.25);
        for (size_t i = 0; i < 6; ++i) frame.floating[2 + i] = bits(doubles[i]);
        for (size_t i = 0; i < 5; ++i) stack[i] = integers[2 + i];
        stack[5] = bits(doubles[6]); stack[6] = bits(doubles[7]);
        frame.stack = reinterpret_cast<uintptr_t>(stack);
        for (size_t i = 0; i < 8; ++i) floating[i][0] = frame.floating[i];
        list = {frame.stack, reinterpret_cast<uintptr_t>(frame.general.data() + 8),
                reinterpret_cast<uintptr_t>(floating.data() + 8), -40, -128};
        array[0] = frame.general[3]; array[1] = frame.general[4]; array[2] = bits(-2.5);
        float narrow = 1.25f; uint32_t narrow_bits;
        std::memcpy(&narrow_bits, &narrow, sizeof(narrow_bits));
        array[3] = 0xdeadbeef00000000 | narrow_bits; array[4] = 0x4444;
        for (size_t i = 0; i < 7; ++i) array[5 + i] = integers[i];
        for (size_t i = 0; i < 8; ++i) array[12 + i] = bits(doubles[i]);
    }
};

void check_mixed(const JniDecodedArguments &decoded) {
    CHECK(decoded.error.empty());
    CHECK(decoded.values.size() == 20);
    CHECK(decoded.values[0].type == "jint");
    CHECK(JniFormatter::format_arg("jint", decoded.values[0].bits) == "0xffffffef (-17)");
    CHECK(JniFormatter::format_arg("jlong", decoded.values[1].bits).find("(-81985529216486895)") != std::string::npos);
    CHECK(JniFormatter::format_arg("jdouble", decoded.values[2].bits).find("(-2.5)") != std::string::npos);
    CHECK(JniFormatter::format_arg("jfloat", decoded.values[3].bits).find("(1.25)") != std::string::npos);
    CHECK(decoded.values[4].type == "jbyteArray");
    CHECK(JniFormatter::format_arg("jbyteArray", decoded.values[4].bits) == "0x4444");
    for (size_t i = 0; i < 7; ++i) CHECK(uint32_t(decoded.values[5 + i].bits) == integers[i]);
    for (size_t i = 0; i < 8; ++i) CHECK(decoded.values[12 + i].bits == bits(doubles[i]));
}

void ordinary_reads_independent_register_banks_and_shared_stack() {
    Fixture fixture;
    check_mixed(decode_arm64_jni_arguments(function("CallLongMethod", "..."), fixture.frame, signature, safe_read_memory));
}

void fixed_scalars_do_not_promote_float_or_advance_the_other_register_bank() {
    JniFuncInfo target{"FixedScalars", JniType::kVoid, "JNIEnv",
                       {JniType::kObject, JniType::kFloat, JniType::kInt, JniType::kDouble}};
    Arm64JniArguments frame;
    frame.general = {0x1111, 0x2222, uint32_t(-38), 0xbad0bad0};
    frame.floating = {0xdeadbeefbfc00000, bits(-3.25)}; // float32 -1.5, double64 -3.25
    frame.has_floating = true;
    const auto original = frame;
    const auto decoded = decode_arm64_jni_fixed_arguments(target, frame, safe_read_memory);
    CHECK(decoded.error.empty() && decoded.values.size() == 4);
    CHECK(decoded.values[0].bits == 0x2222);
    CHECK(decoded.values[1].type == JniType::kFloat && decoded.values[1].bits == 0xbfc00000);
    CHECK(uint32_t(decoded.values[2].bits) == uint32_t(-38));
    CHECK(decoded.values[3].bits == bits(-3.25));
    CHECK(frame.general == original.general && frame.floating == original.floating);
    frame.has_floating = false;
    const auto unavailable = decode_arm64_jni_fixed_arguments(target, frame, safe_read_memory);
    CHECK(unavailable.error == "floating argument registers unavailable" && unavailable.values.empty());
}

void fixed_stack_arguments_refuse_unreadable_storage_without_partial_values() {
    JniFuncInfo target{"FixedOverflow", JniType::kVoid, "JNIEnv",
                       {JniType::kLong, JniType::kLong, JniType::kLong, JniType::kLong,
                        JniType::kLong, JniType::kLong, JniType::kLong, JniType::kLong}};
    Arm64JniArguments frame;
    frame.general = {0, 1, 2, 3, 4, 5, 6, 7};
    const uint64_t stack[] = {8};
    frame.stack = reinterpret_cast<uintptr_t>(stack);
    const auto decoded = decode_arm64_jni_fixed_arguments(target, frame, safe_read_memory);
    CHECK(decoded.error.empty() && decoded.values.size() == 8 && decoded.values.back().bits == 8);
    frame.stack = 0;
    const auto unavailable = decode_arm64_jni_fixed_arguments(target, frame, safe_read_memory);
    CHECK(unavailable.error == "unreadable JNI argument storage" && unavailable.values.empty());
}

void va_list_is_decoded_without_consuming_target_storage() {
    Fixture fixture;
    Arm64JniArguments call;
    call.general[3] = reinterpret_cast<uintptr_t>(&fixture.list);
    const auto original = fixture.list;
    check_mixed(decode_arm64_jni_arguments(function("CallLongMethodV", "va_list"), call, signature, safe_read_memory));
    CHECK(std::memcmp(&fixture.list, &original, sizeof(original)) == 0);
}

void jvalue_array_uses_typed_union_members_without_vararg_promotions() {
    Fixture fixture;
    fixture.frame.general[3] = reinterpret_cast<uintptr_t>(fixture.array);
    check_mixed(decode_arm64_jni_arguments(function("CallLongMethodA", "jvalue*"), fixture.frame, signature, safe_read_memory));
}

void exhausted_va_list_register_offsets_can_be_positive() {
    Fixture fixture;
    uint64_t stack[] = {uint32_t(-23), bits(-2.5)};
    fixture.list = {reinterpret_cast<uintptr_t>(stack), 0, 0, 8, 16};
    Arm64JniArguments call;
    call.general[3] = reinterpret_cast<uintptr_t>(&fixture.list);
    const auto decoded = decode_arm64_jni_arguments(function("CallLongMethodV", "va_list"), call, "f(ID)J", safe_read_memory);
    CHECK(decoded.error.empty() && decoded.values.size() == 2);
    CHECK(uint32_t(decoded.values[0].bits) == uint32_t(-23));
    CHECK(decoded.values[1].bits == bits(-2.5));
}

void constructors_and_nonvirtual_calls_use_their_own_fixed_argument_count() {
    Arm64JniArguments call;
    call.general[3] = 0x1234567800000017;
    auto decoded = decode_arm64_jni_arguments(function("NewObject", "..."), call, "<init>(I)V", safe_read_memory);
    CHECK(decoded.error.empty() && decoded.values.size() == 1 && uint32_t(decoded.values[0].bits) == 23);
    call.general[4] = uint32_t(-23);
    decoded = decode_arm64_jni_arguments(function("CallNonvirtualLongMethod", "...", true), call, "value(I)J", safe_read_memory);
    CHECK(decoded.error.empty() && uint32_t(decoded.values[0].bits) == uint32_t(-23));
    Fixture fixture;
    call.general[4] = reinterpret_cast<uintptr_t>(fixture.array);
    check_mixed(decode_arm64_jni_arguments(function("CallNonvirtualLongMethodA", "jvalue*", true), call, signature, safe_read_memory));
}

void unavailable_or_invalid_inputs_never_return_partial_plausible_values() {
    const auto target = function("CallLongMethodV", "va_list");
    Fixture fixture;
    Arm64JniArguments call;
    call.general[3] = reinterpret_cast<uintptr_t>(&fixture.list);
    CHECK(decode_arm64_jni_arguments(target, call, std::nullopt, safe_read_memory).error == "method signature unavailable");
    for (const char *invalid : {"broken", "bad(IX)J", "bad(I)Vtrailing", "bad([V)J", "bad(ILfoo)J", "bad(I"}) {
        const auto decoded = decode_arm64_jni_arguments(target, call, invalid, safe_read_memory);
        CHECK(decoded.error == "invalid method signature" && decoded.values.empty());
    }
    const std::string embedded_null = std::string("bad(Lfoo") + '\0' + ";)J";
    CHECK(decode_arm64_jni_arguments(target, call, embedded_null, safe_read_memory).error == "invalid method signature");
    fixture.list.general_offset = -7;
    CHECK(decode_arm64_jni_arguments(target, call, signature, safe_read_memory).error == "invalid arm64 va_list offsets");
    call.general[3] = 1;
    CHECK(decode_arm64_jni_arguments(target, call, signature, safe_read_memory).error == "unreadable va_list");
    call.general[3] = std::numeric_limits<uintptr_t>::max() - 7;
    const auto invalid_array = decode_arm64_jni_arguments(function("CallLongMethodA", "jvalue*"), call, "f(II)J", safe_read_memory);
    CHECK(!invalid_array.error.empty() && invalid_array.values.empty());
    call.general = {};
    call.stack = 1;
    const auto invalid_stack = decode_arm64_jni_arguments(function("CallLongMethod", "..."), call, "f(IIIIII)J", safe_read_memory);
    CHECK(invalid_stack.error == "unaligned arm64 argument stack" && invalid_stack.values.empty());
    const auto missing_fp = decode_arm64_jni_arguments(function("CallLongMethod", "..."), call, "f(F)J", safe_read_memory);
    CHECK(missing_fp.error == "floating argument registers unavailable" && missing_fp.values.empty());
    CHECK(decode_arm64_jni_arguments(target, call, "f()J", safe_read_memory).error.empty());
}

void signed_and_floating_output_uses_jni_widths_and_bit_representations() {
    CHECK(JniFormatter::format_arg("jint", 0x7fff80000000) == "0x80000000 (-2147483648)");
    CHECK(JniFormatter::format_arg("jbyte", 0xfffffffb) == "0xfb (-5)");
    CHECK(JniFormatter::format_arg("jshort", 0xfffffb2e) == "0xfb2e (-1234)");
    CHECK(JniFormatter::format_arg("jchar", 0xffffffff00008123) == "0x8123 (33059)");
    CHECK(JniFormatter::format_arg("jdouble", bits(-3.25)).find("(-3.25)") != std::string::npos);
    JniFormatter formatter;
    const auto target = function("CallDoubleMethod", "...");
    CHECK(formatter.format_leave(1, 0, target, 0, false).find("undecoded") != std::string::npos);
}
} // namespace

int main() {
    ordinary_reads_independent_register_banks_and_shared_stack();
    fixed_scalars_do_not_promote_float_or_advance_the_other_register_bank();
    fixed_stack_arguments_refuse_unreadable_storage_without_partial_values();
    va_list_is_decoded_without_consuming_target_storage();
    jvalue_array_uses_typed_union_members_without_vararg_promotions();
    exhausted_va_list_register_offsets_can_be_positive();
    constructors_and_nonvirtual_calls_use_their_own_fixed_argument_count();
    unavailable_or_invalid_inputs_never_return_partial_plausible_values();
    signed_and_floating_output_uses_jni_widths_and_bit_representations();
}
