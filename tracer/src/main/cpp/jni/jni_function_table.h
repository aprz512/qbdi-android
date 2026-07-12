#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

// ── JNI 类型标签 ──────────────────────────────────────────────
// 对标 jnitrace 的类型系统，用于参数/返回值格式化
namespace JniType {
    constexpr const char *kVoid     = "void";
    constexpr const char *kBoolean  = "jboolean";
    constexpr const char *kByte     = "jbyte";
    constexpr const char *kChar     = "jchar";
    constexpr const char *kShort    = "jshort";
    constexpr const char *kInt      = "jint";
    constexpr const char *kLong     = "jlong";
    constexpr const char *kFloat    = "jfloat";
    constexpr const char *kDouble   = "jdouble";
    constexpr const char *kSize     = "jsize";
    constexpr const char *kObject   = "jobject";
    constexpr const char *kClass    = "jclass";
    constexpr const char *kString   = "jstring";
    constexpr const char *kArray    = "jarray";
    constexpr const char *kThrowable= "jthrowable";
    constexpr const char *kWeak     = "jweak";
    constexpr const char *kMethodID = "jmethodID";
    constexpr const char *kFieldID  = "jfieldID";
    constexpr const char *kPointer  = "jvalue*";
    constexpr const char *kVaList   = "va_list";
    constexpr const char *kVarArgs  = "...";
}

// ── 单个 JNI 函数的元信息 ────────────────────────────────────
struct JniFuncInfo {
    const char *name;                 // "FindClass", "GetMethodID", ...
    const char *ret_type;             // "jclass", "jint", "void", ...
    const char *struct_name;          // "JNIEnv" or "JavaVM"
    std::vector<const char *> args;   // 参数类型列表 (不含 JNIEnv* / JavaVM*)
    uintptr_t address = 0;            // 运行时解析的实际地址
};

// ── 完整 JNI 函数表 (JNI 1.6, ~230 个函数) ─────────────────
// 参数签名来自 jni.h，顺序与 JNINativeInterface vtable 一致
inline std::vector<JniFuncInfo> build_jni_function_table() {
    std::vector<JniFuncInfo> table;

    // ─── 保留槽位 (indices 0-3) ───
    // 跳过，由 vtable 实际布局决定

    // ─── 版本 & 类操作 ───
    table.push_back({"GetVersion",        JniType::kInt,    "JNIEnv", {}});
    table.push_back({"DefineClass",       JniType::kClass,  "JNIEnv", {JniType::kString, JniType::kObject, JniType::kPointer, JniType::kSize}});
    table.push_back({"FindClass",         JniType::kClass,  "JNIEnv", {JniType::kString}});
    table.push_back({"FromReflectedMethod",JniType::kMethodID,"JNIEnv",{JniType::kObject}});
    table.push_back({"FromReflectedField",JniType::kFieldID, "JNIEnv", {JniType::kObject}});
    table.push_back({"ToReflectedMethod", JniType::kObject, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kBoolean}});
    table.push_back({"GetSuperclass",     JniType::kClass,  "JNIEnv", {JniType::kClass}});
    table.push_back({"IsAssignableFrom",  JniType::kBoolean,"JNIEnv", {JniType::kClass, JniType::kClass}});
    table.push_back({"ToReflectedField",  JniType::kObject, "JNIEnv", {JniType::kClass, JniType::kFieldID, JniType::kBoolean}});

    // ─── 异常 ───
    table.push_back({"Throw",             JniType::kInt,    "JNIEnv", {JniType::kThrowable}});
    table.push_back({"ThrowNew",          JniType::kInt,    "JNIEnv", {JniType::kClass, JniType::kString}});
    table.push_back({"ExceptionOccurred", JniType::kThrowable,"JNIEnv",{}});
    table.push_back({"ExceptionDescribe", JniType::kVoid,   "JNIEnv", {}});
    table.push_back({"ExceptionClear",    JniType::kVoid,   "JNIEnv", {}});
    table.push_back({"FatalError",        JniType::kVoid,   "JNIEnv", {JniType::kString}});

    // ─── 局部/全局引用 ───
    table.push_back({"PushLocalFrame",    JniType::kInt,    "JNIEnv", {JniType::kInt}});
    table.push_back({"PopLocalFrame",     JniType::kObject, "JNIEnv", {JniType::kObject}});
    table.push_back({"NewGlobalRef",      JniType::kObject, "JNIEnv", {JniType::kObject}});
    table.push_back({"DeleteGlobalRef",   JniType::kVoid,   "JNIEnv", {JniType::kObject}});
    table.push_back({"DeleteLocalRef",    JniType::kVoid,   "JNIEnv", {JniType::kObject}});
    table.push_back({"IsSameObject",      JniType::kBoolean,"JNIEnv", {JniType::kObject, JniType::kObject}});
    table.push_back({"NewLocalRef",       JniType::kObject, "JNIEnv", {JniType::kObject}});
    table.push_back({"EnsureLocalCapacity",JniType::kInt,   "JNIEnv", {JniType::kInt}});

    // ─── 对象操作 ───
    table.push_back({"AllocObject",       JniType::kObject, "JNIEnv", {JniType::kClass}});
    table.push_back({"NewObject",         JniType::kObject, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kVarArgs}});
    table.push_back({"NewObjectV",        JniType::kObject, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kVaList}});
    table.push_back({"NewObjectA",        JniType::kObject, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kPointer}});
    table.push_back({"GetObjectClass",    JniType::kClass,  "JNIEnv", {JniType::kObject}});
    table.push_back({"IsInstanceOf",      JniType::kBoolean,"JNIEnv", {JniType::kObject, JniType::kClass}});
    table.push_back({"GetMethodID",       JniType::kMethodID,"JNIEnv",{JniType::kClass, JniType::kString, JniType::kString}});
    table.push_back({"GetFieldID",        JniType::kFieldID,"JNIEnv", {JniType::kClass, JniType::kString, JniType::kString}});

    // ─── Call<Type>Method (实例方法) ───
    #define CALL_METHODS(RetType, JavaType) \
        table.push_back({"Call" #JavaType "Method",    RetType, "JNIEnv", {JniType::kObject, JniType::kMethodID, JniType::kVarArgs}}); \
        table.push_back({"Call" #JavaType "MethodV",   RetType, "JNIEnv", {JniType::kObject, JniType::kMethodID, JniType::kVaList}}); \
        table.push_back({"Call" #JavaType "MethodA",   RetType, "JNIEnv", {JniType::kObject, JniType::kMethodID, JniType::kPointer}});

    CALL_METHODS(JniType::kObject,  Object)
    CALL_METHODS(JniType::kBoolean, Boolean)
    CALL_METHODS(JniType::kByte,    Byte)
    CALL_METHODS(JniType::kChar,    Char)
    CALL_METHODS(JniType::kShort,   Short)
    CALL_METHODS(JniType::kInt,     Int)
    CALL_METHODS(JniType::kLong,    Long)
    CALL_METHODS(JniType::kFloat,   Float)
    CALL_METHODS(JniType::kDouble,  Double)
    CALL_METHODS(JniType::kVoid,    Void)

    // ─── CallNonvirtual<Type>Method ───
    #define CALL_NV_METHODS(RetType, JavaType) \
        table.push_back({"CallNonvirtual" #JavaType "Method",    RetType, "JNIEnv", {JniType::kObject, JniType::kClass, JniType::kMethodID, JniType::kVarArgs}}); \
        table.push_back({"CallNonvirtual" #JavaType "MethodV",   RetType, "JNIEnv", {JniType::kObject, JniType::kClass, JniType::kMethodID, JniType::kVaList}}); \
        table.push_back({"CallNonvirtual" #JavaType "MethodA",   RetType, "JNIEnv", {JniType::kObject, JniType::kClass, JniType::kMethodID, JniType::kPointer}});

    CALL_NV_METHODS(JniType::kObject,  Object)
    CALL_NV_METHODS(JniType::kBoolean, Boolean)
    CALL_NV_METHODS(JniType::kByte,    Byte)
    CALL_NV_METHODS(JniType::kChar,    Char)
    CALL_NV_METHODS(JniType::kShort,   Short)
    CALL_NV_METHODS(JniType::kInt,     Int)
    CALL_NV_METHODS(JniType::kLong,    Long)
    CALL_NV_METHODS(JniType::kFloat,   Float)
    CALL_NV_METHODS(JniType::kDouble,  Double)
    CALL_NV_METHODS(JniType::kVoid,    Void)

    // ─── Get/Set<Type>Field ───
    #define FIELD_ACCESSORS(RetType, JavaType) \
        table.push_back({"Get" #JavaType "Field", RetType, "JNIEnv", {JniType::kObject, JniType::kFieldID}}); \
        table.push_back({"Set" #JavaType "Field", JniType::kVoid, "JNIEnv", {JniType::kObject, JniType::kFieldID, RetType}});

    FIELD_ACCESSORS(JniType::kObject,  Object)
    FIELD_ACCESSORS(JniType::kBoolean, Boolean)
    FIELD_ACCESSORS(JniType::kByte,    Byte)
    FIELD_ACCESSORS(JniType::kChar,    Char)
    FIELD_ACCESSORS(JniType::kShort,   Short)
    FIELD_ACCESSORS(JniType::kInt,     Int)
    FIELD_ACCESSORS(JniType::kLong,    Long)
    FIELD_ACCESSORS(JniType::kFloat,   Float)
    FIELD_ACCESSORS(JniType::kDouble,  Double)

    // ─── 静态方法 ───
    table.push_back({"GetStaticMethodID", JniType::kMethodID, "JNIEnv", {JniType::kClass, JniType::kString, JniType::kString}});
    table.push_back({"GetStaticFieldID",  JniType::kFieldID,  "JNIEnv", {JniType::kClass, JniType::kString, JniType::kString}});

    #define CALL_STATIC_METHODS(RetType, JavaType) \
        table.push_back({"CallStatic" #JavaType "Method",    RetType, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kVarArgs}}); \
        table.push_back({"CallStatic" #JavaType "MethodV",   RetType, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kVaList}}); \
        table.push_back({"CallStatic" #JavaType "MethodA",   RetType, "JNIEnv", {JniType::kClass, JniType::kMethodID, JniType::kPointer}});

    CALL_STATIC_METHODS(JniType::kObject,  Object)
    CALL_STATIC_METHODS(JniType::kBoolean, Boolean)
    CALL_STATIC_METHODS(JniType::kByte,    Byte)
    CALL_STATIC_METHODS(JniType::kChar,    Char)
    CALL_STATIC_METHODS(JniType::kShort,   Short)
    CALL_STATIC_METHODS(JniType::kInt,     Int)
    CALL_STATIC_METHODS(JniType::kLong,    Long)
    CALL_STATIC_METHODS(JniType::kFloat,   Float)
    CALL_STATIC_METHODS(JniType::kDouble,  Double)
    CALL_STATIC_METHODS(JniType::kVoid,    Void)

    // ─── Get/SetStatic<Type>Field ───
    #define STATIC_FIELD_ACCESSORS(RetType, JavaType) \
        table.push_back({"GetStatic" #JavaType "Field", RetType, "JNIEnv", {JniType::kClass, JniType::kFieldID}}); \
        table.push_back({"SetStatic" #JavaType "Field", JniType::kVoid, "JNIEnv", {JniType::kClass, JniType::kFieldID, RetType}});

    STATIC_FIELD_ACCESSORS(JniType::kObject,  Object)
    STATIC_FIELD_ACCESSORS(JniType::kBoolean, Boolean)
    STATIC_FIELD_ACCESSORS(JniType::kByte,    Byte)
    STATIC_FIELD_ACCESSORS(JniType::kChar,    Char)
    STATIC_FIELD_ACCESSORS(JniType::kShort,   Short)
    STATIC_FIELD_ACCESSORS(JniType::kInt,     Int)
    STATIC_FIELD_ACCESSORS(JniType::kLong,    Long)
    STATIC_FIELD_ACCESSORS(JniType::kFloat,   Float)
    STATIC_FIELD_ACCESSORS(JniType::kDouble,  Double)

    // ─── 字符串操作 ───
    table.push_back({"NewString",            JniType::kString,  "JNIEnv", {JniType::kPointer, JniType::kSize}});
    table.push_back({"GetStringLength",      JniType::kSize,    "JNIEnv", {JniType::kString}});
    table.push_back({"GetStringChars",       JniType::kPointer, "JNIEnv", {JniType::kString, JniType::kBoolean}});
    table.push_back({"ReleaseStringChars",   JniType::kVoid,    "JNIEnv", {JniType::kString, JniType::kPointer}});
    table.push_back({"NewStringUTF",         JniType::kString,  "JNIEnv", {JniType::kString}});
    table.push_back({"GetStringUTFLength",   JniType::kSize,    "JNIEnv", {JniType::kString}});
    table.push_back({"GetStringUTFChars",    JniType::kString,  "JNIEnv", {JniType::kString, JniType::kBoolean}});
    table.push_back({"ReleaseStringUTFChars",JniType::kVoid,    "JNIEnv", {JniType::kString, JniType::kString}});
    table.push_back({"GetStringRegion",      JniType::kVoid,    "JNIEnv", {JniType::kString, JniType::kSize, JniType::kSize, JniType::kPointer}});
    table.push_back({"GetStringUTFRegion",   JniType::kVoid,    "JNIEnv", {JniType::kString, JniType::kSize, JniType::kSize, JniType::kPointer}});
    table.push_back({"GetStringCritical",    JniType::kPointer, "JNIEnv", {JniType::kString, JniType::kBoolean}});
    table.push_back({"ReleaseStringCritical",JniType::kVoid,    "JNIEnv", {JniType::kString, JniType::kPointer}});

    // ─── 数组操作 ───
    table.push_back({"GetArrayLength",       JniType::kSize,   "JNIEnv", {JniType::kArray}});
    table.push_back({"NewObjectArray",       JniType::kArray,  "JNIEnv", {JniType::kSize, JniType::kClass, JniType::kObject}});
    table.push_back({"GetObjectArrayElement",JniType::kObject, "JNIEnv", {JniType::kArray, JniType::kSize}});
    table.push_back({"SetObjectArrayElement",JniType::kVoid,   "JNIEnv", {JniType::kArray, JniType::kSize, JniType::kObject}});

    // jni.h: jbooleanArray, jbyteArray, ... 都是 jobject 的子类型, args 统一用 kArray
    #define PRIMITIVE_ARRAY_OPS(JavaType) \
        table.push_back({"New" #JavaType "Array",              JniType::kArray,  "JNIEnv", {JniType::kSize}}); \
        table.push_back({"Get" #JavaType "ArrayElements",      JniType::kPointer,"JNIEnv", {JniType::kArray, JniType::kBoolean}}); \
        table.push_back({"Release" #JavaType "ArrayElements",  JniType::kVoid,   "JNIEnv", {JniType::kArray, JniType::kPointer, JniType::kInt}}); \
        table.push_back({"Get" #JavaType "ArrayRegion",        JniType::kVoid,   "JNIEnv", {JniType::kArray, JniType::kSize, JniType::kSize, JniType::kPointer}}); \
        table.push_back({"Set" #JavaType "ArrayRegion",        JniType::kVoid,   "JNIEnv", {JniType::kArray, JniType::kSize, JniType::kSize, JniType::kPointer}});

    PRIMITIVE_ARRAY_OPS(Boolean)
    PRIMITIVE_ARRAY_OPS(Byte)
    PRIMITIVE_ARRAY_OPS(Char)
    PRIMITIVE_ARRAY_OPS(Short)
    PRIMITIVE_ARRAY_OPS(Int)
    PRIMITIVE_ARRAY_OPS(Long)
    PRIMITIVE_ARRAY_OPS(Float)
    PRIMITIVE_ARRAY_OPS(Double)

    table.push_back({"GetPrimitiveArrayCritical",    JniType::kPointer, "JNIEnv", {JniType::kArray, JniType::kBoolean}});
    table.push_back({"ReleasePrimitiveArrayCritical",JniType::kVoid,    "JNIEnv", {JniType::kArray, JniType::kPointer, JniType::kInt}});

    // ─── 注册 Native 方法 ───
    table.push_back({"RegisterNatives",   JniType::kInt,   "JNIEnv", {JniType::kClass, JniType::kPointer, JniType::kInt}});
    table.push_back({"UnregisterNatives", JniType::kInt,   "JNIEnv", {JniType::kClass}});

    // ─── 监视器 ───
    table.push_back({"MonitorEnter", JniType::kInt,  "JNIEnv", {JniType::kObject}});
    table.push_back({"MonitorExit",  JniType::kInt,  "JNIEnv", {JniType::kObject}});

    // ─── JavaVM ───
    table.push_back({"GetJavaVM",    JniType::kInt,  "JNIEnv", {JniType::kPointer}});

    // ─── NIO ───
    table.push_back({"NewDirectByteBuffer",     JniType::kObject,  "JNIEnv", {JniType::kPointer, JniType::kLong}});
    table.push_back({"GetDirectBufferAddress",  JniType::kPointer, "JNIEnv", {JniType::kObject}});
    table.push_back({"GetDirectBufferCapacity", JniType::kLong,    "JNIEnv", {JniType::kObject}});

    // ─── 弱引用 ───
    table.push_back({"NewWeakGlobalRef",   JniType::kWeak,  "JNIEnv", {JniType::kObject}});
    table.push_back({"DeleteWeakGlobalRef",JniType::kVoid,  "JNIEnv", {JniType::kWeak}});
    table.push_back({"ExceptionCheck",     JniType::kBoolean,"JNIEnv",{}});
    table.push_back({"GetObjectRefType",   JniType::kInt,   "JNIEnv", {JniType::kObject}});

    // ─── JavaVM 方法 (JNIInvokeInterface vtable) ───
    // 对标 jnitrace JavaVM callbacks (main.ts:83-87)
    // 注意: JavaVM 函数在独立 vtable 中, 需要单独解析
    table.push_back({"DestroyJavaVM",             JniType::kInt,   "JavaVM", {JniType::kPointer}});
    table.push_back({"AttachCurrentThread",       JniType::kInt,   "JavaVM", {JniType::kPointer, JniType::kPointer, JniType::kPointer}});
    table.push_back({"DetachCurrentThread",       JniType::kInt,   "JavaVM", {}});
    table.push_back({"GetEnv",                    JniType::kInt,   "JavaVM", {JniType::kPointer, JniType::kPointer, JniType::kPointer}});
    table.push_back({"AttachCurrentThreadAsDaemon",JniType::kInt,  "JavaVM", {JniType::kPointer, JniType::kPointer, JniType::kPointer}});

    return table;
}

// ── 地址 → 函数信息 查找表 ────────────────────────────────
using JniAddressMap = std::unordered_map<uintptr_t, const JniFuncInfo *>;
