// Standalone ART fixture. Run through app_process with JniAbiProbe.dex.
#include <jni.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include "third_party/nlohmann/json.hpp"

using nlohmann::json;
namespace {
using Configure = int (*)(const char *, uint64_t, char *, uint64_t, uint64_t *);
using Status = int (*)(uint64_t, char *, uint64_t, uint64_t *);
JavaVM *java_vm;

json snapshot_probe(void *tracer, JNIEnv *env) {
    auto snapshot = reinterpret_cast<Configure>(dlsym(tracer,"qbdi_tracer_snapshot_json"));
    if (!snapshot) return {{"error","snapshot export missing"}};
    char stat[4096]{};
    FILE *source = std::fopen("/proc/self/stat","re");
    if (!source) return {{"error","stat unavailable"}};
    const bool read = std::fgets(stat,sizeof(stat),source) != nullptr;
    std::fclose(source);
    char *cursor = read ? std::strrchr(stat,')') : nullptr;
    if (!cursor) return {{"error","stat invalid"}};
    ++cursor;
    std::string epoch;
    for (unsigned index = 0; index <= 19; ++index) {
        while (*cursor == ' ') ++cursor;
        char *end = cursor;
        while (*end && *end != ' ' && *end != '\n') ++end;
        if (index == 19) epoch.assign(cursor,end);
        cursor = end;
    }
    json request = {{"schema",1},{"expectedPid",getpid()},{"expectedStarttime",epoch},
                    {"includeJava",true},{"maxThreads",32},{"maxFrames",32}};
    bool preserved_errno = true;
    const auto capture = [&](const json &value) {
        const auto input = value.dump();
        char output[65536]{}; uint64_t length = 0;
        errno = 123;
        const int code = snapshot(input.data(),input.size(),output,sizeof(output),&length);
        preserved_errno &= errno == 123;
        if (code || length < 2 || length > sizeof(output) || output[length-1])
            return json{{"error","snapshot transport"},{"code",code},{"size",length}};
        return json::parse(output,output+length-1);
    };
    json result;
    result["available"] = capture(request);
    request["includeJava"] = false;
    result["disabled"] = capture(request);
    request["includeJava"] = true;
    request["expectedStarttime"] = "1";
    result["wrong_epoch"] = capture(request);
    request["expectedStarttime"] = epoch;
    jclass exception = env->FindClass("java/lang/IllegalStateException");
    env->ThrowNew(exception,"snapshot-existing-exception");
    const auto before = env->ExceptionOccurred();
    result["pending"] = capture(request);
    const auto after = env->ExceptionOccurred();
    env->ExceptionClear();
    result["exception_preserved"] = before && after && env->IsSameObject(before,after);
    env->DeleteLocalRef(before); env->DeleteLocalRef(after); env->DeleteLocalRef(exception);
    JNIEnv *current = nullptr;
    result["attachment_preserved"] = java_vm->GetEnv(reinterpret_cast<void **>(&current),JNI_VERSION_1_6) == JNI_OK && current == env;
    result["errno_preserved"] = preserved_errno;
    bool rejected = true;
    for (const char *field : {"maxThreads","maxFrames","schema"}) {
        auto invalid = request; invalid[field] = field == std::string("schema") ? json(true) : json(0);
        const auto input = invalid.dump(); char output[32]; std::memset(output,'q',sizeof(output));
        uint64_t length = 0;
        rejected &= snapshot(input.data(),input.size(),output,sizeof(output),&length) == 2 && output[0] == 'q';
    }
    request["includeJava"] = false;
    const auto input = request.dump(); char output[8]; std::memset(output,'q',sizeof(output)); uint64_t required = 0;
    result["transport_bounds"] = rejected &&
        snapshot(input.data(),input.size(),output,sizeof(output),&required) == 1 &&
        required > sizeof(output) && required <= 65536 && output[0] == 'q';
    return result;
}

__attribute__((noinline, optnone)) uintptr_t platform_register() {
    uintptr_t value;
    asm volatile("mov %0, x18" : "=r"(value));
    return value;
}

__attribute__((noinline, optnone)) uint64_t stack_in_bounds() {
    pthread_attr_t attributes;
    void *base = nullptr;
    size_t size = 0;
    char local;
    if (pthread_getattr_np(pthread_self(), &attributes)) return 0;
    const int error = pthread_attr_getstack(&attributes, &base, &size);
    pthread_attr_destroy(&attributes);
    const uintptr_t pointer = reinterpret_cast<uintptr_t>(&local);
    return !error && pointer >= reinterpret_cast<uintptr_t>(base) &&
           pointer - reinterpret_cast<uintptr_t>(base) < size;
}

jlong call_long_v(JNIEnv *env, jclass type, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    const jlong result = env->functions->CallStaticLongMethodV(env, type, method, arguments);
    va_end(arguments);
    return result;
}

jdouble call_double_v(JNIEnv *env, jclass type, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    const jdouble result = env->functions->CallStaticDoubleMethodV(env, type, method, arguments);
    va_end(arguments);
    return result;
}

jint call_int_v(JNIEnv *env, jclass type, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    const jint result = env->functions->CallStaticIntMethodV(env, type, method, arguments);
    va_end(arguments);
    return result;
}

jobject new_object_v(JNIEnv *env, jclass type, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    jobject result = env->functions->NewObjectV(env, type, method, arguments);
    va_end(arguments);
    return result;
}

jlong call_instance_v(JNIEnv *env, jobject receiver, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    const jlong result = env->functions->CallLongMethodV(env, receiver, method, arguments);
    va_end(arguments);
    return result;
}

jlong call_nonvirtual_v(JNIEnv *env, jobject receiver, jclass type, jmethodID method, ...) {
    va_list arguments;
    va_start(arguments, method);
    const jlong result = env->functions->CallNonvirtualLongMethodV(env, receiver, type, method, arguments);
    va_end(arguments);
    return result;
}

struct ReceiverContext {
    jclass base = nullptr;
    jclass derived = nullptr;
    jobject object = nullptr;
};

// This function is the only JNI argument scene. Its entry has integer/pointer
// parameters, so the gateway does not need to accept floating point arguments.
__attribute__((noinline, optnone)) uint64_t exercise(
        JNIEnv *env, jclass type, jbyteArray bytes, int mode, int scenario,
        ReceiverContext *receivers) {
    if (scenario < 2) {
        const jint a = scenario == 0 ? 2 : INT32_MIN;
        const jint b = scenario == 0 ? -38 : INT32_MAX;
        jmethodID method = env->GetStaticMethodID(type, "simple", "(II[B)J");
        if (!method) return 0;
        jvalue arguments[3]{};
        arguments[0].i = a; arguments[1].i = b; arguments[2].l = bytes;
        if (mode == 0) return env->functions->CallStaticLongMethod(env, type, method, a, b, bytes);
        if (mode == 1) return call_long_v(env, type, method, a, b, bytes);
        return env->functions->CallStaticLongMethodA(env, type, method, arguments);
    }
    if (scenario == 2) {
        jmethodID method = env->GetStaticMethodID(type, "mixed", "(IJDF[BIIIIIIIDDDDDDDD)J");
        if (!method) return 0;
        const jlong wide = -81985529216486895LL;
        jvalue arguments[20]{};
        arguments[0].i = -17; arguments[1].j = wide;
        arguments[2].d = -2.5; arguments[3].f = 1.25f; arguments[4].l = bytes;
        const jint ints[] = {5, -6, 7, -8, 9, -10, 11};
        const jdouble doubles[] = {0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5};
        for (size_t i = 0; i < 7; ++i) arguments[5 + i].i = ints[i];
        for (size_t i = 0; i < 8; ++i) arguments[12 + i].d = doubles[i];
        if (mode == 0) return env->functions->CallStaticLongMethod(env, type, method,
                -17, wide, -2.5, 1.25, bytes, 5, -6, 7, -8, 9, -10, 11,
                0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5);
        if (mode == 1) return call_long_v(env, type, method,
                -17, wide, -2.5, 1.25, bytes, 5, -6, 7, -8, 9, -10, 11,
                0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5);
        return env->functions->CallStaticLongMethodA(env, type, method, arguments);
    }
    if (scenario == 3) {
        jmethodID method = env->GetStaticMethodID(type, "narrow", "(ZBSCF)D");
        if (!method) return 0;
        jvalue arguments[5]{};
        arguments[0].z = JNI_TRUE; arguments[1].b = -5; arguments[2].s = -1234;
        arguments[3].c = 0x8123; arguments[4].f = -1.5f;
        const jdouble value = mode == 0
                ? env->functions->CallStaticDoubleMethod(env, type, method, JNI_TRUE, -5, -1234, 0x8123, -1.5)
                : mode == 1 ? call_double_v(env, type, method, JNI_TRUE, -5, -1234, 0x8123, -1.5)
                : env->functions->CallStaticDoubleMethodA(env, type, method, arguments);
        return value == -3.25 ? 42 : 0;
    }
    if (scenario == 4) {
        jmethodID method = env->GetStaticMethodID(type, "throwing", "(I)I");
        if (!method) return 0;
        jvalue arguments[1]{}; arguments[0].i = -23;
        if (mode == 0) return env->functions->CallStaticIntMethod(env, type, method, -23);
        if (mode == 1) return call_int_v(env, type, method, -23);
        return env->functions->CallStaticIntMethodA(env, type, method, arguments);
    }
    if (scenario == 5) {
        jfieldID f = env->GetFieldID(receivers->base, "floatValue", "F");
        jfieldID d = env->GetFieldID(receivers->base, "doubleValue", "D");
        jfieldID sf = env->GetStaticFieldID(receivers->base, "staticFloatValue", "F");
        jfieldID sd = env->GetStaticFieldID(receivers->base, "staticDoubleValue", "D");
        if (!f || !d || !sf || !sd) return 0;
        env->SetFloatField(receivers->object, f, -1.5f);
        env->SetDoubleField(receivers->object, d, -3.25);
        env->SetStaticFloatField(receivers->base, sf, 1.25f);
        env->SetStaticDoubleField(receivers->base, sd, -2.5);
        const bool native_values = env->GetFloatField(receivers->object, f) == -1.5f &&
                env->GetDoubleField(receivers->object, d) == -3.25 &&
                env->GetStaticFloatField(receivers->base, sf) == 1.25f &&
                env->GetStaticDoubleField(receivers->base, sd) == -2.5;
        jmethodID method = env->GetStaticMethodID(type, "checkFields", "(Lorg/qbdi/abi/JniAbiProbe$BaseReceiver;)I");
        if (!method) return 0;
        const jint java_values = env->CallStaticIntMethod(type, method, receivers->object);
        return native_values && java_values == 42 ? 42 : 0;
    }
    jvalue arguments[3]{};
    arguments[0].i = 2; arguments[1].i = -38; arguments[2].l = bytes;
    if (scenario == 6) {
        jmethodID method = env->GetMethodID(receivers->base, "<init>", "(II[B)V");
        if (!method) return 0;
        jobject object = mode == 0 ? env->functions->NewObject(env, receivers->base, method, 2, -38, bytes)
                : mode == 1 ? new_object_v(env, receivers->base, method, 2, -38, bytes)
                : env->functions->NewObjectA(env, receivers->base, method, arguments);
        jfieldID valid = env->GetFieldID(receivers->base, "valid", "Z");
        const bool passed = object && valid && env->GetBooleanField(object, valid);
        if (object) env->DeleteLocalRef(object);
        return passed ? 42 : 0;
    }
    const bool nonvirtual = scenario == 8;
    jmethodID method = env->GetMethodID(nonvirtual ? receivers->base : receivers->derived, "value", "(II[B)J");
    if (!method) return 0;
    if (nonvirtual) {
        if (mode == 0) return env->functions->CallNonvirtualLongMethod(env, receivers->object, receivers->base, method, 2, -38, bytes);
        if (mode == 1) return call_nonvirtual_v(env, receivers->object, receivers->base, method, 2, -38, bytes);
        return env->functions->CallNonvirtualLongMethodA(env, receivers->object, receivers->base, method, arguments);
    }
    if (mode == 0) return env->functions->CallLongMethod(env, receivers->object, method, 2, -38, bytes);
    if (mode == 1) return call_instance_v(env, receivers->object, method, 2, -38, bytes);
    return env->functions->CallLongMethodA(env, receivers->object, method, arguments);
}

__attribute__((noinline, optnone)) void *attach_callback(void *) {
    JNIEnv *env = nullptr;
    if (java_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return nullptr;
    jclass type = env->FindClass("java/lang/Integer");
    jmethodID method = type ? env->GetStaticMethodID(type, "parseInt", "(Ljava/lang/String;)I") : nullptr;
    jstring text = env->NewStringUTF("42");
    const jint value = method && text ? env->CallStaticIntMethod(type, method, text) : 0;
    const bool passed = value == 42 && !env->ExceptionCheck();
    java_vm->DetachCurrentThread();
    return reinterpret_cast<void *>(passed ? 42 : 0);
}

struct Work {
    jclass type;
    std::string directory, package, session;
    Configure configure;
    Status status;
    ReceiverContext receivers;
    json result = json::object();
};

void *worker(void *opaque) {
    auto &work = *static_cast<Work *>(opaque);
    JNIEnv *env = nullptr;
    if (java_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return nullptr;
    jbyteArray bytes = env->NewByteArray(5);
    const jbyte input[] = {0, -1, 42, 127, -128};
    env->SetByteArrayRegion(bytes, 0, 5, input);
    const jmethodID context = env->GetStaticMethodID(work.type, "context", "(Ljava/lang/String;I)V");
    const jmethodID reset_fields = env->GetStaticMethodID(work.type, "resetFields", "(Lorg/qbdi/abi/JniAbiProbe$BaseReceiver;)V");
    const jmethodID constructor = env->GetMethodID(work.receivers.derived, "<init>", "()V");
    if (!context || !reset_fields || !constructor) { java_vm->DetachCurrentThread(); return nullptr; }
    work.receivers.object = env->NewObject(work.receivers.derived, constructor);
    if (!work.receivers.object || env->ExceptionCheck()) { java_vm->DetachCurrentThread(); return nullptr; }
    work.result["native_input"] = {{"bytes", {0, -1, 42, 127, -128}},
        {"simple", {2, -38}}, {"extremes", {INT32_MIN, INT32_MAX}},
        {"mixed", {-17, -81985529216486895LL, -2.5, 1.25}},
        {"ints", {5, -6, 7, -8, 9, -10, 11}},
        {"doubles", {0.5, -1.5, 2.5, -3.5, 4.5, -5.5, 6.5, -7.5}},
        {"narrow", {true, -5, -1234, 0x8123, -1.5}},
        {"fields", {-1.5, -3.25, 1.25, -2.5}}};
    work.result["byte_array_handle"] = reinterpret_cast<uintptr_t>(bytes);
    work.result["baseline_x18"] = platform_register();
    work.result["baseline_stack"] = stack_in_bounds();
    for (int phase = 0; phase < 2; ++phase) {
        if (phase) {
            Dl_info info{};
            dladdr(reinterpret_cast<void *>(exercise), &info);
            json scenes = json::array();
            const auto scene = [&](const char *name, uintptr_t pointer) {
                char offset[32];
                snprintf(offset, sizeof(offset), "0x%lx", pointer - reinterpret_cast<uintptr_t>(info.dli_fbase));
                scenes.push_back({{"name", name}, {"location", {{"offset", offset}}}});
            };
            scene("jni-arguments", reinterpret_cast<uintptr_t>(exercise));
            scene("platform-register", reinterpret_cast<uintptr_t>(platform_register));
            scene("thread-stack", reinterpret_cast<uintptr_t>(stack_in_bounds));
            scene("attach-callback", reinterpret_cast<uintptr_t>(attach_callback));
            json request = {{"schemaVersion", 1}, {"packageName", work.package},
                {"targetModule", "libjni_abi_probe.so"},
                {"trace", {{"profile", "full"}, {"compression", false}, {"lz4Level", 0},
                    {"autoBuffer", false}, {"bufferMb", 8}, {"hexdumpLimit", 0}}},
                {"flight", {{"enabled", false}, {"followThreads", false}, {"entryScene", ""},
                    {"capacityMb", 64}, {"chunkKb", 256}, {"maxThreads", 4}, {"protectedChunks", 2}}},
                {"session", {{"id", work.session}}}, {"scenes", scenes}};
            work.result["configuration"] = request;
            const std::string document = request.dump();
            char response[65536]{}; uint64_t length = 0;
            if (work.configure(document.data(), document.size(), response, sizeof(response), &length)) {
                work.result["error"] = response; break;
            }
            for (int attempt = 0; attempt < 100; ++attempt) {
                work.status(1, response, sizeof(response), &length);
                if (strstr(response, "\"state\":\"installed\"")) break;
                usleep(20000);
            }
            if (!strstr(response, "\"state\":\"installed\"")) {
                work.result["error"] = response; break;
            }
            work.result["traced_x18"] = platform_register();
            work.result["traced_stack"] = stack_in_bounds();
        }
        const char *label = phase ? "traced" : "baseline";
        for (int mode = 0; mode < 3; ++mode) {
            jstring text = env->NewStringUTF(label);
            env->CallStaticVoidMethod(work.type, context, text, mode);
            env->DeleteLocalRef(text);
            for (int scenario = 0; scenario < 9; ++scenario) {
                // Each setter must change a fresh value, including after the
                // baseline phase. Reset outside the instrumented JNI scene.
                if (scenario == 5) env->CallStaticVoidMethod(work.type, reset_fields, work.receivers.object);
                const uint64_t value = exercise(env, work.type, bytes, mode, scenario, &work.receivers);
                const bool exception = env->ExceptionCheck();
                work.result[label].push_back({{"mode", mode}, {"case", scenario},
                    {"return", value}, {"pending_exception", exception}});
                if (exception) env->ExceptionClear();
            }
        }
    }
    java_vm->DetachCurrentThread();
    return nullptr;
}
} // namespace

extern "C" JNIEXPORT jstring JNICALL Java_org_qbdi_abi_JniAbiProbe_run(
        JNIEnv *env, jclass type, jstring directory, jstring package, jstring session) {
    alarm(45);
    const auto string = [&](jstring value) {
        const char *text = env->GetStringUTFChars(value, nullptr);
        std::string result(text); env->ReleaseStringUTFChars(value, text); return result;
    };
    Work work{static_cast<jclass>(env->NewGlobalRef(type)), string(directory), string(package), string(session), nullptr, nullptr};
    jclass base = env->FindClass("org/qbdi/abi/JniAbiProbe$BaseReceiver");
    jclass derived = env->FindClass("org/qbdi/abi/JniAbiProbe$DerivedReceiver");
    if (!base || !derived || env->ExceptionCheck()) return nullptr;
    work.receivers.base = static_cast<jclass>(env->NewGlobalRef(base));
    work.receivers.derived = static_cast<jclass>(env->NewGlobalRef(derived));
    env->GetJavaVM(&java_vm);
    void *tracer = dlopen((work.directory + "/libqbdi_tracer.so").c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!tracer) return env->NewStringUTF(dlerror());
    auto companion = reinterpret_cast<int (*)(const char *)>(dlsym(tracer, "qbdi_tracer_set_shadowhook_helper_path"));
    work.configure = reinterpret_cast<Configure>(dlsym(tracer, "qbdi_tracer_configure_json"));
    work.status = reinterpret_cast<Status>(dlsym(tracer, "qbdi_tracer_get_status_json"));
    if (!companion || !work.configure || !work.status || companion((work.directory + "/libshadowhook_nothing.so").c_str()))
        return env->NewStringUTF("missing tracer exports or companion");
    pthread_t thread;
    void *baseline = nullptr, *traced = nullptr;
    if (pthread_create(&thread, nullptr, attach_callback, nullptr) || pthread_join(thread, &baseline))
        return env->NewStringUTF("baseline attach failed");
    if (pthread_create(&thread, nullptr, worker, &work) || pthread_join(thread, nullptr))
        return env->NewStringUTF("worker failed");
    if (pthread_create(&thread, nullptr, attach_callback, nullptr) || pthread_join(thread, &traced))
        return env->NewStringUTF("traced attach failed");
    work.result["baseline_attach"] = reinterpret_cast<uintptr_t>(baseline);
    work.result["traced_attach"] = reinterpret_cast<uintptr_t>(traced);
    work.result["pid"] = getpid();
    char response[65536]{}; uint64_t length = 0;
    work.status(1, response, sizeof(response), &length);
    work.result["status"] = json::parse(response);
    work.result["diagnostics"] = snapshot_probe(tracer,env);
    env->DeleteGlobalRef(work.type);
    env->DeleteGlobalRef(work.receivers.base);
    env->DeleteGlobalRef(work.receivers.derived);
    alarm(0);
    return env->NewStringUTF(work.result.dump().c_str());
}
