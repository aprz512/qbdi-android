#include "core/diagnostics_snapshot.h"
#include "core/tracer_configuration.h"
#include "third_party/nlohmann/json.hpp"

#include <jni.h>
#include <shadowhook.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <memory>
#include <string>
#include <time.h>
#include <unistd.h>

namespace {
using nlohmann::json;
constexpr size_t kResponseBytes = 64 * 1024;
constexpr size_t kJavaBudget = 24 * 1024;

uint64_t monotonic_ns() {
    timespec now{};
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
        ? uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec : 0;
}

std::string starttime() {
    char raw[4096]{};
    FILE *source = std::fopen("/proc/self/stat", "re");
    if (source == nullptr) return {};
    const bool read = std::fgets(raw, sizeof(raw), source) != nullptr;
    std::fclose(source);
    char *tail = read ? std::strrchr(raw, ')') : nullptr;
    if (tail == nullptr) return {};
    ++tail;
    for (unsigned index = 0; index <= 19; ++index) {
        while (*tail == ' ') ++tail;
        char *end = tail;
        while (*end && *end != ' ' && *end != '\n') ++end;
        if (end == tail) return {};
        if (index == 19) return std::string(tail, end);
        tail = end;
    }
    return {};
}

std::string hex(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

std::string dump(const json &value) {
    return value.dump(-1, ' ', false, json::error_handler_t::replace);
}

json mappings() {
    json result = {{"status","unavailable"},{"reason","proc_maps_unreadable"},
                   {"truncated",false},{"rows",json::array()}};
    std::unique_ptr<FILE, decltype(&std::fclose)> source(std::fopen("/proc/self/maps", "re"),std::fclose);
    if (source == nullptr) return result;
    size_t bytes = 0;
    char line[4096];
    result["status"] = "available"; result["reason"] = "";
    // Reserve the bounded output for runtime and JIT mappings before filling
    // the remaining space with Java images. Address order can put hundreds of
    // boot image mappings ahead of libart. Each of three scans has a 1 MiB cap.
    for (unsigned priority = 0; priority < 3; ++priority) {
      std::rewind(source.get());
      size_t scanned = 0;
      while (std::fgets(line, sizeof(line), source.get())) {
        scanned += std::strlen(line);
        if (scanned > 1024 * 1024 || std::strchr(line, '\n') == nullptr) {
            result["truncated"] = true; break;
        }
        unsigned long long first = 0, last = 0, offset = 0;
        char permissions[5]{}; int path_offset = 0;
        if (std::sscanf(line, "%llx-%llx %4s %llx %*s %*s %n",
                        &first, &last, permissions, &offset, &path_offset) != 4 ||
            path_offset <= 0 || first >= last) continue;
        std::string path(line + path_offset);
        if (!path.empty() && path.back() == '\n') path.pop_back();
        const bool jit = path.find("jit") != std::string::npos;
        const bool art = path.find("libart.so") != std::string::npos ||
                         path.find("libandroid_runtime.so") != std::string::npos;
        const bool image = path.find("dalvik-") != std::string::npos ||
                           path.find(".oat") != std::string::npos ||
                           path.find(".odex") != std::string::npos ||
                           path.find(".vdex") != std::string::npos ||
                           path.find(".dex") != std::string::npos ||
                           path.find(".art") != std::string::npos;
        if (!jit && !art && !image) continue;
        if (priority != (art ? 0U : jit ? 1U : 2U)) continue;
        json row = {{"start",hex(first)},{"end",hex(last)},{"offset",hex(offset)},
                    {"permissions",permissions},{"path",path},
                    {"classification",art ? "art_runtime_name_match" : jit ? "jit_name_match" : "java_image_name_match"}};
        const auto size = dump(row).size();
        if (result["rows"].size() >= 64 || bytes + size > 16 * 1024) {
            result["truncated"] = true; break;
        }
        bytes += size;
        result["rows"].push_back(std::move(row));
      }
      if (std::ferror(source.get())) {
          result["status"] = "unavailable"; result["reason"] = "proc_maps_read_failed";
          result["rows"] = json::array(); break;
      }
    }
    return result;
}

json native_threads(unsigned maximum) {
    json result = {{"status","unavailable"},{"reason","proc_tasks_unreadable"},
                   {"truncated",false},{"rows",json::array()}};
    std::unique_ptr<DIR, decltype(&closedir)> directory(opendir("/proc/self/task"),closedir);
    if (directory == nullptr) return result;
    result["status"] = "available"; result["reason"] = "";
    for (;;) {
        errno = 0;
        const auto *entry = readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                result["status"] = "unavailable"; result["reason"] = "proc_tasks_read_failed";
                result["rows"] = json::array();
            }
            break;
        }
        const size_t length = std::strlen(entry->d_name);
        if (length == 0 || length > 10 || std::strspn(entry->d_name,"0123456789") != length) continue;
        if (result["rows"].size() >= maximum) { result["truncated"] = true; break; }
        char path[128], name[128]{};
        std::snprintf(path,sizeof(path),"/proc/self/task/%s/comm",entry->d_name);
        FILE *source = std::fopen(path,"re");
        bool readable = false;
        if (source != nullptr) {
            readable = std::fgets(name,sizeof(name),source) != nullptr;
            std::fclose(source);
        }
        name[std::strcspn(name,"\n")] = 0;
        result["rows"].push_back({{"tid",std::strtoul(entry->d_name,nullptr,10)},
                                  {"name",name},{"nameAvailable",readable}});
    }
    return result;
}

std::string java_text(JNIEnv *env, jstring value, bool *truncated) {
    if (value == nullptr) return {};
    const jsize length = env->GetStringLength(value);
    const jsize count = std::min<jsize>(length,128);
    *truncated |= length > count;
    std::array<jchar,128> units{};
    env->GetStringRegion(value,0,count,units.data());
    if (env->ExceptionCheck()) return {};
    std::string text;
    for (jsize index = 0; index < count; ++index) {
        uint32_t point = units[index];
        if (point >= 0xd800 && point <= 0xdbff && index + 1 < count &&
            units[index+1] >= 0xdc00 && units[index+1] <= 0xdfff) {
            point = 0x10000 + ((point - 0xd800) << 10) + units[++index] - 0xdc00;
        } else if (point >= 0xd800 && point <= 0xdfff) point = 0xfffd;
        if (point < 0x80) text += char(point);
        else if (point < 0x800) { text += char(0xc0 | (point >> 6)); text += char(0x80 | (point & 63)); }
        else if (point < 0x10000) {
            text += char(0xe0 | (point >> 12)); text += char(0x80 | ((point >> 6) & 63)); text += char(0x80 | (point & 63));
        } else {
            text += char(0xf0 | (point >> 18)); text += char(0x80 | ((point >> 12) & 63));
            text += char(0x80 | ((point >> 6) & 63)); text += char(0x80 | (point & 63));
        }
    }
    return text;
}

json java_threads(unsigned maximum_threads, unsigned maximum_frames, bool enabled) {
    json result = {{"status",enabled ? "unavailable" : "disabled"},{"reason",enabled ? "vm_unavailable" : "not_requested"},
                   {"truncated",false},{"rows",json::array()}};
    if (!enabled) return result;
    using GetVMs = jint (*)(JavaVM **,jsize,jsize *);
    auto get_vms = reinterpret_cast<GetVMs>(dlsym(RTLD_DEFAULT,"JNI_GetCreatedJavaVMs"));
    void *art = nullptr;
    if (get_vms == nullptr) {
        art = dlopen("libart.so",RTLD_NOW | RTLD_NOLOAD);
        if (art != nullptr) get_vms = reinterpret_cast<GetVMs>(dlsym(art,"JNI_GetCreatedJavaVMs"));
    }
    // The app linker namespace may hide libart from dlopen/dlsym. Reuse the
    // existing dependency's loaded-ELF lookup (XDL_DEFAULT; never force-load).
    // No ShadowHook initialization, hooks or exception handlers are installed.
    if (get_vms == nullptr) {
        for (const char *name : {"libart.so","libnativehelper.so"}) {
            void *loaded = shadowhook_dlopen(name);
            if (loaded != nullptr) {
                get_vms = reinterpret_cast<GetVMs>(shadowhook_dlsym_dynsym(loaded,"JNI_GetCreatedJavaVMs"));
                shadowhook_dlclose(loaded);
            }
            if (get_vms != nullptr) break;
        }
    }
    JavaVM *vm = nullptr; jsize count = 0;
    const bool have_vm = get_vms != nullptr && get_vms(&vm,1,&count) == JNI_OK && count == 1 && vm != nullptr;
    if (art != nullptr) dlclose(art);
    if (!have_vm) return result;
    JNIEnv *env = nullptr;
    const auto attached = vm->GetEnv(reinterpret_cast<void **>(&env),JNI_VERSION_1_6);
    const bool own_attachment = attached == JNI_EDETACHED;
    if ((own_attachment && vm->AttachCurrentThread(&env,nullptr) != JNI_OK) || env == nullptr) {
        result["reason"] = "jni_attach_failed"; return result;
    }
    struct Attachment {
        JavaVM *vm; JNIEnv *env; bool owned; bool frame = false;
        ~Attachment() { if (frame) env->PopLocalFrame(nullptr); if (owned) vm->DetachCurrentThread(); }
    } attachment{vm,env,own_attachment};
    if (env->ExceptionCheck()) { result["reason"] = "preexisting_java_exception"; return result; }
    if (env->PushLocalFrame(64) < 0) {
        env->ExceptionClear(); result["reason"] = "jni_local_frame_failed"; return result;
    }
    attachment.frame = true;
    // Exceptions created by this opt-in operation are cleared on every path;
    // a preexisting target exception is never consumed above.
    struct Exceptions { JNIEnv *env; ~Exceptions() { if (env->ExceptionCheck()) env->ExceptionClear(); } } exceptions{env};
    jclass thread = nullptr, group_class = nullptr, frame_class = nullptr;
    if (!(thread = env->FindClass("java/lang/Thread")) || env->ExceptionCheck() ||
        !(group_class = env->FindClass("java/lang/ThreadGroup")) || env->ExceptionCheck() ||
        !(frame_class = env->FindClass("java/lang/StackTraceElement")) || env->ExceptionCheck()) {
        result["reason"] = "java_classes_unavailable"; return result;
    }
    jmethodID current = nullptr, get_group = nullptr, get_parent = nullptr, enumerate = nullptr,
              get_name = nullptr, get_id = nullptr, get_stack = nullptr, frame_text = nullptr;
    // Short circuit after every throwing JNI operation. CheckJNI rejects calls
    // made with a pending exception, including a second lookup after a failure.
    if (!(current = env->GetStaticMethodID(thread,"currentThread","()Ljava/lang/Thread;")) || env->ExceptionCheck() ||
        !(get_group = env->GetMethodID(thread,"getThreadGroup","()Ljava/lang/ThreadGroup;")) || env->ExceptionCheck() ||
        !(get_parent = env->GetMethodID(group_class,"getParent","()Ljava/lang/ThreadGroup;")) || env->ExceptionCheck() ||
        !(enumerate = env->GetMethodID(group_class,"enumerate","([Ljava/lang/Thread;Z)I")) || env->ExceptionCheck() ||
        !(get_name = env->GetMethodID(thread,"getName","()Ljava/lang/String;")) || env->ExceptionCheck() ||
        !(get_id = env->GetMethodID(thread,"getId","()J")) || env->ExceptionCheck() ||
        !(get_stack = env->GetMethodID(thread,"getStackTrace","()[Ljava/lang/StackTraceElement;")) || env->ExceptionCheck() ||
        !(frame_text = env->GetMethodID(frame_class,"toString","()Ljava/lang/String;")) || env->ExceptionCheck()) {
        result["reason"] = "java_methods_unavailable"; return result;
    }
    const auto self = env->CallStaticObjectMethod(thread,current);
    if (env->ExceptionCheck() || !self) { result["reason"] = "java_thread_group_unavailable"; return result; }
    jobject group = self ? env->CallObjectMethod(self,get_group) : nullptr;
    if (env->ExceptionCheck() || !group) { result["reason"] = "java_thread_group_unavailable"; return result; }
    for (unsigned depth = 0; depth < 16; ++depth) {
        const auto parent = env->CallObjectMethod(group,get_parent);
        if (env->ExceptionCheck()) { result["reason"] = "java_enumeration_failed"; return result; }
        if (parent == nullptr) break;
        env->DeleteLocalRef(group); group = parent;
        if (depth == 15) result["truncated"] = true;
    }
    const auto threads = env->NewObjectArray(maximum_threads,thread,nullptr);
    const jint found = threads ? env->CallIntMethod(group,enumerate,threads,JNI_TRUE) : 0;
    if (env->ExceptionCheck() || !threads || found < 0) { result["reason"] = "java_enumeration_failed"; return result; }
    result["truncated"] = result["truncated"].get<bool>() || unsigned(found) >= maximum_threads;
    size_t budget = 0;
    for (jint index = 0; index < std::min<jint>(found,maximum_threads); ++index) {
        if (budget + 2048 > kJavaBudget) { result["truncated"] = true; break; }
        if (env->PushLocalFrame(16) < 0) { result["truncated"] = true; break; }
        struct Frame { JNIEnv *env; ~Frame() { env->PopLocalFrame(nullptr); } } local_frame{env};
        const auto actor = env->GetObjectArrayElement(threads,index);
        jstring name = nullptr; jlong id = 0; jobjectArray frames = nullptr;
        if (env->ExceptionCheck() || !actor ||
            !(name = static_cast<jstring>(env->CallObjectMethod(actor,get_name))) || env->ExceptionCheck() ||
            (id = env->CallLongMethod(actor,get_id)) <= 0 || env->ExceptionCheck() ||
            !(frames = static_cast<jobjectArray>(env->CallObjectMethod(actor,get_stack))) || env->ExceptionCheck()) {
            env->ExceptionClear(); result["truncated"] = true; continue;
        }
        bool name_truncated = false;
        json row = {{"javaId",std::to_string(id)},{"name",java_text(env,name,&name_truncated)},
                    {"nameTruncated",name_truncated},{"frames",json::array()},{"framesTruncated",false}};
        if (env->ExceptionCheck()) {
            env->ExceptionClear(); result["truncated"] = true; continue;
        }
        budget += dump(row).size();
        const auto frame_count = env->GetArrayLength(frames);
        row["framesTruncated"] = unsigned(frame_count) > maximum_frames;
        for (jsize frame_index = 0; frame_index < std::min<jsize>(frame_count,maximum_frames); ++frame_index) {
            const auto frame = env->GetObjectArrayElement(frames,frame_index);
            const auto value = frame && !env->ExceptionCheck()
                ? static_cast<jstring>(env->CallObjectMethod(frame,frame_text)) : nullptr;
            bool shortened = false;
            const auto text = !env->ExceptionCheck() ? java_text(env,value,&shortened) : std::string();
            const auto bytes = dump(json(text)).size();
            if (env->ExceptionCheck() || budget + bytes + 64 > kJavaBudget) {
                env->ExceptionClear(); row["framesTruncated"] = true; result["truncated"] = true;
                if (value) env->DeleteLocalRef(value);
                if (frame) env->DeleteLocalRef(frame);
                break;
            }
            budget += bytes + 1;
            row["frames"].push_back(text);
            if (shortened) row["framesTruncated"] = true;
            if (value) env->DeleteLocalRef(value);
            if (frame) env->DeleteLocalRef(frame);
        }
        result["rows"].push_back(std::move(row));
    }
    result["status"] = "available"; result["reason"] = "";
    return result;
}

json capture(const json &request) {
    const auto initial = starttime();
    const auto pid = ::getpid();
    if (initial.empty() || request.at("expectedPid") != pid || request.at("expectedStarttime") != initial)
        return {{"schema",1},{"ok",false},{"reason","process_identity_mismatch"}};
    json result = {{"schema",1},{"ok",true},{"reason",""},{"pid",pid},{"starttime",initial},
                   {"startedMonotonicNs",monotonic_ns()}};
    result["mappings"] = mappings();
    result["nativeThreads"] = native_threads(request.at("maxThreads"));
    result["java"] = java_threads(request.at("maxThreads"),request.at("maxFrames"),request.at("includeJava"));
    result["finishedMonotonicNs"] = monotonic_ns();
    if (starttime() != initial) return {{"schema",1},{"ok",false},{"reason","process_identity_changed"}};
    return result;
}
} // namespace

extern "C" int32_t qbdi_tracer_snapshot_json(const char *request, uint64_t request_size,
        char *response, uint64_t capacity, uint64_t *response_size) noexcept {
    const int saved_errno = errno;
    struct Errno { int value; ~Errno() { errno = value; } } preserve{saved_errno};
    if (!request || !response || !response_size || request_size == 0 || request_size > 1024 ||
        capacity < 2 || capacity > kResponseBytes) return QTRACE_JSON_INVALID_ARGUMENT;
    try {
        bool duplicate = false;
        std::array<std::string,6> keys{}; size_t key_count = 0;
        const auto options = json::parse(request,request + request_size,
            [&](int, json::parse_event_t event, json &value) {
                if (event == json::parse_event_t::key) {
                    for (size_t index = 0; index < key_count; ++index) duplicate |= keys[index] == value;
                    if (key_count < keys.size()) keys[key_count++] = value.get<std::string>();
                    else duplicate = true;
                }
                return true;
            });
        if (duplicate || !options.is_object() || options.size() != 6 || !options.contains("schema") ||
            !options["schema"].is_number_unsigned() || options["schema"] != 1 ||
            !options.contains("expectedPid") || !options["expectedPid"].is_number_unsigned() ||
            options["expectedPid"] < 1 || options["expectedPid"] > INT32_MAX ||
            !options.contains("expectedStarttime") || !options["expectedStarttime"].is_string() ||
            !options.contains("includeJava") || !options["includeJava"].is_boolean() ||
            !options.contains("maxThreads") || !options["maxThreads"].is_number_unsigned() ||
            !options.contains("maxFrames") || !options["maxFrames"].is_number_unsigned() ||
            options["maxThreads"] < 1 || options["maxThreads"] > 32 ||
            options["maxFrames"] < 1 || options["maxFrames"] > 32 ||
            options["expectedStarttime"].get_ref<const std::string &>().size() > 32)
            return QTRACE_JSON_INVALID_ARGUMENT;
        const auto &epoch = options["expectedStarttime"].get_ref<const std::string &>();
        if (epoch.empty() || epoch[0] == '0' || epoch.find_first_not_of("0123456789") != std::string::npos)
            return QTRACE_JSON_INVALID_ARGUMENT;
        const auto result = dump(capture(options));
        *response_size = result.size() + 1;
        if (*response_size > capacity) return QTRACE_JSON_RESPONSE_TOO_SMALL;
        std::memcpy(response,result.c_str(),*response_size);
        return QTRACE_JSON_OK;
    } catch (...) {
        return QTRACE_JSON_INVALID_ARGUMENT;
    }
}
