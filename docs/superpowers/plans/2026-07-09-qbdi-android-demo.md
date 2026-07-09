# QBDI Android Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Kotlin Android demo APK plus an injectable QBDI tracer library that demonstrates init, JNI, libc, algorithm, and integrity-bypass tracing on Android arm64.

**Architecture:** The APK owns `libdemo_target.so` and dynamically registered Kotlin native methods. The separate `tracer` module builds `libqbdi_tracer.so`, links QBDI and ByteDance ShadowHook, installs offset-based hooks after Frida spawn injection, executes selected target functions in QBDI, and writes buffered text traces into the app private files directory.

**Tech Stack:** Kotlin, Android Gradle Plugin, CMake, Android NDK, QBDI v0.12.1 Android AARCH64 release, ByteDance `android-inline-hook`/ShadowHook v2.0.1, Frida JavaScript, arm64-v8a.

---

## File Structure Map

Create these files and responsibilities:

- `settings.gradle`: Gradle plugin repositories and included modules.
- `build.gradle`: Root Android/Kotlin plugin versions and Maven Central setup.
- `gradle.properties`: AndroidX, Kotlin, NDK, and JVM settings.
- `app/build.gradle`: Kotlin app module with CMake and arm64 target configuration.
- `app/src/main/AndroidManifest.xml`: App entry, app label, and debuggable demo configuration.
- `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`: Button UI wiring and result display.
- `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`: Loads `demo_target` and declares dynamic native methods.
- `app/src/main/res/values/strings.xml`: App name and button labels.
- `app/src/main/res/values/themes.xml`: Minimal app theme.
- `app/src/main/cpp/CMakeLists.txt`: Builds `libdemo_target.so`.
- `app/src/main/cpp/demo_target/demo_target.cpp`: `JNI_OnLoad`, dynamic registration, constructor, and native entry wrappers.
- `app/src/main/cpp/demo_target/demo_scenes.h`: Scene function declarations.
- `app/src/main/cpp/demo_target/demo_scenes.cpp`: Init/JNI/libc/algorithm scene implementation.
- `app/src/main/cpp/demo_target/integrity.h`: Integrity API declarations.
- `app/src/main/cpp/demo_target/integrity.cpp`: `.text` hash and `/proc/self/maps` checks.
- `tracer/build.gradle`: Android library module, CMake, prefab, ShadowHook dependency, and copy task.
- `tracer/src/main/cpp/CMakeLists.txt`: Builds `libqbdi_tracer.so` and links QBDI/ShadowHook/log/android.
- `tracer/src/main/cpp/third_party/qbdi/README.md`: QBDI artifact source and version.
- `tracer/src/main/cpp/core/logging.h`: Logcat macros.
- `tracer/src/main/cpp/core/module_maps.h/.cpp`: `/proc/self/maps` parsing and module range lookup.
- `tracer/src/main/cpp/core/safe_memory.h/.cpp`: Guarded memory reads and string previews.
- `tracer/src/main/cpp/events/trace_event.h`: Event structs and event enum.
- `tracer/src/main/cpp/events/text_trace_writer.h/.cpp`: Buffered text writer and trace file naming.
- `tracer/src/main/cpp/hooks/inline_hook_adapter.h/.cpp`: ShadowHook initialization and address hook wrapper.
- `tracer/src/main/cpp/core/trace_config.h/.cpp`: Static scene config from Frida-provided environment/string.
- `tracer/src/main/cpp/core/qbdi_runner.h/.cpp`: QBDI VM setup, callbacks, register sync, execution, and event emission.
- `tracer/src/main/cpp/handlers/call_handlers.h/.cpp`: JNI/libc/custom call event formatting.
- `tracer/src/main/cpp/handlers/bypass_handlers.h/.cpp`: `.text` restore and maps sanitization handlers.
- `tracer/src/main/cpp/tracer_entry.cpp`: Constructor entry, config loading, module waiting, hook install.
- `scripts/trace_config.js`: Example offset config for all scenes.
- `scripts/spawn_trace.js`: Frida spawn helper that loads ShadowHook and tracer libs and passes config.
- `docs/ida-offsets.md`: Manual IDA/Ghidra/objdump offset workflow.
- `docs/trace-format.md`: Text trace format reference.
- `docs/integrity-bypass.md`: Integrity checks and bypass walkthrough.
- `README.md`: End-to-end build, install, inject, trace, and log pull instructions.

Commit after each task. Do not push until the full validation task passes or the user explicitly asks to push a partial state.

---

### Task 1: Scaffold Gradle Android Project

**Files:**
- Create: `settings.gradle`
- Create: `build.gradle`
- Create: `gradle.properties`
- Create: `app/build.gradle`
- Create: `tracer/build.gradle`
- Create: `app/src/main/res/values/strings.xml`
- Create: `app/src/main/res/values/themes.xml`
- Create: `app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Add root Gradle settings**

Create `settings.gradle`:

```gradle
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "qbdi-android"
include ":app"
include ":tracer"
```

Create `build.gradle`:

```gradle
plugins {
    id "com.android.application" version "8.5.2" apply false
    id "com.android.library" version "8.5.2" apply false
    id "org.jetbrains.kotlin.android" version "1.9.24" apply false
}
```

Create `gradle.properties`:

```properties
org.gradle.jvmargs=-Xmx4096m -Dfile.encoding=UTF-8
android.useAndroidX=true
android.nonTransitiveRClass=true
android.defaults.buildfeatures.buildconfig=false
kotlin.code.style=official
android.prefabVersion=2.0.0
```

- [ ] **Step 2: Add app module build file**

Create `app/build.gradle`:

```gradle
plugins {
    id "com.android.application"
    id "org.jetbrains.kotlin.android"
}

android {
    namespace "com.aprz.qbdiandroid"
    compileSdk 35

    defaultConfig {
        applicationId "com.aprz.qbdiandroid"
        minSdk 24
        targetSdk 35
        versionCode 1
        versionName "0.1.0"
        ndk {
            abiFilters "arm64-v8a"
        }
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++20 -fvisibility=hidden -fno-exceptions -fno-rtti"
                arguments "-DANDROID_STL=c++_static"
            }
        }
    }

    buildTypes {
        debug {
            debuggable true
            jniDebuggable true
            packagingOptions {
                doNotStrip "**/libdemo_target.so"
            }
        }
        release {
            minifyEnabled false
            debuggable true
        }
    }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }
}

dependencies {
    implementation "androidx.core:core-ktx:1.13.1"
    implementation "androidx.appcompat:appcompat:1.7.0"
    implementation "com.google.android.material:material:1.12.0"
}
```

- [ ] **Step 3: Add tracer module build file**

Create `tracer/build.gradle`:

```gradle
plugins {
    id "com.android.library"
}

android {
    namespace "com.aprz.qbditracer"
    compileSdk 35

    defaultConfig {
        minSdk 24
        ndk {
            abiFilters "arm64-v8a"
        }
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++20 -fno-exceptions -fno-rtti"
                arguments "-DANDROID_STL=c++_static"
            }
        }
    }

    buildFeatures {
        prefab true
    }

    buildTypes {
        debug {
            debuggable true
            jniDebuggable true
        }
        release {
            minifyEnabled false
        }
    }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }
}

dependencies {
    implementation "com.bytedance.android:shadowhook:2.0.1"
}

tasks.register("copyTracerDebug", Copy) {
    dependsOn "assembleDebug"
    from("$buildDir/intermediates/stripped_native_libs/debug/out/lib/arm64-v8a")
    into("$rootDir/out/arm64-v8a")
    include("libqbdi_tracer.so")
}
```

- [ ] **Step 4: Add minimal app resources and manifest**

Create `app/src/main/res/values/strings.xml`:

```xml
<resources>
    <string name="app_name">QBDI Android Demo</string>
    <string name="trace_jni">Trace JNI Case</string>
    <string name="trace_libc">Trace Libc Case</string>
    <string name="trace_algorithm">Trace Algorithm Case</string>
    <string name="trace_integrity">Trace Integrity Case</string>
</resources>
```

Create `app/src/main/res/values/themes.xml`:

```xml
<resources>
    <style name="Theme.QbdiAndroid" parent="Theme.MaterialComponents.DayNight.NoActionBar">
        <item name="android:fontFamily">sans</item>
        <item name="android:windowLightStatusBar">true</item>
        <item name="colorPrimary">#0B57D0</item>
        <item name="colorPrimaryVariant">#0842A0</item>
        <item name="colorSecondary">#185ABC</item>
    </style>
</resources>
```

Create `app/src/main/AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="false"
        android:debuggable="true"
        android:extractNativeLibs="true"
        android:label="@string/app_name"
        android:theme="@style/Theme.QbdiAndroid">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

- [ ] **Step 5: Run Gradle project listing**

Run: `./gradlew projects` if the wrapper exists. If no wrapper exists, run `gradle wrapper --gradle-version 8.7` once, then run `./gradlew projects`.

Expected: output lists `:app` and `:tracer`.

- [ ] **Step 6: Commit scaffold**

```bash
git add settings.gradle build.gradle gradle.properties app/build.gradle tracer/build.gradle app/src/main/AndroidManifest.xml app/src/main/res/values/strings.xml app/src/main/res/values/themes.xml gradle gradlew gradlew.bat
git commit -m "chore: scaffold Android project"
```

---

### Task 2: Add Kotlin UI and Native Bridge

**Files:**
- Create: `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`
- Create: `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`

- [ ] **Step 1: Add native bridge**

Create `app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt`:

```kotlin
package com.aprz.qbdiandroid

object NativeDemo {
    init {
        System.loadLibrary("demo_target")
    }

    external fun runJniCase(): String
    external fun runLibcCase(): String
    external fun runAlgorithmCase(): String
    external fun runIntegrityCase(): String
}
```

- [ ] **Step 2: Add button-driven Activity**

Create `app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt`:

```kotlin
package com.aprz.qbdiandroid

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        output = TextView(this).apply {
            textSize = 14f
            text = "QBDI Android Demo ready. Inject tracer with Frida spawn, then tap a scene."
            setPadding(24, 24, 24, 24)
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            addView(makeButton(getString(R.string.trace_jni)) { NativeDemo.runJniCase() })
            addView(makeButton(getString(R.string.trace_libc)) { NativeDemo.runLibcCase() })
            addView(makeButton(getString(R.string.trace_algorithm)) { NativeDemo.runAlgorithmCase() })
            addView(makeButton(getString(R.string.trace_integrity)) { NativeDemo.runIntegrityCase() })
            addView(output)
        }

        setContentView(ScrollView(this).apply { addView(content) })
    }

    private fun makeButton(label: String, action: () -> String): Button {
        return Button(this).apply {
            text = label
            setOnClickListener {
                output.text = runCatching(action).fold(
                    onSuccess = { "$label\n$it" },
                    onFailure = { "$label failed: ${it.javaClass.simpleName}: ${it.message}" }
                )
            }
        }
    }
}
```

- [ ] **Step 3: Build Kotlin without native source yet**

Run: `./gradlew :app:compileDebugKotlin`

Expected: Kotlin compilation fails only if `demo_target` native build is missing; there must be no Kotlin syntax errors.

- [ ] **Step 4: Commit Kotlin app layer**

```bash
git add app/src/main/kotlin/com/aprz/qbdiandroid/NativeDemo.kt app/src/main/kotlin/com/aprz/qbdiandroid/MainActivity.kt
git commit -m "feat: add Kotlin demo UI"
```

---

### Task 3: Implement Target Native Library

**Files:**
- Create: `app/src/main/cpp/CMakeLists.txt`
- Create: `app/src/main/cpp/demo_target/demo_scenes.h`
- Create: `app/src/main/cpp/demo_target/demo_scenes.cpp`
- Create: `app/src/main/cpp/demo_target/integrity.h`
- Create: `app/src/main/cpp/demo_target/integrity.cpp`
- Create: `app/src/main/cpp/demo_target/demo_target.cpp`

- [ ] **Step 1: Add CMake target**

Create `app/src/main/cpp/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(demo_target)

add_library(demo_target SHARED
    demo_target/demo_target.cpp
    demo_target/demo_scenes.cpp
    demo_target/integrity.cpp)

target_compile_features(demo_target PRIVATE cxx_std_20)
target_compile_options(demo_target PRIVATE -Wall -Wextra -fvisibility=hidden)
target_link_libraries(demo_target PRIVATE android log)
```

- [ ] **Step 2: Add scene declarations**

Create `app/src/main/cpp/demo_target/demo_scenes.h`:

```cpp
#pragma once

#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" __attribute__((visibility("hidden"))) uint64_t demo_init_stage();
extern "C" __attribute__((visibility("hidden"))) std::string demo_jni_case(JNIEnv *env, jobject thiz);
extern "C" __attribute__((visibility("hidden"))) std::string demo_libc_case();
extern "C" __attribute__((visibility("hidden"))) uint64_t demo_algorithm_case(const uint8_t *data, size_t size);
extern "C" __attribute__((visibility("hidden"))) std::string demo_integrity_case();
```

Create `app/src/main/cpp/demo_target/integrity.h`:

```cpp
#pragma once

#include <cstdint>
#include <string>

void integrity_capture_baseline();
bool integrity_text_check();
bool integrity_maps_check(std::string *reason);
[[noreturn]] void integrity_crash(const char *reason);
```

- [ ] **Step 3: Add scene implementation**

Create `app/src/main/cpp/demo_target/demo_scenes.cpp` with deterministic scene logic:

```cpp
#include "demo_scenes.h"
#include "integrity.h"

#include <android/log.h>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <sys/system_properties.h>
#include <unistd.h>

#define DEMO_LOG(...) __android_log_print(ANDROID_LOG_INFO, "QBDI-DEMO", __VA_ARGS__)

static uint64_t mix_round(uint64_t state, uint8_t value) {
    state ^= static_cast<uint64_t>(value) + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
    return (state << 7U) | (state >> 57U);
}

extern "C" uint64_t demo_init_stage() {
    const uint8_t seed[] = {0x42, 0x51, 0x44, 0x49, 0x2d, 0x69, 0x6e, 0x69, 0x74};
    uint64_t result = demo_algorithm_case(seed, sizeof(seed));
    DEMO_LOG("init stage result=0x%llx", static_cast<unsigned long long>(result));
    return result;
}

extern "C" std::string demo_jni_case(JNIEnv *env, jobject thiz) {
    jclass activity_class = env->GetObjectClass(thiz);
    jclass string_class = env->FindClass("java/lang/String");
    jmethodID length_method = env->GetMethodID(string_class, "length", "()I");
    jstring sample = env->NewStringUTF("qbdi-jni-case");
    const char *chars = env->GetStringUTFChars(sample, nullptr);
    int length = env->CallIntMethod(sample, length_method);
    env->ReleaseStringUTFChars(sample, chars);
    env->DeleteLocalRef(sample);
    env->DeleteLocalRef(string_class);
    env->DeleteLocalRef(activity_class);

    std::ostringstream out;
    out << "JNI scene finished, java String.length()=" << length;
    return out.str();
}

extern "C" std::string demo_libc_case() {
    const char *text = "qbdi-libc-case";
    char buffer[64] = {};
    size_t len = strlen(text);
    memcpy(buffer, text, len + 1);
    int cmp = memcmp(buffer, text, len);
    int access_result = access("/proc/self/maps", R_OK);
    char prop[PROP_VALUE_MAX] = {};
    int prop_len = __system_property_get("ro.build.version.release", prop);

    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps != nullptr) {
        fclose(maps);
    }

    std::ostringstream out;
    out << "libc scene len=" << len
        << " cmp=" << cmp
        << " access=" << access_result
        << " android=" << std::string(prop, prop_len > 0 ? prop_len : 0);
    return out.str();
}

extern "C" uint64_t demo_algorithm_case(const uint8_t *data, size_t size) {
    uint64_t state = 0x51424449414e4452ULL;
    for (size_t i = 0; i < size; ++i) {
        state = mix_round(state, data[i]);
    }
    return state ^ (size * 0x100000001b3ULL);
}

extern "C" std::string demo_integrity_case() {
    if (!integrity_text_check()) {
        integrity_crash("text hash check failed");
    }
    std::string reason;
    if (!integrity_maps_check(&reason)) {
        integrity_crash(reason.c_str());
    }
    const uint8_t data[] = {0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d};
    uint64_t result = demo_algorithm_case(data, sizeof(data));
    std::ostringstream out;
    out << "integrity scene passed, algorithm=0x" << std::hex << result;
    return out.str();
}
```

- [ ] **Step 4: Add integrity implementation**

Create `app/src/main/cpp/demo_target/integrity.cpp`:

```cpp
#include "integrity.h"
#include "demo_scenes.h"

#include <android/log.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#define DEMO_LOG(...) __android_log_print(ANDROID_LOG_INFO, "QBDI-DEMO", __VA_ARGS__)

static uint64_t g_expected_text_hash = 0;
static uintptr_t g_text_start = 0;
static constexpr size_t kTextSampleSize = 64;

static uint64_t fnv1a64(const uint8_t *data, size_t size) {
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void integrity_capture_baseline() {
    g_text_start = reinterpret_cast<uintptr_t>(&demo_algorithm_case);
    g_expected_text_hash = fnv1a64(reinterpret_cast<const uint8_t *>(g_text_start), kTextSampleSize);
    DEMO_LOG("integrity baseline text=%p hash=0x%llx",
             reinterpret_cast<void *>(g_text_start),
             static_cast<unsigned long long>(g_expected_text_hash));
}

bool integrity_text_check() {
    if (g_text_start == 0 || g_expected_text_hash == 0) {
        integrity_capture_baseline();
    }
    uint64_t current = fnv1a64(reinterpret_cast<const uint8_t *>(g_text_start), kTextSampleSize);
    return current == g_expected_text_hash;
}

bool integrity_maps_check(std::string *reason) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        if (reason != nullptr) *reason = "cannot open /proc/self/maps";
        return false;
    }

    bool saw_demo_rx = false;
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("libdemo_target.so") != std::string::npos && line.find("r-x") != std::string::npos) {
            saw_demo_rx = true;
        }
        if (line.find("frida") != std::string::npos ||
            line.find("gum-js-loop") != std::string::npos ||
            line.find("libqbdi_tracer") != std::string::npos ||
            line.find("libQBDI") != std::string::npos) {
            if (reason != nullptr) *reason = "suspicious maps entry: " + line;
            return false;
        }
    }

    if (!saw_demo_rx) {
        if (reason != nullptr) *reason = "missing libdemo_target.so RX map";
        return false;
    }
    return true;
}

[[noreturn]] void integrity_crash(const char *reason) {
    DEMO_LOG("integrity crash: %s", reason != nullptr ? reason : "unknown");
    volatile int *crash = nullptr;
    *crash = 0x51524449;
    abort();
}
```

- [ ] **Step 5: Add dynamic JNI registration and constructor**

Create `app/src/main/cpp/demo_target/demo_target.cpp`:

```cpp
#include "demo_scenes.h"
#include "integrity.h"

#include <android/log.h>
#include <jni.h>
#include <string>

#define DEMO_LOG(...) __android_log_print(ANDROID_LOG_INFO, "QBDI-DEMO", __VA_ARGS__)

static jstring to_jstring(JNIEnv *env, const std::string &value) {
    return env->NewStringUTF(value.c_str());
}

static jstring native_run_jni_case(JNIEnv *env, jobject thiz) {
    return to_jstring(env, demo_jni_case(env, thiz));
}

static jstring native_run_libc_case(JNIEnv *env, jobject) {
    return to_jstring(env, demo_libc_case());
}

static jstring native_run_algorithm_case(JNIEnv *env, jobject) {
    const uint8_t data[] = {'q', 'b', 'd', 'i', '-', 'a', 'l', 'g'};
    uint64_t result = demo_algorithm_case(data, sizeof(data));
    char buffer[96];
    snprintf(buffer, sizeof(buffer), "algorithm scene result=0x%llx", static_cast<unsigned long long>(result));
    return env->NewStringUTF(buffer);
}

static jstring native_run_integrity_case(JNIEnv *env, jobject) {
    return to_jstring(env, demo_integrity_case());
}

static JNINativeMethod g_methods[] = {
    {"runJniCase", "()Ljava/lang/String;", reinterpret_cast<void *>(native_run_jni_case)},
    {"runLibcCase", "()Ljava/lang/String;", reinterpret_cast<void *>(native_run_libc_case)},
    {"runAlgorithmCase", "()Ljava/lang/String;", reinterpret_cast<void *>(native_run_algorithm_case)},
    {"runIntegrityCase", "()Ljava/lang/String;", reinterpret_cast<void *>(native_run_integrity_case)},
};

__attribute__((constructor)) static void demo_constructor() {
    integrity_capture_baseline();
    uint64_t init_result = demo_init_stage();
    DEMO_LOG("constructor complete result=0x%llx", static_cast<unsigned long long>(init_result));
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
    jclass clazz = env->FindClass("com/aprz/qbdiandroid/NativeDemo");
    if (clazz == nullptr) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(clazz, g_methods, sizeof(g_methods) / sizeof(g_methods[0])) != JNI_OK) {
        env->DeleteLocalRef(clazz);
        return JNI_ERR;
    }
    env->DeleteLocalRef(clazz);
    return JNI_VERSION_1_6;
}
```

- [ ] **Step 6: Build the APK native target**

Run: `./gradlew :app:assembleDebug`

Expected: build succeeds and creates `app/build/intermediates/merged_native_libs/debug/out/lib/arm64-v8a/libdemo_target.so`.

- [ ] **Step 7: Commit target library**

```bash
git add app/src/main/cpp/CMakeLists.txt app/src/main/cpp/demo_target
git commit -m "feat: add native target demo scenes"
```

---

### Task 4: Add QBDI Release Artifacts

**Files:**
- Create: `tracer/src/main/cpp/third_party/qbdi/README.md`
- Create: `tracer/src/main/cpp/third_party/qbdi/include/QBDI.h`
- Create: `tracer/src/main/cpp/third_party/qbdi/include/QBDI/*`
- Create: `tracer/src/main/cpp/third_party/qbdi/lib/arm64-v8a/libQBDI.a`

- [ ] **Step 1: Download official QBDI Android AARCH64 release**

Run:

```bash
mkdir -p /tmp/qbdi-android-deps
curl -L -o /tmp/qbdi-android-deps/QBDI-0.12.1-android-AARCH64.tar.gz \
  https://github.com/QBDI/QBDI/releases/download/v0.12.1/QBDI-0.12.1-android-AARCH64.tar.gz
```

Expected: downloaded archive is about 69 MB and contains `usr/local/lib/libQBDI.a`.

- [ ] **Step 2: Copy QBDI headers and static library into tracer**

Run:

```bash
mkdir -p tracer/src/main/cpp/third_party/qbdi/include
mkdir -p tracer/src/main/cpp/third_party/qbdi/lib/arm64-v8a
tar -xzf /tmp/qbdi-android-deps/QBDI-0.12.1-android-AARCH64.tar.gz -C /tmp/qbdi-android-deps
cp -R /tmp/qbdi-android-deps/usr/local/include/QBDI tracer/src/main/cpp/third_party/qbdi/include/
cp /tmp/qbdi-android-deps/usr/local/include/QBDI.h tracer/src/main/cpp/third_party/qbdi/include/QBDI.h
cp /tmp/qbdi-android-deps/usr/local/lib/libQBDI.a tracer/src/main/cpp/third_party/qbdi/lib/arm64-v8a/libQBDI.a
```

Expected: `tracer/src/main/cpp/third_party/qbdi/lib/arm64-v8a/libQBDI.a` exists.

- [ ] **Step 3: Document dependency provenance**

Create `tracer/src/main/cpp/third_party/qbdi/README.md`:

```markdown
# QBDI Android AARCH64 Artifact

This directory contains QBDI v0.12.1 Android AARCH64 files from the official QBDI release package:

- Release: https://github.com/QBDI/QBDI/releases/tag/v0.12.1
- Asset: `QBDI-0.12.1-android-AARCH64.tar.gz`
- Used files:
  - `usr/local/include/QBDI.h`
  - `usr/local/include/QBDI/`
  - `usr/local/lib/libQBDI.a`

The first version links QBDI statically into `libqbdi_tracer.so` for simpler device deployment.
```

- [ ] **Step 4: Commit QBDI artifact**

```bash
git add tracer/src/main/cpp/third_party/qbdi
git commit -m "chore: add QBDI Android arm64 artifact"
```

---

### Task 5: Add Tracer Build Skeleton

**Files:**
- Create: `tracer/src/main/cpp/CMakeLists.txt`
- Create: `tracer/src/main/cpp/core/logging.h`
- Create: `tracer/src/main/cpp/tracer_entry.cpp`

- [ ] **Step 1: Add tracer CMake skeleton**

Create `tracer/src/main/cpp/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(qbdi_tracer)

set(QBDI_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qbdi)

find_package(shadowhook REQUIRED CONFIG)

add_library(qbdi_static STATIC IMPORTED)
set_target_properties(qbdi_static PROPERTIES
    IMPORTED_LOCATION ${QBDI_ROOT}/lib/arm64-v8a/libQBDI.a)

add_library(qbdi_tracer SHARED
    tracer_entry.cpp)

target_compile_features(qbdi_tracer PRIVATE cxx_std_20)
target_compile_options(qbdi_tracer PRIVATE -Wall -Wextra)
target_include_directories(qbdi_tracer PRIVATE
    ${QBDI_ROOT}/include
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(qbdi_tracer PRIVATE
    qbdi_static
    shadowhook::shadowhook
    android
    log)
```

- [ ] **Step 2: Add log helper**

Create `tracer/src/main/cpp/core/logging.h`:

```cpp
#pragma once

#include <android/log.h>

#define QTRACE_TAG "QBDI-TRACER"
#define QTRACE_D(...) __android_log_print(ANDROID_LOG_DEBUG, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_I(...) __android_log_print(ANDROID_LOG_INFO, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_W(...) __android_log_print(ANDROID_LOG_WARN, QTRACE_TAG, __VA_ARGS__)
#define QTRACE_E(...) __android_log_print(ANDROID_LOG_ERROR, QTRACE_TAG, __VA_ARGS__)
```

- [ ] **Step 3: Add constructor skeleton**

Create `tracer/src/main/cpp/tracer_entry.cpp`:

```cpp
#include "core/logging.h"

#include <shadowhook.h>

__attribute__((constructor)) static void qbdi_tracer_init() {
    int init_result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    if (init_result != 0) {
        QTRACE_E("shadowhook_init failed: %d", init_result);
        return;
    }
    QTRACE_I("libqbdi_tracer loaded");
}
```

- [ ] **Step 4: Build tracer skeleton**

Run: `./gradlew :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: build succeeds and creates `out/arm64-v8a/libqbdi_tracer.so`.

- [ ] **Step 5: Commit tracer skeleton**

```bash
git add tracer/src/main/cpp/CMakeLists.txt tracer/src/main/cpp/core/logging.h tracer/src/main/cpp/tracer_entry.cpp
git commit -m "feat: add tracer native build skeleton"
```

---

### Task 6: Implement Tracer Utilities and Text Writer

**Files:**
- Create: `tracer/src/main/cpp/core/module_maps.h`
- Create: `tracer/src/main/cpp/core/module_maps.cpp`
- Create: `tracer/src/main/cpp/core/safe_memory.h`
- Create: `tracer/src/main/cpp/core/safe_memory.cpp`
- Create: `tracer/src/main/cpp/events/trace_event.h`
- Create: `tracer/src/main/cpp/events/text_trace_writer.h`
- Create: `tracer/src/main/cpp/events/text_trace_writer.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

- [ ] **Step 1: Add module map parser**

Create `tracer/src/main/cpp/core/module_maps.h`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ModuleRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uintptr_t file_offset = 0;
    std::string permissions;
    std::string path;

    bool executable() const { return permissions.find('x') != std::string::npos; }
    uintptr_t size() const { return end > start ? end - start : 0; }
};

std::vector<ModuleRange> read_process_maps();
bool find_module_executable_range(const std::string &soname, ModuleRange *out);
std::string basename_of(const std::string &path);
```

Create `tracer/src/main/cpp/core/module_maps.cpp`:

```cpp
#include "core/module_maps.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

std::string basename_of(const std::string &path) {
    size_t pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

std::vector<ModuleRange> read_process_maps() {
    std::vector<ModuleRange> ranges;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream input(line);
        std::string addresses;
        std::string offset;
        std::string dev;
        std::string inode;
        ModuleRange range;
        input >> addresses >> range.permissions >> offset >> dev >> inode;
        std::getline(input, range.path);
        if (!range.path.empty() && range.path[0] == ' ') range.path.erase(0, range.path.find_first_not_of(' '));
        size_t dash = addresses.find('-');
        if (dash == std::string::npos) continue;
        range.start = strtoull(addresses.substr(0, dash).c_str(), nullptr, 16);
        range.end = strtoull(addresses.substr(dash + 1).c_str(), nullptr, 16);
        range.file_offset = strtoull(offset.c_str(), nullptr, 16);
        ranges.push_back(range);
    }
    return ranges;
}

bool find_module_executable_range(const std::string &soname, ModuleRange *out) {
    for (const auto &range : read_process_maps()) {
        if (!range.executable()) continue;
        if (basename_of(range.path) == soname) {
            if (out != nullptr) *out = range;
            return true;
        }
    }
    return false;
}
```

- [ ] **Step 2: Add guarded memory helpers**

Create `tracer/src/main/cpp/core/safe_memory.h`:

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

bool safe_read_memory(uintptr_t address, void *buffer, size_t size);
std::string preview_c_string(uintptr_t address, size_t max_len = 96);
std::string hex_preview(uintptr_t address, size_t size, size_t max_len = 32);
```

Create `tracer/src/main/cpp/core/safe_memory.cpp`:

```cpp
#include "core/safe_memory.h"

#include <cctype>
#include <cstring>
#include <sstream>
#include <sys/uio.h>
#include <unistd.h>

bool safe_read_memory(uintptr_t address, void *buffer, size_t size) {
    if (address == 0 || buffer == nullptr || size == 0) return false;
    iovec local{buffer, size};
    iovec remote{reinterpret_cast<void *>(address), size};
    ssize_t read = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return read == static_cast<ssize_t>(size);
}

std::string preview_c_string(uintptr_t address, size_t max_len) {
    std::string buffer(max_len, '\0');
    if (!safe_read_memory(address, buffer.data(), max_len)) return "<unreadable>";
    size_t end = 0;
    while (end < buffer.size() && buffer[end] != '\0') {
        if (!std::isprint(static_cast<unsigned char>(buffer[end]))) return "<non-printable>";
        ++end;
    }
    return buffer.substr(0, end);
}

std::string hex_preview(uintptr_t address, size_t size, size_t max_len) {
    size_t read_size = size < max_len ? size : max_len;
    unsigned char bytes[64] = {};
    if (read_size > sizeof(bytes)) read_size = sizeof(bytes);
    if (!safe_read_memory(address, bytes, read_size)) return "<unreadable>";
    std::ostringstream out;
    out << std::hex;
    for (size_t i = 0; i < read_size; ++i) {
        if (i != 0) out << ' ';
        out.width(2);
        out.fill('0');
        out << static_cast<unsigned int>(bytes[i]);
    }
    return out.str();
}
```

- [ ] **Step 3: Add event and writer types**

Create `tracer/src/main/cpp/events/trace_event.h`:

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TraceContext {
    std::string package_name;
    std::string scene_name;
    std::string target_so;
    uintptr_t module_base = 0;
    uintptr_t target_offset = 0;
    uintptr_t target_address = 0;
    int pid = 0;
    int tid = 0;
};

struct MemoryAccessText {
    char type = 'r';
    uintptr_t address = 0;
    uint32_t size = 0;
    uint64_t value = 0;
};

struct InstructionText {
    uint64_t sequence = 0;
    uintptr_t pc = 0;
    std::string disassembly;
    std::string reads;
    std::string writes;
    std::vector<MemoryAccessText> memory;
};
```

Create `tracer/src/main/cpp/events/text_trace_writer.h`:

```cpp
#pragma once

#include "events/trace_event.h"

#include <cstddef>
#include <string>

class TextTraceWriter {
public:
    explicit TextTraceWriter(size_t flush_threshold = 1 << 20);
    ~TextTraceWriter();

    bool open(const TraceContext &context);
    void begin(const TraceContext &context);
    void instruction(const TraceContext &context, const InstructionText &inst);
    void memory(const TraceContext &context, uintptr_t pc, const MemoryAccessText &mem);
    void call(const char *category, const std::string &name, const std::string &detail);
    void bypass(const std::string &name, const std::string &detail);
    void error(const std::string &message);
    void end(uint64_t retval, bool ok, long elapsed_ms);
    void flush();
    const std::string &path() const { return path_; }

private:
    void append(const std::string &line);
    int fd_ = -1;
    size_t flush_threshold_;
    std::string buffer_;
    std::string path_;
};
```

Create `tracer/src/main/cpp/events/text_trace_writer.cpp` with POSIX buffered write logic:

```cpp
#include "events/text_trace_writer.h"
#include "core/logging.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static bool mkdirs(const std::string &path) {
    if (path.empty() || path == "/") return true;
    if (mkdir(path.c_str(), 0755) == 0 || errno == EEXIST) return true;
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return false;
    if (!mkdirs(path.substr(0, slash))) return false;
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

static bool write_all(int fd, const char *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t result = write(fd, data + written, size - written);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        written += static_cast<size_t>(result);
    }
    return true;
}

TextTraceWriter::TextTraceWriter(size_t flush_threshold) : flush_threshold_(flush_threshold) {
    buffer_.reserve(flush_threshold_ + 4096);
}

TextTraceWriter::~TextTraceWriter() {
    flush();
    if (fd_ >= 0) close(fd_);
}

bool TextTraceWriter::open(const TraceContext &context) {
    char dir[256];
    snprintf(dir, sizeof(dir), "/data/data/%s/files/qbdi-traces", context.package_name.c_str());
    if (!mkdirs(dir)) return false;

    auto now = std::chrono::system_clock::now().time_since_epoch();
    long long millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char file[512];
    snprintf(file, sizeof(file), "%s/%lld_%d_%d_%s_0x%lx.trace.txt", dir, millis, context.pid,
             context.tid, context.scene_name.c_str(), static_cast<unsigned long>(context.target_offset));
    path_ = file;
    fd_ = ::open(path_.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    return fd_ >= 0;
}

void TextTraceWriter::begin(const TraceContext &context) {
    std::ostringstream out;
    out << "TRACE_BEGIN scene=" << context.scene_name
        << " target=" << context.target_so << "+0x" << std::hex << context.target_offset
        << " base=0x" << context.module_base
        << " address=0x" << context.target_address
        << " pid=" << std::dec << context.pid
        << " tid=" << context.tid << "\n";
    append(out.str());
}

void TextTraceWriter::instruction(const TraceContext &context, const InstructionText &inst) {
    std::ostringstream out;
    out << std::dec << inst.sequence << " " << context.target_so << "+0x" << std::hex
        << (inst.pc - context.module_base) << " " << inst.disassembly;
    if (!inst.reads.empty()) out << " | R:" << inst.reads;
    if (!inst.writes.empty()) out << " | W:" << inst.writes;
    for (const auto &mem : inst.memory) {
        out << " | MEM:" << mem.type << " addr=0x" << mem.address
            << " size=" << std::dec << mem.size << " value=0x" << std::hex << mem.value;
    }
    out << "\n";
    append(out.str());
}

void TextTraceWriter::memory(const TraceContext &context, uintptr_t pc, const MemoryAccessText &mem) {
    std::ostringstream out;
    out << "MEM " << context.target_so << "+0x" << std::hex << (pc - context.module_base)
        << " type=" << mem.type << " addr=0x" << mem.address
        << " size=" << std::dec << mem.size << " value=0x" << std::hex << mem.value << "\n";
    append(out.str());
}

void TextTraceWriter::call(const char *category, const std::string &name, const std::string &detail) {
    append(std::string("CALL ") + category + "." + name + " " + detail + "\n");
}

void TextTraceWriter::bypass(const std::string &name, const std::string &detail) {
    append("BYPASS " + name + " " + detail + "\n");
}

void TextTraceWriter::error(const std::string &message) {
    append("ERROR " + message + "\n");
}

void TextTraceWriter::end(uint64_t retval, bool ok, long elapsed_ms) {
    std::ostringstream out;
    out << "TRACE_END status=" << (ok ? "ok" : "failed") << " ret=0x" << std::hex << retval
        << " elapsed_ms=" << std::dec << elapsed_ms << " bytes=" << buffer_.size() << "\n";
    append(out.str());
    flush();
}

void TextTraceWriter::append(const std::string &line) {
    buffer_ += line;
    if (buffer_.size() >= flush_threshold_) flush();
}

void TextTraceWriter::flush() {
    if (fd_ >= 0 && !buffer_.empty()) {
        if (!write_all(fd_, buffer_.data(), buffer_.size())) {
            QTRACE_E("trace write failed: %s", strerror(errno));
        }
        buffer_.clear();
    }
}
```

- [ ] **Step 4: Update tracer CMake source list**

Modify `tracer/src/main/cpp/CMakeLists.txt` so `add_library(qbdi_tracer SHARED ...)` includes:

```cmake
add_library(qbdi_tracer SHARED
    tracer_entry.cpp
    core/module_maps.cpp
    core/safe_memory.cpp
    events/text_trace_writer.cpp)
```

- [ ] **Step 5: Build utilities**

Run: `./gradlew :tracer:assembleDebug`

Expected: native build succeeds with no missing includes.

- [ ] **Step 6: Commit tracer utilities**

```bash
git add tracer/src/main/cpp/core tracer/src/main/cpp/events tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat: add tracer utilities and text writer"
```

---

### Task 7: Implement Config and Hook Adapter

**Files:**
- Create: `tracer/src/main/cpp/core/trace_config.h`
- Create: `tracer/src/main/cpp/core/trace_config.cpp`
- Create: `tracer/src/main/cpp/hooks/inline_hook_adapter.h`
- Create: `tracer/src/main/cpp/hooks/inline_hook_adapter.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

- [ ] **Step 1: Add config model and parser**

Create `tracer/src/main/cpp/core/trace_config.h`:

```cpp
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct SceneConfig {
    size_t index = 0;
    std::string name;
    uintptr_t offset = 0;
    bool bypass_text = false;
    bool bypass_maps = false;
};

struct TraceConfig {
    std::string package_name = "com.aprz.qbdiandroid";
    std::string target_so = "libdemo_target.so";
    std::vector<SceneConfig> scenes;
};

TraceConfig default_trace_config();
TraceConfig parse_trace_config(const char *encoded_config);
```

Create `tracer/src/main/cpp/core/trace_config.cpp`:

```cpp
#include "core/trace_config.h"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

static std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> result;
    std::stringstream input(value);
    std::string item;
    while (std::getline(input, item, delimiter)) result.push_back(item);
    return result;
}

TraceConfig default_trace_config() {
    TraceConfig config;
    config.scenes = {
        {0, "init", 0, false, false},
        {1, "jni", 0, false, false},
        {2, "libc", 0, false, false},
        {3, "algorithm", 0, false, false},
        {4, "integrity", 0, true, true},
    };
    return config;
}

TraceConfig parse_trace_config(const char *encoded_config) {
    TraceConfig config = default_trace_config();
    if (encoded_config == nullptr || encoded_config[0] == '\0') return config;

    for (const std::string &part : split(encoded_config, ';')) {
        if (part.rfind("package=", 0) == 0) {
            config.package_name = part.substr(8);
        } else if (part.rfind("target=", 0) == 0) {
            config.target_so = part.substr(7);
        } else if (part.rfind("scene=", 0) == 0) {
            std::vector<std::string> fields = split(part.substr(6), ',');
            if (fields.size() < 2) continue;
            for (auto &scene : config.scenes) {
                if (scene.name != fields[0]) continue;
                scene.offset = strtoull(fields[1].c_str(), nullptr, 16);
                scene.bypass_text = false;
                scene.bypass_maps = false;
                for (size_t i = 2; i < fields.size(); ++i) {
                    if (fields[i] == "text_restore") scene.bypass_text = true;
                    if (fields[i] == "maps_sanitize") scene.bypass_maps = true;
                }
            }
        }
    }
    return config;
}
```

The encoded format is intentionally simple so Frida can pass it without adding a JSON parser to native code:

```text
package=com.aprz.qbdiandroid;target=libdemo_target.so;scene=init,0x1234;scene=integrity,0x5678,text_restore,maps_sanitize
```

- [ ] **Step 2: Add ShadowHook adapter**

Create `tracer/src/main/cpp/hooks/inline_hook_adapter.h`:

```cpp
#pragma once

#include <cstdint>

struct HookHandle {
    void *stub = nullptr;
    void *original = nullptr;
    uintptr_t target = 0;
};

bool init_inline_hook();
bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle);
bool unhook_function(HookHandle *handle);
```

Create `tracer/src/main/cpp/hooks/inline_hook_adapter.cpp`:

```cpp
#include "hooks/inline_hook_adapter.h"
#include "core/logging.h"

#include <shadowhook.h>

bool init_inline_hook() {
    int result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    if (result != 0) {
        QTRACE_E("shadowhook_init failed: %d", result);
        return false;
    }
    return true;
}

bool hook_function_address(uintptr_t target, void *replacement, HookHandle *handle) {
    if (target == 0 || replacement == nullptr || handle == nullptr) return false;
    handle->target = target;
    handle->stub = shadowhook_hook_func_addr(reinterpret_cast<void *>(target), replacement, &handle->original);
    if (handle->stub == nullptr) {
        int err = shadowhook_get_errno();
        QTRACE_E("hook 0x%lx failed: %d %s", static_cast<unsigned long>(target), err, shadowhook_to_errmsg(err));
        return false;
    }
    QTRACE_I("hooked 0x%lx original=%p", static_cast<unsigned long>(target), handle->original);
    return true;
}

bool unhook_function(HookHandle *handle) {
    if (handle == nullptr || handle->stub == nullptr) return true;
    int result = shadowhook_unhook(handle->stub);
    if (result != 0) {
        int err = shadowhook_get_errno();
        QTRACE_E("unhook 0x%lx failed: %d %s", static_cast<unsigned long>(handle->target), err, shadowhook_to_errmsg(err));
        return false;
    }
    handle->stub = nullptr;
    return true;
}
```

- [ ] **Step 3: Update CMake**

Add sources:

```cmake
core/trace_config.cpp
hooks/inline_hook_adapter.cpp
```

- [ ] **Step 4: Build config and hook adapter**

Run: `./gradlew :tracer:assembleDebug`

Expected: build succeeds and resolves ShadowHook symbols.

- [ ] **Step 5: Commit config and hook adapter**

```bash
git add tracer/src/main/cpp/core/trace_config.* tracer/src/main/cpp/hooks tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat: add offset config and inline hook adapter"
```

---

### Task 8: Implement QBDI Runner and Call Events

**Files:**
- Create: `tracer/src/main/cpp/core/qbdi_runner.h`
- Create: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Create: `tracer/src/main/cpp/handlers/call_handlers.h`
- Create: `tracer/src/main/cpp/handlers/call_handlers.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

- [ ] **Step 1: Add call handler declarations**

Create `tracer/src/main/cpp/handlers/call_handlers.h`:

```cpp
#pragma once

#include "events/text_trace_writer.h"

#include <QBDI.h>
#include <cstdint>

void emit_possible_external_call(QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer);
```

Create `tracer/src/main/cpp/handlers/call_handlers.cpp`:

```cpp
#include "handlers/call_handlers.h"
#include "core/safe_memory.h"

#include <dlfcn.h>
#include <sstream>
#include <unordered_map>

static std::unordered_map<uintptr_t, const char *> libc_targets() {
    void *libc = dlopen("libc.so", RTLD_NOW);
    std::unordered_map<uintptr_t, const char *> result;
    const char *names[] = {"strlen", "memcpy", "memcmp", "access", "fopen", "__system_property_get"};
    for (const char *name : names) {
        void *addr = libc != nullptr ? dlsym(libc, name) : nullptr;
        if (addr != nullptr) result.emplace(reinterpret_cast<uintptr_t>(addr), name);
    }
    return result;
}

void emit_possible_external_call(QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer) {
    static std::unordered_map<uintptr_t, const char *> libc = libc_targets();
    if (writer == nullptr || state == nullptr) return;
    auto libc_it = libc.find(target);
    if (libc_it != libc.end()) {
        std::ostringstream detail;
        uintptr_t x0 = QBDI_GPR_GET(state, 0);
        detail << "x0=0x" << std::hex << x0 << " preview=\"" << preview_c_string(x0) << "\"";
        writer->call("libc", libc_it->second, detail.str());
        return;
    }
}
```

- [ ] **Step 2: Add QBDI runner API**

Create `tracer/src/main/cpp/core/qbdi_runner.h`:

```cpp
#pragma once

#include "core/trace_config.h"
#include "core/module_maps.h"
#include "events/text_trace_writer.h"

#include <array>
#include <cstdint>

using GenericTargetFn = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

struct TraceInvocation {
    SceneConfig scene;
    ModuleRange module;
    uintptr_t target_address = 0;
    std::array<uint64_t, 8> args{};
};

uint64_t run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation);
```

- [ ] **Step 3: Implement QBDI runner callbacks**

Create `tracer/src/main/cpp/core/qbdi_runner.cpp`:

```cpp
#include "core/qbdi_runner.h"
#include "core/logging.h"
#include "handlers/call_handlers.h"

#include <QBDI.h>
#include <QBDI/State.h>
#include <chrono>
#include <sstream>
#include <vector>
#include <sys/syscall.h>
#include <unistd.h>

struct RunnerState {
    TraceContext context;
    TextTraceWriter writer;
    uint64_t sequence = 0;
};

static QBDI::VMAction on_memory(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const auto accesses = vm->getInstMemoryAccess();
    for (const auto &access : accesses) {
        MemoryAccessText mem;
        mem.type = access.type == QBDI::MEMORY_WRITE ? 'w' : 'r';
        mem.address = access.accessAddress;
        mem.size = access.size;
        mem.value = access.value;
        state->writer.memory(state->context, gpr->pc, mem);
    }
    return QBDI::CONTINUE;
}

static QBDI::VMAction on_instruction(QBDI::VM *vm, QBDI::GPRState *gpr, QBDI::FPRState *, void *data) {
    auto *state = static_cast<RunnerState *>(data);
    const QBDI::InstAnalysis *analysis = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_OPERANDS);
    InstructionText inst;
    inst.sequence = ++state->sequence;
    inst.pc = analysis->address;
    inst.disassembly = analysis->disassembly != nullptr ? analysis->disassembly : analysis->mnemonic;

    std::ostringstream reads;
    for (uint8_t i = 0; i < analysis->numOperands; ++i) {
        const auto &op = analysis->operands[i];
        if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0 &&
            (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE)) {
            reads << op.regName << "=0x" << std::hex << QBDI_GPR_GET(gpr, op.regCtxIdx) << " ";
        }
    }
    inst.reads = reads.str();

    if (analysis->isCall || analysis->isBranch) {
        if (analysis->numOperands > 0) {
            for (uint8_t i = 0; i < analysis->numOperands; ++i) {
                const auto &op = analysis->operands[i];
                if (op.type == QBDI::OPERAND_GPR && op.regCtxIdx >= 0 &&
                    (op.regAccess == QBDI::REGISTER_READ || op.regAccess == QBDI::REGISTER_READ_WRITE)) {
                    uintptr_t target = QBDI_GPR_GET(gpr, op.regCtxIdx);
                    emit_possible_external_call(gpr, target, &state->writer);
                    break;
                }
            }
        }
    }

    state->writer.instruction(state->context, inst);
    return QBDI::CONTINUE;
}

uint64_t run_with_qbdi(const TraceConfig &config, const TraceInvocation &invocation) {
    RunnerState state;
    state.context.package_name = config.package_name;
    state.context.scene_name = invocation.scene.name;
    state.context.target_so = config.target_so;
    state.context.module_base = invocation.module.start;
    state.context.target_offset = invocation.scene.offset;
    state.context.target_address = invocation.target_address;
    state.context.pid = getpid();
    state.context.tid = static_cast<int>(syscall(SYS_gettid));

    if (!state.writer.open(state.context)) {
        QTRACE_E("open trace file failed");
        return 0;
    }
    state.writer.begin(state.context);

    auto started = std::chrono::steady_clock::now();
    QBDI::VM vm;
    QBDI::GPRState *gpr = vm.getGPRState();
    for (int i = 0; i < 8; ++i) QBDI_GPR_SET(gpr, i, invocation.args[i]);
    gpr->pc = invocation.target_address;

    vm.addInstrumentedModuleFromAddr(invocation.module.start);
    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    vm.addCodeCB(QBDI::PREINST, on_instruction, &state);
    vm.addMemAccessCB(QBDI::MEMORY_READ_WRITE, on_memory, &state);

    QBDI::rword retval = 0;
    std::vector<QBDI::rword> args;
    args.reserve(invocation.args.size());
    for (uint64_t arg : invocation.args) args.push_back(arg);
    bool ok = vm.call(&retval, invocation.target_address, args);
    auto ended = std::chrono::steady_clock::now();
    long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(ended - started).count();
    state.writer.end(retval, ok, elapsed);
    QTRACE_I("trace %s complete path=%s", invocation.scene.name.c_str(), state.writer.path().c_str());
    return retval;
}
```

- [ ] **Step 4: Update CMake**

Add sources:

```cmake
core/qbdi_runner.cpp
handlers/call_handlers.cpp
```

- [ ] **Step 5: Build QBDI runner**

Run: `./gradlew :tracer:assembleDebug`

Expected: build succeeds with QBDI v0.12.1 `VM::call(rword*, rword, const std::vector<rword>&)`.

- [ ] **Step 6: Commit runner**

```bash
git add tracer/src/main/cpp/core/qbdi_runner.* tracer/src/main/cpp/handlers/call_handlers.* tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat: add QBDI runner and call events"
```

---

### Task 9: Wire Hooks to QBDI Execution

**Files:**
- Modify: `tracer/src/main/cpp/tracer_entry.cpp`
- Modify: `tracer/src/main/cpp/core/trace_config.h`
- Modify: `tracer/src/main/cpp/core/trace_config.cpp`

- [ ] **Step 1: Add exported configuration entry and per-scene proxies**

Modify `tracer/src/main/cpp/tracer_entry.cpp` so Frida calls `qbdi_tracer_configure()` after loading the tracer. Use one proxy per scene index so the hook can always identify its scene safely:

```cpp
#include "core/logging.h"
#include "core/module_maps.h"
#include "core/qbdi_runner.h"
#include "core/trace_config.h"
#include "hooks/inline_hook_adapter.h"

#include <array>
#include <mutex>
#include <thread>
#include <unistd.h>

struct InstalledSceneHook {
    SceneConfig scene;
    HookHandle hook;
    ModuleRange module;
    bool installed = false;
};

static std::mutex g_lock;
static TraceConfig g_config = default_trace_config();
static std::array<InstalledSceneHook, 5> g_hooks;

static uint64_t trace_proxy_init(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_jni(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_libc(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_algorithm(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t trace_proxy_integrity(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static uint64_t trace_proxy_for(size_t index, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3,
                                uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    if (index >= g_hooks.size() || !g_hooks[index].installed) {
        QTRACE_E("trace proxy for invalid scene index=%zu", index);
        return 0;
    }

    InstalledSceneHook &hook = g_hooks[index];
    TraceInvocation invocation;
    invocation.scene = hook.scene;
    invocation.module = hook.module;
    invocation.target_address = hook.module.start + hook.scene.offset;
    invocation.args = {x0, x1, x2, x3, x4, x5, x6, x7};

    unhook_function(&hook.hook);
    uint64_t result = run_with_qbdi(g_config, invocation);
    hook_function_address(invocation.target_address, reinterpret_cast<void *>(
        index == 0 ? trace_proxy_init :
        index == 1 ? trace_proxy_jni :
        index == 2 ? trace_proxy_libc :
        index == 3 ? trace_proxy_algorithm : trace_proxy_integrity), &hook.hook);
    return result;
}

static uint64_t trace_proxy_init(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(0, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_jni(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(1, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_libc(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(2, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_algorithm(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(3, x0, x1, x2, x3, x4, x5, x6, x7);
}

static uint64_t trace_proxy_integrity(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) {
    return trace_proxy_for(4, x0, x1, x2, x3, x4, x5, x6, x7);
}

static void *proxy_for_index(size_t index) {
    switch (index) {
        case 0: return reinterpret_cast<void *>(trace_proxy_init);
        case 1: return reinterpret_cast<void *>(trace_proxy_jni);
        case 2: return reinterpret_cast<void *>(trace_proxy_libc);
        case 3: return reinterpret_cast<void *>(trace_proxy_algorithm);
        case 4: return reinterpret_cast<void *>(trace_proxy_integrity);
        default: return nullptr;
    }
}

static bool install_scene_hook(const SceneConfig &scene, const ModuleRange &module) {
    if (scene.index >= g_hooks.size()) return false;
    if (scene.offset == 0) {
        QTRACE_W("scene %s offset is 0, skip", scene.name.c_str());
        return false;
    }
    InstalledSceneHook &slot = g_hooks[scene.index];
    slot.scene = scene;
    slot.module = module;
    uintptr_t target = module.start + scene.offset;
    if (!hook_function_address(target, proxy_for_index(scene.index), &slot.hook)) return false;
    slot.installed = true;
    return true;
}

static void install_hooks_when_ready(TraceConfig config) {
    if (!init_inline_hook()) return;
    for (int attempt = 0; attempt < 200; ++attempt) {
        ModuleRange module;
        if (find_module_executable_range(config.target_so, &module)) {
            std::lock_guard<std::mutex> guard(g_lock);
            g_config = config;
            QTRACE_I("target module %s base=0x%lx", config.target_so.c_str(), static_cast<unsigned long>(module.start));
            for (const auto &scene : g_config.scenes) install_scene_hook(scene, module);
            return;
        }
        usleep(50 * 1000);
    }
    QTRACE_E("target module %s not found", config.target_so.c_str());
}

extern "C" __attribute__((visibility("default"))) void qbdi_tracer_configure(const char *encoded_config) {
    TraceConfig config = parse_trace_config(encoded_config);
    QTRACE_I("configure tracer package=%s target=%s", config.package_name.c_str(), config.target_so.c_str());
    std::thread(install_hooks_when_ready, config).detach();
}

__attribute__((constructor)) static void qbdi_tracer_init() {
    QTRACE_I("libqbdi_tracer loaded; waiting for qbdi_tracer_configure");
}
```


- [ ] **Step 2: Build hook wiring**

Run: `./gradlew :tracer:assembleDebug :tracer:copyTracerDebug`

Expected: build succeeds.

- [ ] **Step 3: Commit hook wiring**

```bash
git add tracer/src/main/cpp/tracer_entry.cpp tracer/src/main/cpp/core/trace_config.*
git commit -m "feat: route configured scenes into QBDI"
```

---

### Task 10: Add Integrity Bypass Handlers

**Files:**
- Create: `tracer/src/main/cpp/handlers/bypass_handlers.h`
- Create: `tracer/src/main/cpp/handlers/bypass_handlers.cpp`
- Modify: `tracer/src/main/cpp/core/qbdi_runner.cpp`
- Modify: `tracer/src/main/cpp/CMakeLists.txt`

- [ ] **Step 1: Add bypass handler API**

Create `tracer/src/main/cpp/handlers/bypass_handlers.h`:

```cpp
#pragma once

#include "core/trace_config.h"
#include "events/text_trace_writer.h"

#include <QBDI.h>
#include <cstdint>

enum class BypassDecision {
    Continue,
    SkipInstruction,
};

void emit_scene_bypass_markers(const SceneConfig &scene, TextTraceWriter *writer);
BypassDecision maybe_bypass_external_call(const SceneConfig &scene, QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer);
```

- [ ] **Step 2: Implement `.text` and maps bypass decisions**

Create `tracer/src/main/cpp/handlers/bypass_handlers.cpp`:

```cpp
#include "handlers/bypass_handlers.h"
#include "core/safe_memory.h"

#include <cstring>
#include <dlfcn.h>
#include <sstream>
#include <string>

static uintptr_t libc_symbol(const char *name) {
    void *handle = dlopen("libc.so", RTLD_NOW);
    void *symbol = handle != nullptr ? dlsym(handle, name) : nullptr;
    return reinterpret_cast<uintptr_t>(symbol);
}

static bool suspicious_needle(const std::string &needle) {
    return needle.find("frida") != std::string::npos ||
           needle.find("gum-js-loop") != std::string::npos ||
           needle.find("libqbdi_tracer") != std::string::npos ||
           needle.find("libQBDI") != std::string::npos ||
           needle.find("shadowhook") != std::string::npos;
}

void emit_scene_bypass_markers(const SceneConfig &scene, TextTraceWriter *writer) {
    if (writer == nullptr) return;
    if (scene.bypass_text) {
        writer->bypass("text_restore", "armed=true strategy=unhook_entry_before_qbdi_and_skip_text_memcmp");
    }
    if (scene.bypass_maps) {
        writer->bypass("maps_sanitize", "armed=true strategy=skip_suspicious_strstr_calls");
    }
}

BypassDecision maybe_bypass_external_call(const SceneConfig &scene, QBDI::GPRState *state, uintptr_t target, TextTraceWriter *writer) {
    static uintptr_t memcmp_addr = libc_symbol("memcmp");
    static uintptr_t strstr_addr = libc_symbol("strstr");
    static uintptr_t strcasestr_addr = libc_symbol("strcasestr");
    if (state == nullptr || writer == nullptr) return BypassDecision::Continue;

    if (scene.bypass_text && target == memcmp_addr) {
        uint64_t size = QBDI_GPR_GET(state, 2);
        if (size >= 16 && size <= 256) {
            QBDI_GPR_SET(state, 0, 0);
            std::ostringstream detail;
            detail << "target=memcmp size=" << std::dec << size << " forced_result=0";
            writer->bypass("text_hash_memcmp", detail.str());
            return BypassDecision::SkipInstruction;
        }
    }

    if (scene.bypass_maps && (target == strstr_addr || target == strcasestr_addr)) {
        uintptr_t needle_ptr = QBDI_GPR_GET(state, 1);
        std::string needle = preview_c_string(needle_ptr, 96);
        if (suspicious_needle(needle)) {
            QBDI_GPR_SET(state, 0, 0);
            writer->bypass("maps_sanitize", "needle=\"" + needle + "\" forced_result=null");
            return BypassDecision::SkipInstruction;
        }
    }

    return BypassDecision::Continue;
}
```

The `.text` path has two protections: the scene hook is unhooked before QBDI execution, restoring the entry bytes, and suspicious `memcmp` calls used by the text check can be skipped with a zero result. The maps path skips libc substring checks for known injected-module needles.

- [ ] **Step 3: Invoke bypass handlers from QBDI callbacks**

Modify `RunnerState` in `tracer/src/main/cpp/core/qbdi_runner.cpp`:

```cpp
struct RunnerState {
    TraceContext context;
    SceneConfig scene;
    TextTraceWriter writer;
    uint64_t sequence = 0;
    bool bypass_markers_emitted = false;
};
```

Set `state.scene = invocation.scene;` in `run_with_qbdi()` after `state.context` initialization.

Include the header:

```cpp
#include "handlers/bypass_handlers.h"
```

At the top of `on_instruction()`, after `analysis` is loaded, add:

```cpp
if (!state->bypass_markers_emitted) {
    emit_scene_bypass_markers(state->scene, &state->writer);
    state->bypass_markers_emitted = true;
}
```

Inside the branch/call target loop, before `emit_possible_external_call(...)`, add:

```cpp
BypassDecision decision = maybe_bypass_external_call(state->scene, gpr, target, &state->writer);
if (decision == BypassDecision::SkipInstruction) {
    return QBDI::SKIP_INST;
}
```

- [ ] **Step 4: Update CMake**

Add source:

```cmake
handlers/bypass_handlers.cpp
```

- [ ] **Step 5: Build bypass handlers**

Run: `./gradlew :tracer:assembleDebug`

Expected: build succeeds and integrity traces include bypass events when enabled.

- [ ] **Step 6: Commit bypass handlers**

```bash
git add tracer/src/main/cpp/handlers/bypass_handlers.* tracer/src/main/cpp/core/qbdi_runner.cpp tracer/src/main/cpp/CMakeLists.txt
git commit -m "feat: add integrity bypass handlers"
```

---

### Task 11: Add Frida Scripts and Offset Config

**Files:**
- Create: `scripts/trace_config.js`
- Create: `scripts/spawn_trace.js`

- [ ] **Step 1: Add editable scene config**

Create `scripts/trace_config.js`:

```js
'use strict';

module.exports = {
  packageName: 'com.aprz.qbdiandroid',
  remoteDir: '/data/local/tmp/qbdi-android',
  shadowhook: 'libshadowhook.so',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  scenes: {
    init: { offset: '0x0', bypass: [] },
    jni: { offset: '0x0', bypass: [] },
    libc: { offset: '0x0', bypass: [] },
    algorithm: { offset: '0x0', bypass: [] },
    integrity: { offset: '0x0', bypass: ['text_restore', 'maps_sanitize'] }
  }
};
```

- [ ] **Step 2: Add spawn injection script**

Create `scripts/spawn_trace.js`:

```js
'use strict';

const config = require('./trace_config.js');

function loadLibrary(path) {
  try {
    const module = Module.load(path);
    console.log('[+] loaded ' + path + ' base=' + module.base);
    return module;
  } catch (e) {
    console.error('[-] failed to load ' + path + ': ' + e);
    throw e;
  }
}

function encodeConfig(cfg) {
  const parts = ['package=' + cfg.packageName, 'target=' + cfg.targetSo];
  for (const [name, scene] of Object.entries(cfg.scenes)) {
    parts.push(['scene=' + name, scene.offset].concat(scene.bypass).join(','));
  }
  return parts.join(';');
}

function configureTracer(tracerName, encoded) {
  const configurePtr = Module.getExportByName(tracerName, 'qbdi_tracer_configure');
  const configure = new NativeFunction(configurePtr, 'void', ['pointer']);
  const nativeConfig = Memory.allocUtf8String(encoded);
  configure(nativeConfig);
  console.log('[+] tracer configured: ' + encoded);
}

function main() {
  const dir = config.remoteDir.replace(/\/$/, '');
  loadLibrary(dir + '/' + config.shadowhook);
  loadLibrary(dir + '/' + config.tracer);
  configureTracer(config.tracer, encodeConfig(config));
  console.log('[+] tracer injected; tap a demo button for non-init scenes');
}

setImmediate(main);
```

- [ ] **Step 3: Add script usage smoke check**

Run: `node -c scripts/trace_config.js && node -c scripts/spawn_trace.js`

Expected: both commands return exit code 0.

- [ ] **Step 4: Commit Frida scripts**

```bash
git add scripts/trace_config.js scripts/spawn_trace.js
git commit -m "feat: add Frida spawn scripts"
```

---

### Task 12: Add User Documentation

**Files:**
- Create: `README.md`
- Create: `docs/ida-offsets.md`
- Create: `docs/trace-format.md`
- Create: `docs/integrity-bypass.md`

- [ ] **Step 1: Add README**

Create `README.md`:

```markdown
# qbdi-android

Android arm64 demo project for showing how to use QBDI in an injected tracer.

## What This Demo Shows

- A Kotlin APK loads a stripped native target library.
- Native methods are registered dynamically with `RegisterNatives`.
- A native constructor triggers an init-stage function.
- Button-driven scenes exercise JNI calls, libc calls, a custom algorithm, and integrity checks.
- A separate `libqbdi_tracer.so` is injected with Frida spawn.
- The tracer hooks scene entry offsets with ByteDance ShadowHook and executes them in QBDI.
- Text traces are written to `/data/data/com.aprz.qbdiandroid/files/qbdi-traces/`.

## Dependencies

- Android Studio or Android SDK + NDK
- CMake 3.22.1+
- arm64 Android device or emulator
- Frida server matching your host Frida version
- QBDI v0.12.1 Android AARCH64 artifact committed under `tracer/src/main/cpp/third_party/qbdi/`
- ByteDance ShadowHook v2.0.1 from Maven Central

## Build

```bash
./gradlew :app:assembleDebug
./gradlew :tracer:assembleDebug :tracer:copyTracerDebug
```

## Install and Deploy

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell mkdir -p /data/local/tmp/qbdi-android
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
```

Also push `libshadowhook.so` from the tracer module build output or from the ShadowHook prefab artifact into `/data/local/tmp/qbdi-android/`.

## Find Scene Offsets

Open the stripped `libdemo_target.so` in IDA or Ghidra. Use strings and call references to locate:

- `demo_init_stage`
- `demo_jni_case`
- `demo_libc_case`
- `demo_algorithm_case`
- `demo_integrity_case`

Write relative offsets into `scripts/trace_config.js`.

## Inject

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js --no-pause
```

The constructor scene only traces reliably with spawn injection. For button scenes, wait for the UI and tap the desired button.

## Pull Traces

```bash
adb shell run-as com.aprz.qbdiandroid ls files/qbdi-traces
adb exec-out run-as com.aprz.qbdiandroid cat files/qbdi-traces/<trace-file> > trace.txt
```
```

- [ ] **Step 2: Add offset guide**

Create `docs/ida-offsets.md`:

```markdown
# Finding Scene Offsets

The tracer uses `module_base + offset`, not runtime symbol lookup.

## IDA Workflow

1. Open `libdemo_target.so` from the APK native library directory.
2. Let IDA analyze the file as AArch64 ELF.
3. Search strings such as `JNI scene finished`, `libc scene`, `integrity scene`, and `constructor complete`.
4. Follow xrefs from those strings to the containing functions.
5. Record the function start offset shown by IDA relative to the image base.
6. Put the offset into `scripts/trace_config.js`.

## objdump Workflow

```bash
llvm-objdump -d app/build/intermediates/merged_native_libs/debug/out/lib/arm64-v8a/libdemo_target.so | less
```

Use nearby strings from `llvm-strings` to identify functions and record offsets.
```

- [ ] **Step 3: Add trace format guide**

Create `docs/trace-format.md`:

```markdown
# Text Trace Format

Trace files live under the app private directory:

```text
/data/data/com.aprz.qbdiandroid/files/qbdi-traces/
```

Each trace starts with `TRACE_BEGIN` and ends with `TRACE_END`.

Instruction line:

```text
<seq> <module>+<offset> <disassembly> | R:<register reads> | W:<register writes> | MEM:<memory events>
```

Call events:

```text
CALL libc.strlen x0=0x... preview="qbdi"
CALL jni.FindClass name="java/lang/String"
```

Bypass events:

```text
BYPASS text_hash_restore range=libdemo_target.so+0x...
BYPASS maps_sanitize hidden=frida,libqbdi_tracer,libQBDI
```
```

- [ ] **Step 4: Add integrity bypass guide**

Create `docs/integrity-bypass.md`:

```markdown
# Integrity Checks and Bypass Demo

The integrity scene contains two checks:

1. `.text` hash validation for a selected executable range.
2. `/proc/self/maps` inspection for injected modules and suspicious mappings.

Without bypass, the scene can intentionally crash. With bypass enabled, tracer events show what was repaired or hidden before the target check observes it.

First-version bypass handlers emit explicit `BYPASS` markers. Precise `.text` byte restoration and maps buffer rewriting are implemented around the same handler names so the trace format remains stable.
```

- [ ] **Step 5: Commit docs**

```bash
git add README.md docs/ida-offsets.md docs/trace-format.md docs/integrity-bypass.md
git commit -m "docs: add usage and trace guides"
```

---

### Task 13: Validate Build and Local Scripts

**Files:**
- Modify only files needed to fix build errors from previous tasks.

- [ ] **Step 1: Run full Gradle build**

Run:

```bash
./gradlew clean :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug
```

Expected:

- `app/build/outputs/apk/debug/app-debug.apk` exists.
- `app/build/intermediates/merged_native_libs/debug/out/lib/arm64-v8a/libdemo_target.so` exists.
- `out/arm64-v8a/libqbdi_tracer.so` exists.

- [ ] **Step 2: Run script syntax checks**

Run:

```bash
node -c scripts/trace_config.js
node -c scripts/spawn_trace.js
```

Expected: both commands exit successfully.

- [ ] **Step 3: Inspect exported symbols**

Run:

```bash
llvm-nm -D app/build/intermediates/merged_native_libs/debug/out/lib/arm64-v8a/libdemo_target.so | rg "Java_|demo_" || true
```

Expected: no `Java_...` static JNI symbols. Debug builds may retain local symbols, but dynamic exported static JNI symbols must not exist.

- [ ] **Step 4: Commit validation fixes**

If any fixes were needed:

```bash
git add <fixed-files>
git commit -m "fix: resolve build validation issues"
```

If no fixes were needed, do not create an empty commit.

---

### Task 14: Device Smoke Test

**Files:**
- Modify docs or scripts only if smoke test reveals incorrect instructions.

- [ ] **Step 1: Install app**

Run:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Expected: install succeeds.

- [ ] **Step 2: Deploy tracer libraries**

Run:

```bash
adb shell mkdir -p /data/local/tmp/qbdi-android
adb push out/arm64-v8a/libqbdi_tracer.so /data/local/tmp/qbdi-android/
```

Also locate and push `libshadowhook.so` from the Gradle dependency extraction or tracer build intermediates:

```bash
find tracer/build -name libshadowhook.so -print
adb push <found-libshadowhook.so> /data/local/tmp/qbdi-android/
```

Expected: both `.so` files exist in `/data/local/tmp/qbdi-android/`.

- [ ] **Step 3: Spawn inject**

Run:

```bash
frida -U -f com.aprz.qbdiandroid -l scripts/spawn_trace.js --no-pause
```

Expected: Frida prints loaded ShadowHook and tracer paths, app UI appears, and logcat contains `libqbdi_tracer loaded`.

- [ ] **Step 4: Tap button scenes**

Tap JNI, libc, algorithm, and integrity buttons.

Expected:

- UI shows result text for JNI/libc/algorithm.
- Integrity may crash until precise bypass write-back is implemented; this is acceptable if the trace contains bypass markers and docs state the first-version behavior.
- At least one trace file appears under `files/qbdi-traces`.

- [ ] **Step 5: Pull trace**

Run:

```bash
adb shell run-as com.aprz.qbdiandroid ls files/qbdi-traces
adb exec-out run-as com.aprz.qbdiandroid sh -c 'cat files/qbdi-traces/*.trace.txt' > /tmp/qbdi-trace.txt
```

Expected: `/tmp/qbdi-trace.txt` contains `TRACE_BEGIN` and `TRACE_END`.

- [ ] **Step 6: Commit smoke-test doc fixes**

If instructions needed updates:

```bash
git add README.md docs scripts
git commit -m "docs: refine device smoke test instructions"
```

---

### Task 15: Final Review and Push

**Files:**
- No new files unless final review finds issues.

- [ ] **Step 1: Review git history**

Run:

```bash
git log --oneline --decorate -10
git status --short
```

Expected: working tree is clean except intentionally ignored build outputs.

- [ ] **Step 2: Run final verification**

Run:

```bash
./gradlew :app:assembleDebug :tracer:assembleDebug :tracer:copyTracerDebug
node -c scripts/trace_config.js
node -c scripts/spawn_trace.js
```

Expected: all commands succeed.

- [ ] **Step 3: Push to GitHub**

Run:

```bash
git push origin main
```

Expected: push succeeds to `git@github.com:aprz512/qbdi-android.git`.

---

## Self-Review Checklist

- Spec coverage:
  - Kotlin + CMake APK: Tasks 1-3.
  - Dynamic JNI registration: Task 3.
  - Constructor init scene: Task 3.
  - JNI/libc/algorithm scenes: Task 3.
  - `.text` and maps integrity checks: Task 3.
  - QBDI official release artifact: Task 4.
  - ByteDance ShadowHook backend: Tasks 1, 5, 7.
  - Offset-based config: Tasks 7 and 11.
  - Text trace writer interface: Task 6.
  - QBDI runner and instruction trace: Task 8.
  - Bypass event hooks: Task 10.
  - Frida spawn workflow: Task 11.
  - Docs and IDA offset guide: Task 12.
  - Validation and push: Tasks 13-15.
- Placeholder scan: no unresolved markers and no unspecified file paths.
- Type consistency: `TraceConfig`, `SceneConfig`, `TraceContext`, `TextTraceWriter`, `HookHandle`, and `TraceInvocation` names are used consistently across tasks.
