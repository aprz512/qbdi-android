cmake_minimum_required(VERSION 3.22.1)

project(qbdi_android_demo_target LANGUAGES C CXX)

set(ANDROID_16KB_PAGE_LINK_OPTIONS "-Wl,-z,max-page-size=16384")
set(SHADOWHOOK_NOTHING_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tracer/src/main/cpp/third_party/android-inline-hook/shadowhook/src/main/cpp/nothing/sh_nothing.c)

add_library(shadowhook_nothing SHARED ${SHADOWHOOK_NOTHING_SOURCE})
target_compile_options(shadowhook_nothing PRIVATE
    -Oz -fno-ident -fno-unwind-tables -fno-asynchronous-unwind-tables)
target_link_options(shadowhook_nothing PRIVATE
    ${ANDROID_16KB_PAGE_LINK_OPTIONS}
    -Wl,--strip-all
    -Wl,--as-needed
    -Wl,--hash-style=sysv
    -Wl,--build-id=none
    -Wl,-nostdlib
    -nostartfiles
    -nodefaultlibs)

add_library(
    demo_target
    SHARED
    demo_target/demo_target.cpp
    demo_target/demo_scenes.cpp
    demo_target/pthread_fixture.cpp
    demo_target/integrity.cpp
)

target_compile_features(demo_target PRIVATE cxx_std_20)

target_compile_options(
    demo_target
    PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
)

target_link_options(demo_target PRIVATE ${ANDROID_16KB_PAGE_LINK_OPTIONS})

find_library(log-lib log)

target_link_libraries(demo_target PRIVATE android ${log-lib})
