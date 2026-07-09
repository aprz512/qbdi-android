cmake_minimum_required(VERSION 3.22.1)

project(qbdi_android_demo_target LANGUAGES CXX)

add_library(
    demo_target
    SHARED
    demo_target/demo_target.cpp
    demo_target/demo_scenes.cpp
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

find_library(log-lib log)

target_link_libraries(demo_target PRIVATE android ${log-lib})
