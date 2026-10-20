if(NOT EXISTS "${QBDI_ROOT}/CMakeLists.txt")
    message(FATAL_ERROR "QBDI submodule is missing. Run: git submodule update --init --recursive")
endif()
if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "QBDI tracer supports Android arm64-v8a only")
endif()

# Keep the engine optimized and avoid QBDI's forced Debug logging, including in
# Debug tracer builds. This directory scope leaves the tracer build type intact.
set(CMAKE_BUILD_TYPE Release)
set(QBDI_PLATFORM android)
set(QBDI_ARCH AARCH64)
set(QBDI_STATIC_LIBRARY ON)
set(QBDI_SHARED_LIBRARY OFF)
set(QBDI_TEST OFF)
set(QBDI_BENCHMARK OFF)
set(QBDI_EXAMPLES OFF)
set(QBDI_INCLUDE_DOCS OFF)
set(QBDI_INCLUDE_PACKAGE OFF)
set(QBDI_INSTALL OFF)
set(QBDI_TOOLS_PYQBDI OFF)
set(QBDI_TOOLS_FRIDAQBDI OFF)
set(QBDI_LOG_DEBUG OFF)
set(QBDI_CCACHE OFF)

# Keep downloads and generated files outside the submodule working tree.
set(QBDI_THIRD_PARTY_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/downloads")
set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps")
add_subdirectory("${QBDI_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/build" EXCLUDE_FROM_ALL)
