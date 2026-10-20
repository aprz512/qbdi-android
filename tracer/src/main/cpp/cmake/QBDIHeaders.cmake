# Host tests use the Android AARCH64 API layout without building the QBDI engine
# or LLVM. Generate platform headers from the same submodule as the Android build.
get_filename_component(QBDI_ROOT "${CMAKE_CURRENT_LIST_DIR}/../third_party/qbdi" ABSOLUTE)
if(NOT EXISTS "${QBDI_ROOT}/cmake/QBDIConfig.cmake")
    message(FATAL_ERROR "QBDI submodule is missing. Run: git submodule update --init --recursive")
endif()

function(qtrace_configure_qbdi_headers output_dir)
    set(QBDI_PLATFORM android)
    set(QBDI_ARCH AARCH64)
    include("${QBDI_ROOT}/cmake/QBDIConfig.cmake")
    set(QBDI_LOG_DEBUG OFF)
    set(QBDI_ENABLE_LOG_DEBUG 0)
    configure_file("${QBDI_ROOT}/include/QBDI/Config.h.in"
            "${output_dir}/QBDI/Config.h" @ONLY)
    configure_file("${QBDI_ROOT}/include/QBDI/Version.h.in"
            "${output_dir}/QBDI/Version.h" @ONLY)
    foreach(header State Options)
        configure_file("${QBDI_ROOT}/include/QBDI/arch/AARCH64/${header}.h"
                "${output_dir}/QBDI/${header}.h" COPYONLY)
    endforeach()
    set(QTRACE_QBDI_INCLUDE_DIRS "${output_dir}" "${QBDI_ROOT}/include" PARENT_SCOPE)
endfunction()

if(CMAKE_SCRIPT_MODE_FILE)
    if(NOT QTRACE_QBDI_HEADER_DIR)
        message(FATAL_ERROR "Set QTRACE_QBDI_HEADER_DIR to the generated header directory")
    endif()
    qtrace_configure_qbdi_headers("${QTRACE_QBDI_HEADER_DIR}")
endif()
