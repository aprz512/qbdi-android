#include "hooks/inline_hook_adapter.h"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string read_source(const char *relative) {
    std::ifstream input(std::string(QTRACE_SOURCE_DIR) + "/" + relative);
    std::ostringstream contents;
    contents << input.rdbuf();
    assert(input.good() || input.eof());
    return contents.str();
}

std::string read_cpp_source(const char *relative) {
    std::ifstream input(std::string(QTRACE_CPP_SOURCE_DIR) + "/" + relative);
    std::ostringstream contents;
    contents << input.rdbuf();
    assert(input.good() || input.eof());
    return contents.str();
}

std::string read_repo_source(const char *relative) {
    std::ifstream input(std::string(QTRACE_REPO_DIR) + "/" + relative);
    std::ostringstream contents;
    contents << input.rdbuf();
    assert(input.good() || input.eof());
    return contents.str();
}

std::string function_body(const std::string &source, const char *name,
                          const char *next_name) {
    const size_t begin = source.find(name);
    const size_t end = source.find(next_name, begin + 1);
    assert(begin != std::string::npos && end != std::string::npos);
    return source.substr(begin, end - begin);
}

void assert_owned_sources_do_not_contain(const char *relative_root,
                                         const std::string &needle) {
    const std::filesystem::path root =
            std::filesystem::path(QTRACE_REPO_DIR) / relative_root;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file() ||
            entry.path().string().find("/third_party/") != std::string::npos) {
            continue;
        }
        const std::string extension = entry.path().extension().string();
        if (extension != ".c" && extension != ".cc" && extension != ".cpp" &&
            extension != ".h" && extension != ".hpp") {
            continue;
        }
        std::ifstream input(entry.path());
        std::ostringstream contents;
        contents << input.rdbuf();
        assert(contents.str().find(needle) == std::string::npos);
    }
}

} // namespace

int main() {
    static_assert(kShadowHookArm64OriginalSlotBytes == 64);
    const std::string enter = read_source("sh_enter.c");
    assert(enter.find("sh_trampo_free(&sh_enter_trampo_mgr, enter)") != std::string::npos);

    const std::string arm64 = read_source("arch/arm64/sh_inst.c");
    assert(arm64.find("owned->enter = self->enter") != std::string::npos);
    assert(arm64.find("owned->island_enter = self->island_enter") != std::string::npos);
    assert(arm64.find("owned->island_rewrite = self->island_rewrite") != std::string::npos);
    assert(arm64.find("sh_inst_unhook_impl(self, target_addr, load_bias, NULL)") !=
           std::string::npos);
    assert(arm64.find("if (NULL != owned) sh_inst_retained_unclaim(owned)") !=
           std::string::npos);

    const std::string api = read_source("shadowhook.c");
    assert(api.find("shadowhook_unhook_qtrace_retain") != std::string::npos);

    const std::string tracer = read_cpp_source("tracer_entry.cpp");
    const std::string constructor_pre =
            function_body(tracer, "static void module_constructor_pre(",
                          "static void module_destructor_post(");
    assert(constructor_pre.find("module_range_from_phdr(*info, &module)") !=
           std::string::npos);
    assert(constructor_pre.find("install_hooks_for_module(module, 0, true)") !=
           std::string::npos);
    assert(constructor_pre.find("module_range_from_phdr") <
           constructor_pre.find("install_hooks_for_module"));

    const std::string callback_setup =
            function_body(tracer, "static bool prepare_module_callbacks()",
                          "static uintptr_t scene_logical_pc");
    assert(callback_setup.find(
                   "register_inline_hook_dl_init_callback(\n"
                   "            module_constructor_pre, nullptr)") !=
           std::string::npos);
    assert(callback_setup.find("register_inline_hook_dl_fini_callback(") !=
           std::string::npos);
    assert(callback_setup.find(
                   "module_destructor_post, nullptr)") !=
           std::string::npos);

    const std::string adapter = read_cpp_source("hooks/inline_hook_adapter.cpp");
    const std::string init_registration =
            function_body(adapter, "bool register_inline_hook_dl_init_callback(",
                          "bool register_inline_hook_dl_fini_callback(");
    assert(init_registration.find(
                   "shadowhook_register_dl_init_callback(\n"
                   "            callback, nullptr, opaque)") !=
           std::string::npos);
    const std::string fini_registration =
            function_body(adapter, "bool register_inline_hook_dl_fini_callback(",
                          "bool hook_function_address(");
    assert(fini_registration.find(
                   "shadowhook_register_dl_fini_callback(\n"
                   "            nullptr, callback, opaque)") !=
           std::string::npos);

    const std::string build = read_cpp_source("CMakeLists.txt");
    assert(build.find("SHADOWHOOK_DISABLE_LINKER_INIT") == std::string::npos);
    assert(build.find("-Wl,-z,nodelete") != std::string::npos);
    for (const char *removed : {"ModuleGenerationRetainer",
                                "ModuleRetentionLease", "RTLD_NOLOAD",
                                "select_module_handle_probe",
                                "RetentionPending", "begin_loading",
                                "retain_postloaded"}) {
        assert_owned_sources_do_not_contain("tracer/src/main/cpp", removed);
        assert(build.find(removed) == std::string::npos);
    }
    assert_owned_sources_do_not_contain(
            "tracer/src",
            std::string("retention_flags_") + "address");
    assert_owned_sources_do_not_contain(
            "tracer/src",
            std::string("flight_atomic_fetch_") + "and_u32");
    const std::string spawn = read_repo_source("scripts/spawn_trace.js");
    assert(spawn.find("if (!config.flight.enabled) installModuleObserver") !=
           std::string::npos);
    const std::string tracer_child =
            function_body(tracer, "static void tracer_atfork_child()",
                          "static void install_hooks_for_module");
    assert(tracer_child.find(".unlock") == std::string::npos);
    assert(tracer_child.find(".~mutex") == std::string::npos);
    assert(tracer_child.find("new (") == std::string::npos);

    const std::string crash = read_cpp_source("core/crash_marker.cpp");
    const std::string crash_child =
            function_body(crash, "void crash_marker_atfork_child()",
                          "CrashMarkerSession::~CrashMarkerSession");
    assert(crash_child.find(".unlock") == std::string::npos);
    assert(crash_child.find(".~mutex") == std::string::npos);
    assert(crash_child.find("new (") == std::string::npos);
    return 0;
}
