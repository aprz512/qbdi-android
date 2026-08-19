#include <cassert>
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

std::string function_body(const std::string &source, const char *name,
                          const char *next_name) {
    const size_t begin = source.find(name);
    const size_t end = source.find(next_name, begin + 1);
    assert(begin != std::string::npos && end != std::string::npos);
    return source.substr(begin, end - begin);
}

} // namespace

int main() {
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
