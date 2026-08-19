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
    return 0;
}
