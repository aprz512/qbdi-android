#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>

#include "events/trace_record.h"

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

std::string read_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void production_sources_have_only_the_binary_trace_facade() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    std::string production = read_file(root / "CMakeLists.txt");
    for (const char *directory : {"core", "handlers", "rules"}) {
        for (const auto &entry : std::filesystem::recursive_directory_iterator(root / directory)) {
            if (!entry.is_regular_file()) continue;
            const auto extension = entry.path().extension();
            if (extension == ".cpp" || extension == ".h") production += read_file(entry.path());
        }
    }

    CHECK(production.find("TextTraceWriter") == std::string::npos);
    CHECK(production.find("events/text_trace_writer") == std::string::npos);
    CHECK(production.find("events/trace_encoder") == std::string::npos);
    CHECK(production.find(".trace.txt.lz4") == std::string::npos);
    CHECK(!std::regex_search(production,
                             std::regex(R"((^|[^A-Za-z0-9_])TraceEncoder([^A-Za-z0-9_]|$))")));
    CHECK(production.find("events/binary_trace_writer.cpp") != std::string::npos);
}

void instruction_event_model_has_no_text_hot_fields() {
    CHECK(sizeof(MemoryRecord) == 168);
    CHECK(sizeof(InstructionRecord) == 1944);
}

void pending_instruction_reuse_does_not_clear_the_whole_hot_record() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string source = read_file(root / "core" / "pending_instruction.cpp");
    CHECK(source.find("pending_record_ = {};") == std::string::npos);
    CHECK(source.find("pending_record_.reads.count = 0;") != std::string::npos);
    CHECK(source.find("pending_record_.writes.count = 0;") != std::string::npos);
    CHECK(source.find("pending_record_.memory_count = 0;") != std::string::npos);
}

void android_debug_compression_is_not_built_unoptimized() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string cmake = read_file(root / "CMakeLists.txt");
    CHECK(cmake.find("target_compile_options(lz4_static PRIVATE\n"
                     "            $<$<CONFIG:Debug>:-O2>)") != std::string::npos);
}

} // namespace

int main() {
    production_sources_have_only_the_binary_trace_facade();
    instruction_event_model_has_no_text_hot_fields();
    pending_instruction_reuse_does_not_clear_the_whole_hot_record();
    android_debug_compression_is_not_built_unoptimized();
}
