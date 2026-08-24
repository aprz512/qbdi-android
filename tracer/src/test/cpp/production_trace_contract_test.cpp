#include <cstdio>
#include <cstdlib>
#include <array>
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

std::string read_command(const std::string &command) {
    FILE *pipe = ::popen(command.c_str(), "r");
    CHECK(pipe != nullptr);
    std::array<char, 512> buffer{};
    std::string output;
    while (std::fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output += buffer.data();
    }
    CHECK(::pclose(pipe) == 0);
    return output;
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

void flight_register_sync_follows_simulated_call_setup() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string source =
            read_file(root / "core" / "qbdi_thread_session.cpp");
    const size_t call = source.find("QBDI::simulateCallA(gpr, kReturnAddress");
    const size_t sync = source.find("flight_sink.sync_registers(*gpr)", call);
    const size_t run = source.find("vm.run(execution_entry, kReturnAddress)", sync);
    CHECK(call != std::string::npos);
    CHECK(sync != std::string::npos);
    CHECK(run != std::string::npos);
    CHECK(call < sync);
    CHECK(sync < run);
}

void active_qbdi_tls_is_trivial_and_the_session_owns_its_coordinator() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string source =
            read_file(root / "core" / "qbdi_thread_session.cpp");
    const std::string header =
            read_file(root / "core" / "qbdi_thread_session.h");

    CHECK(header.find(
                  "std::shared_ptr<CaptureCoordinator> active_capture_owner_") !=
          std::string::npos);
    CHECK(source.find("thread_local std::shared_ptr") == std::string::npos);
    CHECK(source.find(
                  "thread_local QbdiThreadSession *g_current_qbdi_thread_session") !=
          std::string::npos);

    const size_t try_enter = source.find("bool QbdiThreadSession::try_enter()");
    const size_t owner_lock = source.find(
            "active_capture_owner_ = capture_owner_.lock();", try_enter);
    const size_t raw_publish = source.find(
            "g_current_qbdi_thread_session = this;", try_enter);
    CHECK(try_enter != std::string::npos);
    CHECK(owner_lock != std::string::npos);
    CHECK(raw_publish != std::string::npos);
    CHECK(owner_lock < raw_publish);

    const size_t current_owner = source.find(
            "std::shared_ptr<CaptureCoordinator> current_capture_coordinator()");
    const size_t safe_copy = source.find(
            "g_current_qbdi_thread_session->active_capture_owner_", current_owner);
    CHECK(current_owner != std::string::npos);
    CHECK(safe_copy != std::string::npos);

    for (const char *function : {"QbdiThreadSession::~QbdiThreadSession()",
                                 "void QbdiThreadSession::leave()"}) {
        const size_t start = source.find(function);
        const size_t clear = source.find(
                "g_current_qbdi_thread_session = nullptr;", start);
        const size_t reset = source.find("active_capture_owner_.reset();", start);
        CHECK(start != std::string::npos);
        CHECK(clear != std::string::npos);
        CHECK(reset != std::string::npos);
        CHECK(clear < reset);
    }

    const size_t destructor = source.find("QbdiThreadSession::~QbdiThreadSession()");
    const size_t detached = source.find("if (trace_process_child_detached())", destructor);
    const size_t detached_return = source.find("return;", detached);
    const size_t destructor_clear = source.find(
            "g_current_qbdi_thread_session = nullptr;", destructor);
    CHECK(destructor != std::string::npos);
    CHECK(detached != std::string::npos);
    CHECK(detached_return != std::string::npos);
    CHECK(destructor_clear < detached);
    CHECK(source.find("new (&capture_owner_) std::weak_ptr<CaptureCoordinator>()",
                      detached) < detached_return);
    CHECK(source.find(
                  "new (&active_capture_owner_) std::shared_ptr<CaptureCoordinator>()",
                  detached) < detached_return);

    const size_t leave = source.find("void QbdiThreadSession::leave()");
    const size_t leave_detached = source.find(
            "if (trace_process_child_detached()) return;", leave);
    const size_t leave_clear = source.find(
            "g_current_qbdi_thread_session = nullptr;", leave);
    CHECK(leave_clear < leave_detached);

    CHECK(header.find("bool capture_owner_required_ = false;") !=
          std::string::npos);
    CHECK(source.find("capture_owner_required_ = !owner.expired();") !=
          std::string::npos);
    CHECK(source.find("capture_owner_required_ && active_capture_owner_ == nullptr",
                      try_enter) < raw_publish);
}

void qbdi_thread_session_object_has_no_tls_destructor_registration() {
    const std::filesystem::path build_root(QTRACE_HOST_BUILD_DIR);
    std::filesystem::path object;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(build_root / "CMakeFiles")) {
        if (!entry.is_regular_file() ||
            entry.path().filename() != "qbdi_thread_session.cpp.o" ||
            entry.path().string().find("qbdi_thread_session_test.dir") ==
                    std::string::npos) {
            continue;
        }
        CHECK(object.empty());
        object = entry.path();
    }
    CHECK(!object.empty());
    const std::string undefined =
            read_command("nm -u \"" + object.string() + "\"");
    CHECK(undefined.find("__cxa_thread_atexit") == std::string::npos);
}

void signal_virtualization_is_scoped_to_each_vm_run_epoch() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string source =
            read_file(root / "core" / "qbdi_thread_session.cpp");

    const size_t call = source.find(
            "TraceRunResult call(uintptr_t logical_entry");
    const size_t call_activate = source.find(
            "signal_execution.activate(gpr)", call);
    const size_t call_run = source.find(
            "vm.run(execution_entry, kReturnAddress)", call_activate);
    const size_t call_clear = source.find(
            "signal_execution.clear()", call_run);
    CHECK(call != std::string::npos);
    CHECK(call_activate != std::string::npos);
    CHECK(call_run != std::string::npos);
    CHECK(call_clear != std::string::npos);
    CHECK(call < call_activate && call_activate < call_run &&
          call_run < call_clear);

    const size_t continuation = source.find(
            "TraceRunResult continue_control_only()", call_clear);
    const size_t continuation_activate = source.find(
            "signal_execution.activate(gpr)", continuation);
    const size_t continuation_run = source.find(
            "vm.run(continuation, kReturnAddress)", continuation_activate);
    const size_t continuation_clear = source.find(
            "signal_execution.clear()", continuation_run);
    CHECK(continuation != std::string::npos);
    CHECK(continuation_activate != std::string::npos);
    CHECK(continuation_run != std::string::npos);
    CHECK(continuation_clear != std::string::npos);
    CHECK(continuation < continuation_activate &&
          continuation_activate < continuation_run &&
          continuation_run < continuation_clear);
}

void final_sentinel_postinst_clears_before_vm_run_returns() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string source =
            read_file(root / "core" / "qbdi_thread_session.cpp");
    const size_t post = source.find("static QBDI::VMAction on_target_post(");
    const size_t clear = source.find(
            "observe_qbdi_vm_target_post(self->signal_execution, gpr", post);
    const size_t next_function = source.find(
            "uint32_t add_target_code_callbacks", post);
    CHECK(post != std::string::npos);
    CHECK(clear != std::string::npos);
    CHECK(next_function != std::string::npos);
    CHECK(post < clear && clear < next_function);
}

} // namespace

int main() {
    production_sources_have_only_the_binary_trace_facade();
    instruction_event_model_has_no_text_hot_fields();
    pending_instruction_reuse_does_not_clear_the_whole_hot_record();
    android_debug_compression_is_not_built_unoptimized();
    flight_register_sync_follows_simulated_call_setup();
    active_qbdi_tls_is_trivial_and_the_session_owns_its_coordinator();
    qbdi_thread_session_object_has_no_tls_destructor_registration();
    signal_virtualization_is_scoped_to_each_vm_run_epoch();
    final_sentinel_postinst_clears_before_vm_run_returns();
}
