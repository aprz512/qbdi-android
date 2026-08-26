#include <cstdio>
#include <cstdlib>
#include <array>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <string_view>

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

size_t occurrence_count(std::string_view source, std::string_view needle) {
    size_t count = 0;
    size_t offset = 0;
    while ((offset = source.find(needle, offset)) != std::string_view::npos) {
        ++count;
        offset += needle.size();
    }
    return count;
}

std::string_view function_source(std::string_view source,
                                 std::string_view signature) {
    const size_t start = source.find(signature);
    CHECK(start != std::string_view::npos);
    const size_t opening = source.find('{', start + signature.size());
    CHECK(opening != std::string_view::npos);
    size_t depth = 0;
    char quote = '\0';
    bool escaped = false;
    bool line_comment = false;
    bool block_comment = false;
    for (size_t index = opening; index < source.size(); ++index) {
        const char current = source[index];
        const char next = index + 1 < source.size() ? source[index + 1] : '\0';
        if (line_comment) {
            if (current == '\n') line_comment = false;
            continue;
        }
        if (block_comment) {
            if (current == '*' && next == '/') {
                block_comment = false;
                ++index;
            }
            continue;
        }
        if (quote != '\0') {
            if (escaped) {
                escaped = false;
            } else if (current == '\\') {
                escaped = true;
            } else if (current == quote) {
                quote = '\0';
            }
            continue;
        }
        if (current == '/' && next == '/') {
            line_comment = true;
            ++index;
            continue;
        }
        if (current == '/' && next == '*') {
            block_comment = true;
            ++index;
            continue;
        }
        if (current == '"' || current == '\'') {
            quote = current;
            continue;
        }
        if (current == '{') {
            ++depth;
        } else if (current == '}' && --depth == 0) {
            return source.substr(start, index - start + 1);
        }
    }
    CHECK(false);
    return {};
}

void function_source_ignores_non_code_braces() {
    constexpr std::string_view source = R"cpp(
void selected() {
    const char *text = "}";
    const char brace = '{';
    // }
    /* { } */
    if (true) { return; }
}
void next() {}
)cpp";
    const std::string_view selected = function_source(source, "void selected()");
    CHECK(selected.find("if (true) { return; }") != std::string_view::npos);
    CHECK(selected.find("void next()") == std::string_view::npos);
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

void accepted_generation_owns_one_runtime_and_private_status_publisher() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string tracer_entry = read_file(root / "tracer_entry.cpp");
    const std::string runtime_header =
            read_file(root / "core" / "trace_generation_runtime.h");
    const std::string status = read_file(root / "core" / "session_status.cpp");
    const std::string_view apply = function_source(
            tracer_entry, "static void apply_accepted_configuration(");

    CHECK(occurrence_count(
                  tracer_entry,
                  "static std::shared_ptr<TraceGenerationRuntime> "
                  "g_generation_runtime;") == 1);
    CHECK(occurrence_count(
                  apply, "create_generation_runtime(config, generation)") == 1);
    CHECK(apply.find("g_generation_runtime = std::move(runtime);") !=
          std::string_view::npos);
    CHECK(runtime_header.find("SessionStatusPublisher status_publisher_;") !=
          std::string::npos);
    CHECK(status.find("/data/data/%s/files/qbdi-traces") !=
          std::string::npos);
}

void proxy_admission_precedes_qbdi_and_stop_completes_control_only() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::string tracer_entry = read_file(root / "tracer_entry.cpp");
    const std::string session =
            read_file(root / "core" / "qbdi_thread_session.cpp");
    const std::string_view proxy = function_source(
            tracer_entry, "extern \"C\" uint64_t trace_proxy_dispatch(");
    const size_t admission = proxy.find("->try_begin_call(");
    const size_t qbdi = proxy.find("run_with_qbdi(");
    CHECK(admission != std::string_view::npos);
    CHECK(qbdi != std::string_view::npos);
    CHECK(admission < qbdi);

    const std::string_view target_pre = function_source(
            session, "static QBDI::VMAction on_target_pre(");
    CHECK(target_pre.find("return QBDI::STOP;") != std::string_view::npos);
    const std::string_view call_gateway = function_source(
            session, "TraceRunResult QbdiThreadSession::call_gateway(");
    const size_t seal = call_gateway.find("seal_observed_stop(");
    const size_t continuation = call_gateway.find("continue_execution();");
    CHECK(seal != std::string_view::npos);
    CHECK(continuation != std::string_view::npos);
    CHECK(seal < continuation);
    CHECK(session.find(
                  "return impl_ != nullptr ? impl_->continue_control_only()") !=
          std::string::npos);
}

void deadline_worker_only_requests_stop_and_runtime_has_no_writer_dependency() {
    const std::filesystem::path root(QTRACE_CPP_SOURCE_DIR);
    const std::filesystem::path repo(QTRACE_REPO_DIR);
    const std::string runtime =
            read_file(root / "core" / "trace_generation_runtime.cpp");
    const std::string runtime_header =
            read_file(root / "core" / "trace_generation_runtime.h");
    const std::string tracer_entry = read_file(root / "tracer_entry.cpp");
    const std::string spawn_agent = read_file(repo / "scripts" / "spawn_trace.js");
    const std::string_view deadline = function_source(
            runtime, "void *TraceGenerationRuntime::deadline_entry(");

    CHECK(deadline.find("request_deadline_stop()") != std::string_view::npos);
    for (std::string_view forbidden_dependency : {
                 "events/binary_trace_writer.h", "events/trace_sink.h",
                 "BinaryTraceWriter", "TraceSink"}) {
        CHECK(runtime.find(forbidden_dependency) == std::string_view::npos);
        CHECK(runtime_header.find(forbidden_dependency) == std::string_view::npos);
    }
    for (std::string_view forbidden_operation : {
                 "writer_", ".stop(", "->stop(", ".close(", "->close(",
                 "seal_observed_stop("}) {
        CHECK(runtime.find(forbidden_operation) == std::string_view::npos);
        CHECK(runtime_header.find(forbidden_operation) == std::string_view::npos);
    }
    CHECK(tracer_entry.find("qbdi_tracer_stop_json") == std::string::npos);
    CHECK(tracer_entry.find("qbdi_tracer_stop") == std::string::npos);
    CHECK(spawn_agent.find("rpc.exports.stop") == std::string::npos);
}

} // namespace

int main() {
    function_source_ignores_non_code_braces();
    production_sources_have_only_the_binary_trace_facade();
    instruction_event_model_has_no_text_hot_fields();
    pending_instruction_reuse_does_not_clear_the_whole_hot_record();
    android_debug_compression_is_not_built_unoptimized();
    flight_register_sync_follows_simulated_call_setup();
    active_qbdi_tls_is_trivial_and_the_session_owns_its_coordinator();
    qbdi_thread_session_object_has_no_tls_destructor_registration();
    signal_virtualization_is_scoped_to_each_vm_run_epoch();
    final_sentinel_postinst_clears_before_vm_run_returns();
    accepted_generation_owns_one_runtime_and_private_status_publisher();
    proxy_admission_precedes_qbdi_and_stop_completes_control_only();
    deadline_worker_only_requests_stop_and_runtime_has_no_writer_dependency();
}
