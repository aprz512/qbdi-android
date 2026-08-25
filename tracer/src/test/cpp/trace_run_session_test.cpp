#include "core/trace_run_session.h"
#include "core/qbdi_runner_lifecycle.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

std::string temporary_directory() {
    char path[] = "/tmp/qtrace-session-XXXXXX";
    char *created = ::mkdtemp(path);
    CHECK(created != nullptr);
    return created;
}

TraceContext context_for(const std::string &directory) {
    TraceContext context{};
    context.output_directory = directory;
    context.scene_name = "session";
    context.target_so = "libtarget.so";
    context.module_base = 0x1000;
    context.target_offset = 0x20;
    context.target_address = 0x1020;
    context.pid = 1;
    context.tid = 2;
    return context;
}

TraceOptions options() {
    TraceOptions selected{};
    selected.compression_enabled = false;
    selected.auto_buffer_size = false;
    selected.buffer_bytes = 4096;
    return selected;
}

std::vector<uint8_t> read_bytes(std::string_view path) {
    const std::string owned(path);
    const int fd = ::open(owned.c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    std::vector<uint8_t> bytes;
    uint8_t buffer[4096];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        CHECK(count >= 0);
        if (count == 0) break;
        bytes.insert(bytes.end(), buffer, buffer + count);
    }
    CHECK(::close(fd) == 0);
    return bytes;
}

uint64_t u64(const std::vector<uint8_t> &bytes, size_t offset) {
    uint64_t value = 0;
    for (size_t byte = 0; byte < 8; ++byte)
        value |= static_cast<uint64_t>(bytes[offset + byte]) << (byte * 8U);
    return value;
}

void remove_artifact(const BinaryTraceWriter &writer, const std::string &directory,
                     bool has_metrics) {
    const std::string path(writer.path());
    if (has_metrics) CHECK(::unlink((path + ".metrics").c_str()) == 0);
    CHECK(::unlink(path.c_str()) == 0);
    CHECK(::rmdir(directory.c_str()) == 0);
}

void early_execution_setup_failure_finalizes_one_failed_binary_run() {
    const std::string directory = temporary_directory();
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options(), &metrics);
    const TraceContext context = context_for(directory);
    TraceRunSessionOutcome session;
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(false);
    CHECK(!session.target_should_run());
    session.observe_target_call({false, false, 99}, writer.failed());

    const TraceRunFinalization finalization = session.finalize(writer, 4);
    CHECK(!finalization.target_ran);
    CHECK(finalization.outward_return_value == 0);
    CHECK(!finalization.footer_success);
    CHECK(!finalization.completion_success);
    const std::vector<uint8_t> bytes = read_bytes(writer.path());
    CHECK(bytes.size() >= kBinaryStreamHeaderBytes);
    remove_artifact(writer, directory, false);
}

void callback_registration_failure_blocks_execution_and_success_metrics() {
    struct RegistrationState {
        unsigned int calls = 0;
        unsigned int failing_call = 0;
    };
    const auto registrar = [](void *opaque) noexcept -> uint32_t {
        auto *state = static_cast<RegistrationState *>(opaque);
        ++state->calls;
        return state->calls == state->failing_call ? 0xffffffffU : state->calls;
    };
    for (unsigned int failing_call = 1; failing_call <= 3; ++failing_call) {
        const std::string directory = temporary_directory();
        TraceMetrics metrics{};
        BinaryTraceWriter writer(options(), &metrics);
        const TraceContext context = context_for(directory);
        TraceRunSessionOutcome session;
        CHECK(writer.open(context));
        CHECK(writer.begin(context));
        session.observe_trace_setup(true);
        session.observe_execution_setup(true);
        RegistrationState registration{0, failing_call};
        const QbdiCallbackRegistration callbacks{
                &registration, registrar, registrar, registrar, 0xffffffffU, true};
        session.observe_execution_setup(register_qbdi_callbacks(callbacks));
        CHECK(registration.calls == 3);
        CHECK(!session.target_should_run());
        unsigned int target_calls = 0;
        if (session.target_should_run()) ++target_calls;
        CHECK(target_calls == 0);
        session.observe_target_call({false, false, 73}, writer.failed());
        const TraceRunFinalization finalization = session.finalize(writer, 5);
        CHECK(!finalization.target_ran);
        CHECK(finalization.outward_return_value == 0);
        CHECK(!finalization.footer_success);
        CHECK(!finalization.completion_success);
        CHECK(metrics.instructions == 0);
        remove_artifact(writer, directory, false);
    }
}

void memory_instrumentation_failure_blocks_execution_and_success_metrics() {
    const std::string directory = temporary_directory();
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options(), &metrics);
    const TraceContext context = context_for(directory);
    TraceRunSessionOutcome session;
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(true);
    session.observe_memory_instrumentation(true, false, false);
    CHECK(!session.target_should_run());
    session.observe_target_call({false, false, 73}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 5);
    CHECK(!finalization.target_ran);
    CHECK(!finalization.footer_success);
    CHECK(!finalization.completion_success);
    CHECK(metrics.instructions == 0);
    remove_artifact(writer, directory, false);
}

void successful_target_has_one_authoritative_return_and_metrics() {
    const std::string directory = temporary_directory();
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options(), &metrics);
    const TraceContext context = context_for(directory);
    TraceRunSessionOutcome session;
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(true);
    session.observe_memory_instrumentation(true, true, true);
    CHECK(session.target_should_run());
    session.observe_target_call({true, true, 91}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 6);
    CHECK(finalization.target_ran);
    CHECK(finalization.outward_return_value == 91);
    CHECK(finalization.footer_success);
    CHECK(finalization.completion_success);
    const std::vector<uint8_t> bytes = read_bytes(writer.path());
    const size_t footer = bytes.size() - kBinaryTraceEndRecordBytes;
    CHECK(bytes[footer + kBinaryRecordHeaderBytes] == 1);
    CHECK(u64(bytes, footer + kBinaryRecordHeaderBytes + 1) == 91);
    remove_artifact(writer, directory, true);
}

void writer_failure_after_execution_preserves_target_result() {
    const std::string directory = temporary_directory();
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options(), &metrics);
    const TraceContext context = context_for(directory);
    TraceRunSessionOutcome session;
    CHECK(writer.open(context));
    CHECK(writer.begin(context));
    session.observe_trace_setup(true);
    session.observe_execution_setup(true);
    CHECK(session.target_should_run());
    CHECK(!writer.error(std::string(kBinaryMaxEventDetailBytes + 1, 'x')));
    session.observe_target_call({true, true, 0xfeed}, writer.failed());
    const TraceRunFinalization finalization = session.finalize(writer, 7);
    CHECK(finalization.target_ran);
    CHECK(finalization.outward_return_value == 0xfeed);
    CHECK(!finalization.footer_success);
    CHECK(!finalization.completion_success);
    remove_artifact(writer, directory, false);
}

} // namespace

int main() {
    early_execution_setup_failure_finalizes_one_failed_binary_run();
    callback_registration_failure_blocks_execution_and_success_metrics();
    memory_instrumentation_failure_blocks_execution_and_success_metrics();
    successful_target_has_one_authoritative_return_and_metrics();
    writer_failure_after_execution_preserves_target_result();
}
