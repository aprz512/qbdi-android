#include "core/instruction_collector.h"
#include "core/instruction_cache.h"
#include "core/trace_callback_gate.h"
#include "events/binary_trace_format.h"
#include "events/binary_trace_writer.h"
#include "events/trace_sink.h"
#include "rules/code_rule.h"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

class StopPostRule final : public CodeRule {
public:
    bool matches(const CodeRuleContext &) const override { return true; }

    QBDI::VMAction on_post_instruction(CodeRuleContext &) override {
        ++calls;
        return QBDI::STOP;
    }

    unsigned int calls = 0;
};

class RecordingSink final : public TraceSink {
public:
    bool instruction(const TraceContext &, const InstructionRecord &) override {
        ++count;
        return true;
    }

    bool instruction(const TraceContext &, const InstructionRecord &,
                     const RegisterSnapshot &post_registers) noexcept override {
        ++count;
        last_post_registers = post_registers;
        return true;
    }

    bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) override { return true; }
    bool call(const char *, std::string_view, std::string_view) override { return true; }
    bool rule(const std::string &, const std::string &) override { return true; }
    bool error(const std::string &) override { return true; }
    bool failed() const noexcept override { return false; }

    size_t count = 0;
    RegisterSnapshot last_post_registers{};
};

void completed_pending_instruction_is_emitted_to_injected_sink() {
    TraceOptions options{};
    TraceContext trace{};
    trace.module_base = 0x1000;
    ModuleRange module{};
    module.start = 0x1000;
    module.end = 0x2000;
    InstructionCache cache;
    RecordingSink sink;
    InstructionCollector collector(&cache, &sink, nullptr, &trace, nullptr, options, module);
    PendingInstructionCollector pending(&collector, trace.module_base);

    CHECK(pending.begin({0x1010, nullptr}, {}));
    CHECK(pending.finish_last({}));

    CHECK(sink.count == 1);
}

void completion_forwards_the_complete_post_instruction_registers() {
    TraceOptions options{};
    TraceContext trace{};
    trace.module_base = 0x1000;
    ModuleRange module{};
    module.start = 0x1000;
    module.end = 0x2000;
    InstructionCache cache;
    RecordingSink sink;
    InstructionCollector collector(&cache, &sink, nullptr, &trace, nullptr, options, module);
    PendingInstructionCollector pending(&collector, trace.module_base);
    CHECK(pending.begin({0x1010, nullptr}, {}));
    RegisterSnapshot after{};
    after.values[19] = 0x1919;
    after.values[32] = 0xf0000000;
    after.values[33] = 0x1080;
    CHECK(pending.finish_last(after));

    CHECK(sink.count == 1);
    CHECK(sink.last_post_registers.values[19] == 0x1919);
    CHECK(sink.last_post_registers.values[32] == 0xf0000000);
    CHECK(sink.last_post_registers.values[33] == 0x1080);
}

void latched_writer_blocks_collector_trace_work_but_preserves_rule_action() {
    char directory_template[] = "/tmp/qtrace-collector-XXXXXX";
    char *directory = ::mkdtemp(directory_template);
    CHECK(directory != nullptr);

    TraceOptions options{};
    options.compression_enabled = false;
    options.auto_buffer_size = false;
    options.buffer_bytes = 8192;
    TraceMetrics metrics{};
    BinaryTraceWriter writer(options, &metrics);
    TraceContext trace{};
    trace.output_directory = directory;
    trace.scene_name = "collector";
    trace.target_so = "libtarget.so";
    trace.module_base = 0x1000;
    trace.target_address = 0x1010;
    trace.pid = 1;
    trace.tid = 2;
    CHECK(writer.open(trace));
    CHECK(writer.begin(trace));

    InstructionCache cache;
    TraceCallbackGate gate;
    CodeRuleEngine rules;
    auto rule = std::make_unique<StopPostRule>();
    StopPostRule *rule_observer = rule.get();
    rules.add(std::move(rule));
    ModuleRange module{};
    module.start = 0x1000;
    module.end = 0x2000;
    InstructionCollector collector(&cache, &writer, &rules, &trace, &gate, options, module);

    CHECK(!writer.error(std::string(kBinaryMaxEventDetailBytes + 1U, 'x')));
    CHECK(writer.failed());
    const uint64_t encoded_before = metrics.encoded_bytes;
    CHECK(collector.on_post(nullptr, nullptr, nullptr) == QBDI::STOP);
    CHECK(rule_observer->calls == 1);
    CHECK(!gate.enabled());
    CHECK(metrics.encoded_bytes == encoded_before);
    CHECK(collector.on_post(nullptr, nullptr, nullptr) == QBDI::STOP);
    CHECK(rule_observer->calls == 2);
    CHECK(metrics.encoded_bytes == encoded_before);
    CHECK(!writer.close());

    const std::string artifact(writer.path());
    CHECK(::unlink(artifact.c_str()) == 0);
    CHECK(::rmdir(directory) == 0);
}

} // namespace

int main() {
    completed_pending_instruction_is_emitted_to_injected_sink();
    completion_forwards_the_complete_post_instruction_registers();
    latched_writer_blocks_collector_trace_work_but_preserves_rule_action();
}
