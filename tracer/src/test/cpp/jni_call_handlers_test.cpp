#include "handlers/call_handlers.h"
#include "jni/jni_function_table.h"
#include "jni/jni_state.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <tuple>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #expression); std::abort(); \
} } while (false)

namespace {
struct Sink : TraceSink {
    std::vector<std::tuple<std::string, std::string, std::string>> calls;
    bool instruction(const TraceContext &, const InstructionRecord &) override { return true; }
    bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) override { return true; }
    bool call(const char *category, std::string_view name, std::string_view detail) override {
        calls.emplace_back(category, name, detail); return true;
    }
    bool rule(const std::string &, const std::string &) override { return true; }
    bool error(const std::string &) override { return true; }
    bool failed() const noexcept override { return false; }
};

struct Environment {
    std::vector<uintptr_t> table{0, 0, 0, 0};
    uintptr_t receiver;
    Environment() {
        for (const auto &entry : build_jni_function_table()) {
            if (std::string_view(entry.struct_name) == "JNIEnv") table.push_back(0x100000 + table.size() * 16);
        }
        receiver = reinterpret_cast<uintptr_t>(table.data());
    }
    uintptr_t address(const char *name) const {
        size_t slot = 4;
        for (const auto &entry : build_jni_function_table()) {
            if (std::string_view(entry.struct_name) != "JNIEnv") continue;
            if (std::string_view(entry.name) == name) return table[slot];
            ++slot;
        }
        std::abort();
    }
    QBDI::GPRState state(const char *name, uintptr_t argument = 0) {
        QBDI::GPRState gpr{};
        gpr.x0 = reinterpret_cast<uintptr_t>(&receiver);
        gpr.x1 = argument;
        gpr.pc = address(name);
        return gpr;
    }
};

void event(ExecTransferMonitor &monitor, Sink &sink, QBDI::GPRState &gpr,
           QBDI::VMEvent kind, const QBDI::FPRState *fpr = nullptr) {
    QBDI::VMState state{};
    state.event = kind;
    emit_exec_transfer_event(&monitor, &state, &gpr, &sink, fpr);
}

void nested_jni_calls_keep_distinct_snapshots_and_state_updates() {
    Environment env;
    ExecTransferMonitor monitor;
    Sink sink;
    auto outer = env.state("NewStringUTF", reinterpret_cast<uintptr_t>("outer-text"));
    event(monitor, sink, outer, QBDI::EXEC_TRANSFER_CALL);
    auto inner = env.state("FindClass", reinterpret_cast<uintptr_t>("probe/Inner"));
    event(monitor, sink, inner, QBDI::EXEC_TRANSFER_CALL);
    inner.x0 = 0x7777;
    event(monitor, sink, inner, QBDI::EXEC_TRANSFER_RETURN);
    outer.x0 = 0x8888;
    event(monitor, sink, outer, QBDI::EXEC_TRANSFER_RETURN);
    CHECK(sink.calls.size() == 4);
    CHECK(std::get<1>(sink.calls[2]) == "FindClass");
    CHECK(std::get<1>(sink.calls[3]) == "NewStringUTF");
    CHECK(jni_state().class_name(0x7777) == "probe/Inner");
    CHECK(jni_state().string_value(0x8888) == "outer-text");
    CHECK(monitor.pending.empty());
}

void unrecognized_nested_transfers_do_not_consume_a_jni_return() {
    Environment env;
    ExecTransferMonitor monitor;
    Sink sink;
    auto outer = env.state("NewStringUTF", reinterpret_cast<uintptr_t>("retained-text"));
    event(monitor, sink, outer, QBDI::EXEC_TRANSFER_CALL);
    QBDI::GPRState unknown{};
    unknown.pc = 0xdeadbeef;
    event(monitor, sink, unknown, QBDI::EXEC_TRANSFER_CALL);
    event(monitor, sink, unknown, QBDI::EXEC_TRANSFER_RETURN);
    CHECK(sink.calls.size() == 1);
    outer.x0 = 0x9999;
    event(monitor, sink, outer, QBDI::EXEC_TRANSFER_RETURN);
    CHECK(sink.calls.size() == 2);
    CHECK(jni_state().string_value(0x9999) == "retained-text");
}

void capture_uses_fp_arguments_and_fp_returns_without_modifying_cpu_state() {
    Environment env;
    ExecTransferMonitor monitor;
    Sink sink;
    jni_state().on_get_static_method_id(0xabc1234, "value", "(D)D");
    auto gpr = env.state("CallStaticDoubleMethod", 0x1234);
    gpr.x2 = 0xabc1234;
    QBDI::FPRState fpr{};
    const double argument = -2.5;
    std::memcpy(&fpr.v0, &argument, 8);
    const auto original = gpr;
    event(monitor, sink, gpr, QBDI::EXEC_TRANSFER_CALL, &fpr);
    CHECK(std::memcmp(&gpr, &original, sizeof(gpr)) == 0);
    CHECK(std::get<2>(sink.calls.back()).find("(-2.5)") != std::string::npos);
    const double returned = -3.25;
    std::memcpy(&fpr.v0, &returned, 8);
    gpr.x0 = 0xdeadbeef;
    event(monitor, sink, gpr, QBDI::EXEC_TRANSFER_RETURN, &fpr);
    CHECK(std::get<2>(sink.calls.back()).find("(-3.25)") != std::string::npos);
    CHECK(gpr.x0 == 0xdeadbeef);
}
} // namespace

int main() {
    nested_jni_calls_keep_distinct_snapshots_and_state_updates();
    unrecognized_nested_transfers_do_not_consume_a_jni_return();
    capture_uses_fp_arguments_and_fp_returns_without_modifying_cpu_state();
}
