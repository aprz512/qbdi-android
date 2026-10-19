#include "rules/code_rule.h"
#include "core/qbdi_gateway_entry.h"
#include "events/trace_sink.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort(); } } while (false)

struct Sink final : TraceSink {
    std::vector<std::pair<std::string, std::string>> rules;
    bool instruction(const TraceContext &, const InstructionRecord &) override { return true; }
    bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) override { return true; }
    bool call(const char *, std::string_view, std::string_view) override { return true; }
    bool rule(const std::string &name, const std::string &detail) override {
        rules.emplace_back(name, detail); return true;
    }
    bool error(const std::string &) override { return true; }
    bool failed() const noexcept override { return false; }
};

int main() {
    unsigned char header[] = {3, 0x25, 0x64, 0, 0, 0, 0, 0};
    const char payload[] = "199:/product/bin/su";
    TraceContext trace;
    trace.module_base = reinterpret_cast<uintptr_t>(header);
    InstructionView instruction;
    instruction.address = trace.module_base + 0x146c88;
    QBDI::GPRState gpr{};
    QBDI::FPRState fpr{};
    Sink sink;
    CodeRuleContext context(nullptr, &gpr, &fpr, &instruction, &trace, &sink);
    CodeRuleEngine engine;
    register_user_code_rules(engine);
    for (auto code : {34, 38, 8, 50}) {
        gpr = {};
        gpr.x0 = 123;
        gpr.x2 = 2;
        gpr.x3 = code;
        gpr.x4 = reinterpret_cast<uintptr_t>(payload);
        gpr.x5 = sizeof(payload) - 1;
        gpr.sp = 0x8000;
        gpr.lr = 0x9000;
        gpr.pc = instruction.address;
        const uintptr_t trampoline = 0x12340000;
        const auto action = evaluate_qbdi_gateway_entry(engine, nullptr, &gpr, &fpr,
                                                       instruction.address, trampoline, &trace, &sink);
        const bool blocked = code == 34 || code == 38;
        CHECK(action == (blocked ? QBDI::BREAK_TO_VM : QBDI::CONTINUE));
        CHECK(gpr.x0 == (blocked ? 1 : 123));
        CHECK(gpr.pc == (blocked ? gpr.lr : trampoline));
        CHECK(gpr.sp == 0x8000);
        CHECK(sink.rules.front().second.find("3139393a2f70726f647563742f62696e2f7375") != std::string::npos);
        sink.rules.clear();
    }
    // A non-detection event, foreign module or different PC must pass through.
    gpr.x2 = 0;
    gpr.x3 = 34;
    CHECK(engine.on_pre_instruction(context) == QBDI::CONTINUE);
    gpr.x2 = 2;
    header[0] = 0;
    CHECK(engine.on_pre_instruction(context) == QBDI::CONTINUE);
    header[0] = 3;
    instruction.address += 4;
    CHECK(engine.on_pre_instruction(context) == QBDI::CONTINUE);
    instruction.address = trace.module_base + 0xc6114;
    gpr.x0 = 123;
    CHECK(engine.on_pre_instruction(context) == QBDI::BREAK_TO_VM);
    CHECK(gpr.x0 == 0 && gpr.pc == gpr.lr && gpr.sp == 0x8000);
}
