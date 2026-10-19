#include "rules/code_rule.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort(); } } while (false)

int main() {
    CodeRuleEngine engine;
    register_user_code_rules(engine);
    TraceContext trace;
    trace.module_base = 0x100000;
    QBDI::GPRState gpr{}, before{};
    QBDI::FPRState fpr{};
    InstructionView instruction;
    CodeRuleContext context(nullptr, &gpr, &fpr, &instruction, &trace, nullptr);
    for (uintptr_t offset : {0x6E8A4, 0x6E5C0}) {
        instruction.address = trace.module_base + offset;
        gpr.pc = instruction.address;
        before = gpr;
        CHECK(engine.on_pre_instruction(context) == QBDI::CONTINUE);
        CHECK(engine.on_post_instruction(context) == QBDI::CONTINUE);
        CHECK(std::memcmp(&gpr, &before, sizeof(gpr)) == 0);
    }
}
