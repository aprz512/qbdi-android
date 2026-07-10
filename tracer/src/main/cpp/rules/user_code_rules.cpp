#include "rules/code_rule.h"

#include <QBDI.h>

#include <memory>

namespace {

// 6E8A4: TBNZ W8, #0, loc_6E8B4
// Set bit #0 of W8 so TBNZ takes the branch to loc_6E8B4
class ForceTbnzW8Rule final : public OffsetCodeRule {
public:
    explicit ForceTbnzW8Rule(uintptr_t offset) : OffsetCodeRule(offset) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        uint64_t w8 = context.reg(8);
        context.set_reg(8, w8 | 1ULL);
        context.trace_rule("force_tbnz", "W8 bit#0 set, jump to loc_6E8B4");
        return QBDI::CONTINUE;
    }
};

// 6E5C0: TBNZ W0, #0, loc_6E5D0
// Set bit #0 of W0 so TBNZ takes the branch to loc_6E5D0
class ForceTbnzW0Rule final : public OffsetCodeRule {
public:
    explicit ForceTbnzW0Rule(uintptr_t offset) : OffsetCodeRule(offset) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        uint64_t w0 = context.reg(0);
        context.set_reg(0, w0 | 1ULL);
        context.trace_rule("force_tbnz", "W0 bit#0 set, jump to loc_6E5D0");
        return QBDI::CONTINUE;
    }
};

} // namespace

void register_user_code_rules(CodeRuleEngine &engine) {
    engine.add(std::make_unique<ForceTbnzW8Rule>(0x6E8A4));
    engine.add(std::make_unique<ForceTbnzW0Rule>(0x6E5C0));
}
