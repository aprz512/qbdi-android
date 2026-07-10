#include "rules/code_rule.h"

#include <QBDI.h>

#include <memory>

/*
 * User rules are intentionally empty by default.
 *
 * Add project-specific rules here and register them from register_user_code_rules().
 * Example:
 *
 * namespace {
 * class ForceEqualsRule final : public OffsetCodeRule {
 * public:
 *     explicit ForceEqualsRule(uintptr_t offset) : OffsetCodeRule(offset) {}
 *
 *     QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
 *         context.set_zero_flag(true);
 *         context.trace_rule("force_equals", "z=1");
 *         return QBDI::CONTINUE;
 *     }
 * };
 * }
 *
 * void register_user_code_rules(CodeRuleEngine &engine) {
 *     engine.add(std::make_unique<ForceEqualsRule>(0x1234));
 * }
 */




void register_user_code_rules(CodeRuleEngine &engine) {
    (void)engine;
}
