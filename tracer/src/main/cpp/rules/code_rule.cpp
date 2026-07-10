#include "rules/code_rule.h"

#include <utility>

QBDI::VMAction CodeRule::on_pre_instruction(CodeRuleContext &) {
    return QBDI::CONTINUE;
}

QBDI::VMAction CodeRule::on_post_instruction(CodeRuleContext &) {
    return QBDI::CONTINUE;
}

OffsetCodeRule::OffsetCodeRule(uintptr_t offset) : offset_(offset) {}

bool OffsetCodeRule::matches(const CodeRuleContext &context) const {
    return context.at_offset(offset_);
}

void CodeRuleEngine::add(std::unique_ptr<CodeRule> rule) {
    if (rule != nullptr) rules_.push_back(std::move(rule));
}

QBDI::VMAction CodeRuleEngine::on_pre_instruction(CodeRuleContext &context) {
    for (const auto &rule : rules_) {
        if (!rule->matches(context)) continue;
        QBDI::VMAction action = rule->on_pre_instruction(context);
        if (action != QBDI::CONTINUE) return action;
    }
    return QBDI::CONTINUE;
}

QBDI::VMAction CodeRuleEngine::on_post_instruction(CodeRuleContext &context) {
    for (const auto &rule : rules_) {
        if (!rule->matches(context)) continue;
        QBDI::VMAction action = rule->on_post_instruction(context);
        if (action != QBDI::CONTINUE) return action;
    }
    return QBDI::CONTINUE;
}
