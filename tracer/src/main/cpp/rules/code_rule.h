#pragma once

#include "rules/code_rule_context.h"

#include <QBDI.h>

#include <cstdint>
#include <memory>
#include <vector>

class CodeRule {
public:
    virtual ~CodeRule() = default;
    virtual bool matches(const CodeRuleContext &context) const = 0;
    virtual QBDI::VMAction on_pre_instruction(CodeRuleContext &context);
    virtual QBDI::VMAction on_post_instruction(CodeRuleContext &context);
};

class OffsetCodeRule : public CodeRule {
public:
    explicit OffsetCodeRule(uintptr_t offset);
    bool matches(const CodeRuleContext &context) const override;
    uintptr_t offset() const { return offset_; }

private:
    uintptr_t offset_ = 0;
};

class CodeRuleEngine {
public:
    void add(std::unique_ptr<CodeRule> rule);
    QBDI::VMAction on_pre_instruction(CodeRuleContext &context);
    QBDI::VMAction on_post_instruction(CodeRuleContext &context);

private:
    std::vector<std::unique_ptr<CodeRule>> rules_;
};

void register_user_code_rules(CodeRuleEngine &engine);
