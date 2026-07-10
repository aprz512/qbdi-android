#include "rules/code_rule.h"

#include <QBDI.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <memory>

namespace {
constexpr uintptr_t kDisabledOffset = UINTPTR_MAX;
constexpr uintptr_t kSetEqualsFlagOffset = kDisabledOffset;
constexpr uintptr_t kSetArgOffset = kDisabledOffset;
constexpr uintptr_t kForceReturnOffset = kDisabledOffset;
constexpr uintptr_t kJumpOffset = kDisabledOffset;

class SetEqualsFlagAtOffsetRule final : public OffsetCodeRule {
public:
    SetEqualsFlagAtOffsetRule(uintptr_t offset, bool equals) : OffsetCodeRule(offset), equals_(equals) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        context.set_zero_flag(equals_);
        char detail[96];
        snprintf(detail, sizeof(detail), "offset=0x%" PRIxPTR " z=%d", context.offset(), equals_ ? 1 : 0);
        context.trace_rule("set_equals_flag", detail);
        return QBDI::CONTINUE;
    }

private:
    bool equals_ = true;
};

class SetArgAtOffsetRule final : public OffsetCodeRule {
public:
    SetArgAtOffsetRule(uintptr_t offset, size_t index, uint64_t value)
        : OffsetCodeRule(offset), index_(index), value_(value) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        context.set_arg(index_, value_);
        char detail[128];
        snprintf(detail, sizeof(detail), "offset=0x%" PRIxPTR " x%zu=0x%" PRIx64, context.offset(), index_, value_);
        context.trace_rule("set_arg", detail);
        return QBDI::CONTINUE;
    }

private:
    size_t index_ = 0;
    uint64_t value_ = 0;
};

class ForceReturnAtOffsetRule final : public OffsetCodeRule {
public:
    ForceReturnAtOffsetRule(uintptr_t offset, uint64_t value) : OffsetCodeRule(offset), value_(value) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        context.set_return_value(value_);
        context.set_pc(context.lr());
        char detail[128];
        snprintf(detail, sizeof(detail), "offset=0x%" PRIxPTR " ret=0x%" PRIx64, context.offset(), value_);
        context.trace_rule("force_return", detail);
        return QBDI::BREAK_TO_VM;
    }

private:
    uint64_t value_ = 0;
};

class JumpAtOffsetRule final : public OffsetCodeRule {
public:
    JumpAtOffsetRule(uintptr_t offset, uintptr_t target_offset) : OffsetCodeRule(offset), target_offset_(target_offset) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        context.set_pc(context.absolute(target_offset_));
        char detail[128];
        snprintf(detail, sizeof(detail), "offset=0x%" PRIxPTR " target=0x%" PRIxPTR,
                 context.offset(), target_offset_);
        context.trace_rule("jump", detail);
        return QBDI::BREAK_TO_VM;
    }

private:
    uintptr_t target_offset_ = 0;
};
}

void register_user_code_rules(CodeRuleEngine &engine) {
    if (kSetEqualsFlagOffset != kDisabledOffset) {
        engine.add(std::make_unique<SetEqualsFlagAtOffsetRule>(kSetEqualsFlagOffset, true));
    }
    if (kSetArgOffset != kDisabledOffset) {
        engine.add(std::make_unique<SetArgAtOffsetRule>(kSetArgOffset, 0, 0));
    }
    if (kForceReturnOffset != kDisabledOffset) {
        engine.add(std::make_unique<ForceReturnAtOffsetRule>(kForceReturnOffset, 0));
    }
    if (kJumpOffset != kDisabledOffset) {
        engine.add(std::make_unique<JumpAtOffsetRule>(kJumpOffset, 0));
    }
}
