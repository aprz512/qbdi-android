#include "rules/code_rule.h"

#include <cassert>
#include <memory>

bool CodeRuleContext::at_offset(uintptr_t) const {
    return false;
}

namespace {

class ImmediatePostRule final : public CodeRule {
public:
    bool matches(const CodeRuleContext &) const override { return false; }

    bool requires_immediate_post() const override { return true; }
};

class PreOnlyRule final : public CodeRule {
public:
    bool matches(const CodeRuleContext &) const override { return false; }
};

} // namespace

int main() {
    CodeRuleEngine engine;
    assert(!engine.requires_immediate_post());

    engine.add(std::make_unique<PreOnlyRule>());
    assert(!engine.requires_immediate_post());

    engine.add(std::make_unique<ImmediatePostRule>());
    assert(engine.requires_immediate_post());
}
