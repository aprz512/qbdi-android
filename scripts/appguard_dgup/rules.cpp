// This opt-in tracer build is only for the version-checked DIGIMON UP sample.
#include "rules/code_rule.h"
#include "core/logging.h"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

namespace {
bool identified_engine(CodeRuleContext &context) {
    unsigned char magic[8]{};
    const unsigned char expected[] = {0x03, 0x25, 0x64, 0, 0, 0, 0, 0};
    return context.read_memory(context.module_base(), magic, sizeof(magic)) &&
           memcmp(magic, expected, sizeof(magic)) == 0;
}

class AppGuardReport final : public OffsetCodeRule {
public:
    AppGuardReport() : OffsetCodeRule(0x146c88) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        if (!identified_engine(context)) return QBDI::CONTINUE;
        const auto type = static_cast<uint32_t>(context.arg(2));
        const auto code = static_cast<uint32_t>(context.arg(3));
        const uint64_t length = context.arg(5);
        unsigned char data[512]{};
        size_t captured = length < sizeof(data) ? length : sizeof(data);
        if (captured && !context.read_memory(context.arg(4), data, captured)) captured = 0;
        char hex[sizeof(data) * 2 + 1]{};
        for (size_t i = 0; i < captured; ++i) snprintf(hex + i * 2, 3, "%02x", data[i]);
        const std::string detail = "type=" + std::to_string(type) + " code=" +
            std::to_string(code) + " size=" + std::to_string(length) + " hex=" + hex;
        context.trace_rule("appguard-report", detail);
        QTRACE_I("appguard-report %s", detail.c_str());
        if (type == 2 && (code == 34 || code == 38)) {
            context.trace_rule("appguard-policy", "block code=" + std::to_string(code) + " return=1");
            context.set_return_value(1);
            context.set_pc(context.lr());
            return QBDI::BREAK_TO_VM;
        }
        return QBDI::CONTINUE;
    }
};

class AppGuardTermination final : public OffsetCodeRule {
public:
    AppGuardTermination() : OffsetCodeRule(0xc6114) {}

    QBDI::VMAction on_pre_instruction(CodeRuleContext &context) override {
        if (!identified_engine(context)) return QBDI::CONTINUE;
        context.trace_rule("appguard-termination", "blocked delayed native worker +0xc6114 return=0");
        QTRACE_I("blocked AppGuard delayed native termination worker +0xc6114 via QBDI");
        context.set_return_value(0);
        context.set_pc(context.lr());
        return QBDI::BREAK_TO_VM;
    }
};
} // namespace

void register_user_code_rules(CodeRuleEngine &engine) {
    engine.add(std::make_unique<AppGuardReport>());
    engine.add(std::make_unique<AppGuardTermination>());
}
