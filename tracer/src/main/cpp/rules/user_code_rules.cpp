#include "rules/code_rule.h"

// Default analysis does not modify target registers or memory. Select an
// identity-bound custom rules source explicitly to enable sample policies.
void register_user_code_rules(CodeRuleEngine &) {}
