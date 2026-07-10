# Integrity Checks and Code Rules

The integrity scene contains two checks:

1. `.text` hash validation for `integrity_text_check()` itself.
2. `/proc/self/maps` inspection for injected modules and suspicious mappings.

The JavaScript config now only provides scene offsets. It does not pre-enable bypass handlers.

Runtime behavior changes should be implemented as native CodeRules under `tracer/src/main/cpp/rules/user_code_rules.cpp`. CodeRules can match by module offset, then adjust registers, arguments, return values, PC, flags, or memory through `CodeRuleContext`.
