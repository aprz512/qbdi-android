# Integrity Checks and Code Rules

The integrity scene contains two checks:

1. `.text` hash validation for `integrity_text_check()` itself.
2. `/proc/self/maps` inspection for injected modules and suspicious mappings.

The JavaScript config now only provides scene offsets. It does not pre-enable bypass handlers.

The default `tracer/src/main/cpp/rules/user_code_rules.cpp` is empty. Select sample-specific native CodeRules with `QTRACE_USER_RULES_SOURCE`, bind the build with `QTRACE_USER_RULES_SAMPLE_SHA256`, and explicitly enable `tracer.codeRules` with a matching `target.sha256`. CodeRules can match by module offset, then adjust registers, arguments, return values, PC, flags, or memory through `CodeRuleContext`.
