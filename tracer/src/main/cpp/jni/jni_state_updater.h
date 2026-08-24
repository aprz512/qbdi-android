#pragma once

#include "jni/jni_function_table.h"
#include "jni/jni_state.h"

#include <cstdint>

void update_jni_state(JniState &state, const JniFuncInfo &function,
                      const uint64_t *arguments, uint64_t result);
