#pragma once

#include <cstdint>

extern "C" uint64_t call_target_arm64(uintptr_t target, const uint64_t args[8],
                                       uint64_t indirect_result_x8);
