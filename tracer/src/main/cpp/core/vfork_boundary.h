#pragma once
#include <cstdint>

// Serialize instrumented vfork transfers. The child must bypass QBDI's shared
// execution state and continue at the real caller until exec/_exit.
bool prepare_native_vfork(uintptr_t entry, uintptr_t child_return) noexcept;
void finish_native_vfork() noexcept;
uintptr_t native_vfork_boundary_address() noexcept;
