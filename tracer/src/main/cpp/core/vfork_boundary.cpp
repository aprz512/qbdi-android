#include "core/vfork_boundary.h"
#include <cstdlib>
#include <mutex>

extern "C" {
__attribute__((visibility("hidden"))) volatile uintptr_t qtrace_vfork_target = 0;
__attribute__((visibility("hidden"))) volatile uintptr_t qtrace_vfork_child_return = 0;
__attribute__((visibility("hidden"))) volatile uintptr_t qtrace_vfork_broker_return = 0;
#if defined(QTRACE_HOST_TEST)
void qtrace_native_vfork_boundary() { std::abort(); }
#else
void qtrace_native_vfork_boundary();
#endif
}

namespace { std::mutex vfork_mutex; }

bool prepare_native_vfork(uintptr_t entry, uintptr_t child_return) noexcept {
    if (entry == 0 || child_return == 0 || entry == native_vfork_boundary_address()) return false;
    vfork_mutex.lock();
    qtrace_vfork_target = entry;
    qtrace_vfork_child_return = child_return;
    return true;
}

void finish_native_vfork() noexcept {
    qtrace_vfork_target = 0;
    qtrace_vfork_child_return = 0;
    qtrace_vfork_broker_return = 0;
    vfork_mutex.unlock();
}

uintptr_t native_vfork_boundary_address() noexcept {
    return reinterpret_cast<uintptr_t>(qtrace_native_vfork_boundary);
}
