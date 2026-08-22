#include "pthread_fixture.h"

#include <pthread.h>

extern "C" __attribute__((noinline, visibility("default"))) void *
demo_pthread_parent_start(void *opaque) {
    auto *arguments = static_cast<DemoPthreadParentArgs *>(opaque);
    if (arguments == nullptr || arguments->child_start == nullptr) return nullptr;

    pthread_t child{};
    arguments->result = nullptr;
    arguments->status.create = pthread_create(
            &child, nullptr, arguments->child_start, arguments->arg);
    if (arguments->status.create != 0) return nullptr;

    arguments->status.join = pthread_join(child, &arguments->result);
    return arguments->status.join == 0 ? arguments->result : nullptr;
}
