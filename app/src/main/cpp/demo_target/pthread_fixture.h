#pragma once

extern "C" {

using DemoPthreadStartRoutine = void *(*)(void *);

struct DemoPthreadStatus {
    int create;
    int join;
};

struct DemoPthreadParentArgs {
    DemoPthreadStartRoutine child_start;
    void *arg;
    DemoPthreadStatus status;
    void *result;
};

__attribute__((noinline, visibility("default"))) void *
demo_pthread_parent_start(void *opaque);

}
