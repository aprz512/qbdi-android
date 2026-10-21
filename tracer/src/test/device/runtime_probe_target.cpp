// Small native targets, independent of any application or injection mechanism.
#include "runtime_probe.h"
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static __attribute__((noinline)) uint64_t add25(uint64_t value) { return value + 25; }
static __attribute__((naked, noinline)) uint64_t tail(uint64_t, uint64_t (*)(uint64_t)) {
    asm volatile("br x1");
}
static uint64_t now_ns() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
}

extern "C" __attribute__((visibility("default"), noinline))
uint64_t runtime_probe_target(int scenario, RuntimeProbeInput *input) {
    if (scenario == 0) {
        for (uint64_t index = 0; index < 256; ++index) {
            const auto slot = index % 16;
            input->values[slot] = (input->values[slot] * 33 + index) ^ 0x1234;
        }
        auto *volatile function = &getpid;
        input->observed_pid = function();
        // A real inline svc supplies an independent syscall observation.
        register uint64_t number asm("x8") = SYS_getpid;
        register uint64_t returned asm("x0");
        asm volatile("svc #0" : "=r"(returned) : "r"(number) : "memory", "cc");
        return returned == input->observed_pid ? 42 : 0;
    }
    if (scenario == 1) {
        auto *volatile function = &tail;
        input->values[0] = function(17, add25);
        return input->values[0];
    }
    if (scenario == 2 || scenario == 3 || scenario == 8 || scenario == 10) {
        const pid_t child = scenario == 2 ? fork() : vfork();
        if (child == 0) {
            if (scenario == 8) {
                execl("/system/bin/true", "true", static_cast<char *>(nullptr));
                _exit(99);
            }
            _exit(17);
        }
        if (child < 0 || waitpid(child, &input->wait_status, 0) != child) return 0;
        return WIFEXITED(input->wait_status) && WEXITSTATUS(input->wait_status) == (scenario == 8 ? 0 : 17) ? 42 : 0;
    }
    if (scenario == 4) {
        (void)write(input->receipt_fd, "E", 1);
        execl("/system/bin/true", "true", static_cast<char *>(nullptr));
        return 13;
    }
    if (scenario == 5) {
        (void)write(input->receipt_fd, "X", 1);
        _exit(23);
    }
    if (scenario == 6) {
        (void)write(input->receipt_fd, "T", 1);
        pthread_exit(reinterpret_cast<void *>(42));
    }
    if (scenario == 7) {
        const uint64_t end = now_ns() + 150000000;
        while (now_ns() < end) asm volatile("nop");
        usleep(250000);
        return 42;
    }
    if (scenario == 9) {
        input->values[0] += 1;
        const int result = execl("/qtrace-does-not-exist", "missing", static_cast<char *>(nullptr));
        input->values[0] += 1;
        return result == -1 && input->values[0] == 3 ? 42 : 0;
    }
    return 0;
}
