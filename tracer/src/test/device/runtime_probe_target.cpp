// Small native targets, independent of any application or injection mechanism.
#include "runtime_probe.h"
#include <pthread.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/stat.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
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

// One actual SVC in target code, with no libc errno translation.
static __attribute__((naked, noinline)) uint64_t raw_svc(
        uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) {
    asm volatile("mov x8, x0\nmov x0, x1\nmov x1, x2\nmov x2, x3\n"
                 "mov x3, x4\nmov x4, x5\nmov x5, x6\nsvc #0\nret");
}

static uint64_t observe_svc(RuntimeProbeInput *input, const char *name,
                            uint64_t number, uint64_t a0 = 0, uint64_t a1 = 0,
                            uint64_t a2 = 0, uint64_t a3 = 0,
                            uint64_t a4 = 0, uint64_t a5 = 0) {
    auto &row = input->syscalls[input->syscall_count++];
    row.name = name;
    row.number = number;
    row.args[0] = a0; row.args[1] = a1; row.args[2] = a2; row.args[3] = a3;
    row.args[4] = a4; row.args[5] = a5;
    errno = 123;
    row.errno_before = errno;
    row.raw_return = raw_svc(number, a0, a1, a2, a3, a4, a5);
    row.errno_after = errno;
    return row.raw_return;
}

static volatile sig_atomic_t interrupted = 0;
static volatile sig_atomic_t signal_count = 0;
static volatile sig_atomic_t signal_order = 0;
static volatile sig_atomic_t handler_depth = 0;
static void interrupt_handler(int) { interrupted = 1; signal_count = signal_count + 1; }
static void nested_handler(int) {
    signal_count = signal_count + 1;
    handler_depth = handler_depth + 1;
    if (handler_depth == 1) {
        signal_order = signal_order * 10 + 1;
        syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
        signal_order = signal_order * 10 + 4;
    } else {
        signal_order = signal_order * 10 + 2;
        signal_order = signal_order * 10 + 3;
    }
    handler_depth = handler_depth - 1;
}
static void *interrupt_worker(void *opaque) {
    const auto target = *static_cast<pthread_t *>(opaque);
    usleep(50000);
    pthread_kill(target, SIGUSR1);
    return nullptr;
}
static void *kill_worker(void *) {
    usleep(300000);
    kill(getpid(), SIGKILL);
    return nullptr;
}
struct RestartSender { pthread_t target; int descriptor; };
static void *restart_worker(void *opaque) {
    const auto sender = *static_cast<RestartSender *>(opaque);
    usleep(50000);
    pthread_kill(sender.target, SIGUSR1);
    usleep(50000);
    (void)write(sender.descriptor, "R", 1);
    return nullptr;
}

// Install the fixture disposition before tracer startup, so the broker can
// retain it. A libc sigaction inside the traced target would replace its hook.
extern "C" __attribute__((visibility("default")))
int runtime_probe_prepare(int scenario) {
    if (scenario != 13 && scenario != 16 && scenario != 17) return 0;
    interrupted = 0; signal_count = 0; signal_order = 0; handler_depth = 0;
    struct sigaction action{};
    action.sa_handler = scenario == 16 ? nested_handler : interrupt_handler;
    action.sa_flags = scenario == 16 ? SA_NODEFER : scenario == 17 ? SA_RESTART : 0;
    sigemptyset(&action.sa_mask);
    return sigaction(SIGUSR1, &action, nullptr);
}

extern "C" __attribute__((visibility("default"), noinline))
uint64_t runtime_probe_target(int scenario, RuntimeProbeInput *input) {
    if (scenario == 18) {
        timespec requested{0, 500000000};
        const auto returned = observe_svc(input, "stopped", SYS_nanosleep,
                reinterpret_cast<uint64_t>(&requested));
        return returned == 0 && input->syscalls[0].errno_after == 123 ? 42 : 10;
    }
    if (scenario == 17) {
        int descriptors[2];
        if (pipe(descriptors)) return 11;
        RestartSender request{pthread_self(), descriptors[1]};
        pthread_t sender;
        if (pthread_create(&sender, nullptr, restart_worker, &request)) return 12;
        char byte = 0;
        const auto returned = observe_svc(input, "restarted", SYS_read, descriptors[0],
                reinterpret_cast<uint64_t>(&byte), 1);
        pthread_join(sender, nullptr);
        close(descriptors[0]); close(descriptors[1]);
        input->signal_count = signal_count;
        return returned == 1 && byte == 'R' && signal_count == 1 &&
               input->syscalls[0].errno_after == 123 ? 42 : 13;
    }
    if (scenario == 15) {
        const auto directory = static_cast<uint64_t>(static_cast<int64_t>(AT_FDCWD));
        char link[4096]{};
        struct stat status{};
        struct statx extended{};
        const char *old_path = "/proc/self/qtrace-missing-dir/old";
        const char *new_path = "/proc/self/qtrace-missing-dir/new";
        const auto access = observe_svc(input, "access", SYS_faccessat, directory,
                reinterpret_cast<uint64_t>("/dev/null"), F_OK);
        const auto linked = observe_svc(input, "readlink", SYS_readlinkat, directory,
                reinterpret_cast<uint64_t>("/proc/self/exe"), reinterpret_cast<uint64_t>(link), sizeof(link));
        const auto stated = observe_svc(input, "stat", 79, directory,
                reinterpret_cast<uint64_t>("/dev/null"), reinterpret_cast<uint64_t>(&status), 0);
        const auto renamed = observe_svc(input, "rename", SYS_renameat, directory,
                reinterpret_cast<uint64_t>(old_path), directory, reinterpret_cast<uint64_t>(new_path));
        const auto hard_link = observe_svc(input, "link", SYS_linkat, directory,
                reinterpret_cast<uint64_t>(old_path), directory, reinterpret_cast<uint64_t>(new_path));
        const auto symbolic = observe_svc(input, "symlink", SYS_symlinkat,
                reinterpret_cast<uint64_t>("/qtrace-source"), directory, reinterpret_cast<uint64_t>(new_path));
        const auto extended_stat = observe_svc(input, "statx", SYS_statx, directory,
                reinterpret_cast<uint64_t>("/dev/null"), AT_SYMLINK_NOFOLLOW, STATX_TYPE,
                reinterpret_cast<uint64_t>(&extended));
        return access == 0 && linked > 0 && linked <= sizeof(link) && link[0] == '/' &&
               stated == 0 && S_ISCHR(status.st_mode) && static_cast<int64_t>(renamed) == -ENOENT &&
               static_cast<int64_t>(hard_link) == -ENOENT && static_cast<int64_t>(symbolic) == -ENOENT &&
               (extended_stat == 0 || static_cast<int64_t>(extended_stat) == -ENOSYS) ? 42 : 14;
    }
    if (scenario == 14) {
        pthread_t sender;
        if (pthread_create(&sender, nullptr, kill_worker, nullptr)) return 8;
        (void)write(input->receipt_fd, "K", 1);
        timespec requested{2, 0};
        observe_svc(input, "missing-return", SYS_nanosleep, reinterpret_cast<uint64_t>(&requested));
        pthread_join(sender, nullptr);
        return 9;
    }
    if (scenario == 11 || scenario == 12) {
        const auto page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        auto *mapping = static_cast<char *>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (mapping == MAP_FAILED) return 1;
        std::memcpy(mapping + page - 4, "/dev", 4);
        if (mprotect(mapping + page, page, PROT_NONE)) return 2;
        char long_path[302];
        long_path[0] = '/';
        std::memset(long_path + 1, 'q', 300); long_path[301] = 0;
        const auto directory = static_cast<uint64_t>(static_cast<int64_t>(AT_FDCWD));
        const auto fd = observe_svc(input, "valid", SYS_openat, directory,
                                     reinterpret_cast<uint64_t>("/dev/null"), O_RDONLY);
        if (static_cast<int64_t>(fd) < 0) return 3;
        const auto closed = observe_svc(input, "close", SYS_close, fd);
        const auto missing = observe_svc(input, "missing", SYS_openat, directory,
                reinterpret_cast<uint64_t>("/qtrace-fixture-no-such-file-20261022"), O_RDONLY);
        const auto invalid = observe_svc(input, "invalid", SYS_openat, directory, 1, O_RDONLY);
        const auto partial = observe_svc(input, "partial", SYS_openat, directory,
                                         reinterpret_cast<uint64_t>(mapping + page - 4), O_RDONLY);
        const auto truncated = observe_svc(input, "truncated", SYS_openat, directory,
                                           reinterpret_cast<uint64_t>(long_path), O_RDONLY);
        munmap(mapping, page * 2);
        bool unchanged = true;
        for (uint32_t index = 0; index < input->syscall_count; ++index)
            unchanged &= input->syscalls[index].errno_before == 123 && input->syscalls[index].errno_after == 123;
        return closed == 0 && static_cast<int64_t>(missing) == -ENOENT &&
               static_cast<int64_t>(invalid) == -EFAULT && static_cast<int64_t>(partial) == -EFAULT &&
               static_cast<int64_t>(truncated) == -ENAMETOOLONG && unchanged ? 42 : 4;
    }
    if (scenario == 13 || scenario == 16) {
        interrupted = 0;
        pthread_t current = pthread_self(), sender;
        if (pthread_create(&sender, nullptr, interrupt_worker, &current)) return 6;
        timespec requested{1, 0}, remaining{};
        const auto returned = observe_svc(input, "interrupted", SYS_nanosleep,
                reinterpret_cast<uint64_t>(&requested), reinterpret_cast<uint64_t>(&remaining));
        pthread_join(sender, nullptr);
        input->signal_count = signal_count;
        input->signal_order = signal_order;
        return static_cast<int64_t>(returned) == -EINTR &&
               (scenario == 16 ? signal_count == 2 && signal_order == 1234 : interrupted == 1) &&
               input->syscalls[0].errno_after == 123 ? 42 : 7;
    }
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
