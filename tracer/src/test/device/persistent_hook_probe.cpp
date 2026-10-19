// Device-only integration probe. Two overlapping physical entries must publish
// two completed QBDI traces. The short scene has exactly 113 native instructions.
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int arrivals = 0;
extern "C" void probe_barrier() {
    __atomic_add_fetch(&arrivals, 1, __ATOMIC_ACQ_REL);
    while (__atomic_load_n(&arrivals, __ATOMIC_ACQUIRE) != 2) sched_yield();
}

extern "C" char probe_short_end[], probe_concurrent_end[], probe_reentry_end[];
extern "C" __attribute__((naked, noinline, aligned(4096))) uint64_t probe_short(uint64_t) {
    asm volatile("nop\n.rept 112\nadd x0, x0, #1\n.endr\nret\n"
                 ".global probe_short_end\nprobe_short_end:\n");
}
extern "C" __attribute__((naked, noinline, aligned(4096))) uint64_t probe_concurrent(uint64_t) {
    asm volatile("nop\nstp x19, x30, [sp, #-16]!\nmov x19, x0\nbl probe_barrier\n"
                 "add x0, x19, #7\nldp x19, x30, [sp], #16\nret\n"
                 ".global probe_concurrent_end\nprobe_concurrent_end:\n");
}

extern "C" __attribute__((naked, noinline, aligned(4096))) uint64_t probe_reentry(uint64_t) {
    asm volatile("nop\n1: sub x0, x0, #1\ncmp x0, #0\nb.gt 1b\nret\n"
                 ".global probe_reentry_end\nprobe_reentry_end:\n");
}

using Target = uint64_t (*)(uint64_t);
struct Call { Target target; uint64_t argument; uint64_t result; };
static void *enter(void *opaque) {
    auto *call = static_cast<Call *>(opaque);
    call->result = call->target(call->argument);
    return nullptr;
}
static uint64_t nanoseconds() {
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return uint64_t(now.tv_sec) * 1000000000 + now.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc != 8) return 2;
    alarm(20); // Bound a broken overlap barrier without leaving a remote process.
    void *tracer = dlopen(argv[1], RTLD_NOW);
    if (!tracer) { std::fprintf(stderr, "%s\n", dlerror()); return 3; }
    auto companion = reinterpret_cast<int (*)(const char *)>(dlsym(tracer, "qbdi_tracer_set_shadowhook_helper_path"));
    auto configure = reinterpret_cast<int (*)(const char *, uint64_t, char *, uint64_t, uint64_t *)>(dlsym(tracer, "qbdi_tracer_configure_json"));
    auto install = reinterpret_cast<int (*)(const char *, uintptr_t, uintptr_t)>(dlsym(tracer, "qbdi_tracer_install_region"));
    if (!companion || !configure || !install || companion(argv[2])) return 4;
    const bool concurrent = std::strcmp(argv[6], "concurrent") == 0;
    const bool reentry = std::strcmp(argv[6], "reentry") == 0;
    Target target = reinterpret_cast<Target>(reinterpret_cast<uintptr_t>(concurrent ? probe_concurrent : reentry ? probe_reentry : probe_short) + 4);
    const uintptr_t address = reinterpret_cast<uintptr_t>(target);
    const uintptr_t base = address & ~(uintptr_t(sysconf(_SC_PAGESIZE)) - 1);
    const uintptr_t end = reinterpret_cast<uintptr_t>(concurrent ? probe_concurrent_end : reentry ? probe_reentry_end : probe_short_end);
    const unsigned calls = concurrent ? 2 : std::strtoul(argv[5], nullptr, 10);
    if (calls == 0 || calls > 100) return 5;
    char request[4096], response[65536];
    uint64_t response_size = 0;
    std::snprintf(request, sizeof(request),
        "{\"schemaVersion\":1,\"packageName\":\"%s\",\"targetModule\":\"persistent-probe.so\","
        "\"trace\":{\"profile\":\"fast\",\"compression\":false,\"lz4Level\":0,\"autoBuffer\":false,\"bufferMb\":%s,\"hexdumpLimit\":0},"
        "\"flight\":{\"enabled\":false,\"entryScene\":\"\",\"capacityMb\":64,\"chunkKb\":256,\"maxThreads\":32,\"protectedChunks\":4},"
        "\"session\":{\"id\":\"%s\"},\"scenes\":[{\"name\":\"probe\",\"location\":{\"offset\":\"0x%lx\",\"endOffset\":\"0x%lx\"}}]}",
        argv[7], argv[4], argv[3], address - base, end - base);
    if (configure(request, std::strlen(request), response, sizeof(response), &response_size) ||
        !std::strstr(response, "\"ok\":true") ||
        install("persistent-probe.so", base, sysconf(_SC_PAGESIZE))) return 6;
    uint64_t durations[100]{};
    if (concurrent) {
        Call first{target, 10, 0}, second{target, 20, 0};
        pthread_t threads[2];
        if (pthread_create(threads, nullptr, enter, &first) ||
            pthread_create(threads + 1, nullptr, enter, &second)) return 7;
        pthread_join(threads[0], nullptr);
        pthread_join(threads[1], nullptr);
        if (first.result != 17 || second.result != 27) return 8;
    } else {
        for (unsigned index = 0; index < calls; ++index) {
            const uint64_t started = nanoseconds();
            const uint64_t value = target(reentry ? 3 : index);
            durations[index] = nanoseconds() - started;
            if (value != (reentry ? 0 : index + 112)) return 9;
        }
    }
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    std::printf("{\"pid\":%d,\"calls\":%u,\"start_offset\":%lu,\"end_offset\":%lu,\"peak_rss_kib\":%ld,\"call_ns\":[", getpid(), calls, address - base, end - base, usage.ru_maxrss);
    for (unsigned index = 0; index < (concurrent ? 0 : calls); ++index)
        std::printf("%s%llu", index ? "," : "", static_cast<unsigned long long>(durations[index]));
    std::puts("]}");
    return 0;
}
