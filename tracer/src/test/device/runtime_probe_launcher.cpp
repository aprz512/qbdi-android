// Each baseline/traced phase runs in its own supervised child. Only the target
// library is instrumented; orchestration, JSON and receipts stay outside it.
#include "runtime_probe.h"
#include "third_party/nlohmann/json.hpp"
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>

using nlohmann::json;
using Configure = int (*)(const char *, uint64_t, char *, uint64_t, uint64_t *);
using Status = int (*)(uint64_t, char *, uint64_t, uint64_t *);
static std::string read(const std::string &path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
static void write(const std::string &path, const std::string &value) {
    std::ofstream output(path); output << value; output.flush();
}
struct Work {
    RuntimeProbeTarget target;
    int scenario, count;
    int fd;
    json results = json::array();
};
static void *worker(void *opaque) {
    auto &work = *static_cast<Work *>(opaque);
    for (int repeat = 0; repeat < work.count; ++repeat) {
        RuntimeProbeInput input{};
        for (int index = 0; index < 16; ++index) input.values[index] = index + 1;
        input.receipt_fd = work.fd;
        const auto started = std::chrono::steady_clock::now();
        const auto value = work.target(work.scenario, &input);
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count();
        json values = json::array();
        for (int index = 0; index < 16; ++index) values.push_back(uint64_t(input.values[index]));
        work.results.push_back({{"return",value},{"values",values},{"observed_pid",input.observed_pid},
                                {"wait_status",input.wait_status},{"elapsed_ns",elapsed}});
    }
    return reinterpret_cast<void *>(42);
}

static int phase(const std::string &directory, const std::string &package,
                 const std::string &session, int scenario, const std::string &profile, bool flight, bool traced) {
    alarm(20);
    const std::string label = traced ? "traced" : "baseline";
    void *target_library = dlopen((directory+"/libruntime_probe.so").c_str(), RTLD_NOW | RTLD_LOCAL);
    auto target = reinterpret_cast<RuntimeProbeTarget>(dlsym(target_library,"runtime_probe_target"));
    if (!target_library || !target) return 91;
    Configure configure = nullptr;
    Status status = nullptr;
    json configuration;
    if (traced) {
        void *tracer = dlopen((directory+"/libqbdi_tracer.so").c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!tracer) { write(directory+"/loader-error",dlerror()); return 92; }
        auto companion = reinterpret_cast<int (*)(const char *)>(dlsym(tracer,"qbdi_tracer_set_shadowhook_helper_path"));
        configure = reinterpret_cast<Configure>(dlsym(tracer,"qbdi_tracer_configure_json"));
        status = reinterpret_cast<Status>(dlsym(tracer,"qbdi_tracer_get_status_json"));
        if (!companion || !configure || !status || companion((directory+"/libshadowhook_nothing.so").c_str())) return 93;
        Dl_info info{}; dladdr(reinterpret_cast<void *>(target), &info);
        char offset[32]; std::snprintf(offset,sizeof(offset),"0x%lx",reinterpret_cast<uintptr_t>(target)-reinterpret_cast<uintptr_t>(info.dli_fbase));
        configuration = {{"schemaVersion",1},{"packageName",package},{"targetModule","libruntime_probe.so"},
            {"trace",{{"profile",profile=="calls"?"fast":profile},{"compression",false},{"lz4Level",0},{"autoBuffer",false},{"bufferMb",8},{"hexdumpLimit",32}}},
            {"flight",{{"enabled",flight},{"followThreads",false},{"entryScene",flight?"runtime":""},{"capacityMb",64},{"chunkKb",256},{"maxThreads",4},{"protectedChunks",2}}},
            {"session",{{"id",session}}},
            {"scenes",json::array({{{"name","runtime"},{"location",{{"offset",offset}}}}})}};
        if (scenario == 7) configuration["session"]["durationMs"] = 100;
        if (profile == "calls") configuration["trace"]["events"] = "calls";
        const auto request = configuration.dump();
        char response[65536]{}; uint64_t length = 0;
        const auto configured = configure(request.data(),request.size(),response,sizeof(response),&length);
        write(directory+"/configure-response.json",response);
        if (configured || !json::parse(response).value("ok",false)) {
            write(directory+"/configure-error",response); return 94;
        }
        for (int attempt = 0; attempt < 100; ++attempt) {
            status(1,response,sizeof(response),&length);
            if (std::string(response).find("\"state\":\"installed\"") != std::string::npos) break;
            usleep(20000);
        }
        write(directory+"/install-status.json",response);
        if (std::string(response).find("\"state\":\"installed\"") == std::string::npos) return 95;
    }
    const std::string receipt = directory+"/"+label+".receipt";
    const int fd = open(receipt.c_str(),O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC,0600);
    if (fd < 0) return 96;
    Work work{target,scenario,scenario == 0 ? 5 : 1,fd};
    Work concurrent{target,scenario,1,fd};
    pthread_t thread; void *joined = nullptr;
    pthread_t second; void *second_joined = nullptr;
    if (pthread_create(&thread,nullptr,worker,&work)) return 97;
    if (scenario == 10 && pthread_create(&second,nullptr,worker,&concurrent)) return 97;
    if (pthread_join(thread,&joined)) return 97;
    if (scenario == 10) {
        if (pthread_join(second,&second_joined) || second_joined != reinterpret_cast<void *>(42)) return 97;
        for (auto &row : concurrent.results) work.results.push_back(std::move(row));
    }
    close(fd);
    json result = {{"pid",getpid()},{"joined",reinterpret_cast<uintptr_t>(joined)},
                   {"results",work.results},{"configuration",configuration}};
    if (status) {
        char response[65536]{}; uint64_t length = 0;
        status(1,response,sizeof(response),&length);
        result["status"] = json::parse(response);
    }
    // Give the status publisher a chance to persist the final cold transition.
    usleep(60000);
    write(directory+"/"+label+".json",result.dump());
    return 0;
}

int main(int argc,char **argv) {
    if (argc != 7) return 2;
    alarm(45);
    const std::string directory=argv[1], package=argv[2], session=argv[3], profile=argv[5];
    const int scenario=std::stoi(argv[4]);
    const bool flight=std::string(argv[6])=="1";
    json result = {{"scenario",scenario},{"profile",profile},{"flight",flight}};
    const std::string status_path="/data/user/0/"+package+"/files/qbdi-traces/session-"+session+".status.json";
    for (int traced=0; traced<2; ++traced) {
        const std::string label=traced?"traced":"baseline";
        const auto child=fork();
        if (child<0) return 3;
        if (child==0) {
            raise(SIGSTOP);
            _exit(phase(directory,package,session,scenario,profile,flight,traced));
        }
        int wait_status=0;
        if (waitpid(child,&wait_status,WUNTRACED)!=child || !WIFSTOPPED(wait_status)) return 4;
        mkdir((directory+"/"+label).c_str(),0700);
        write(directory+"/"+label+"/pid",std::to_string(child));
        write(directory+"/"+label+"/epoch",read("/proc/"+std::to_string(child)+"/stat"));
        kill(child,SIGCONT);
        json history=json::array(); std::string previous;
        for (;;) {
            const auto waited=waitpid(child,&wait_status,WNOHANG);
            if (waited==child) break;
            if (waited<0) return 5;
            if (traced) {
                const auto snapshot=read(status_path);
                if (!snapshot.empty() && snapshot!=previous && history.size()<256) {
                    history.push_back(json::parse(snapshot,nullptr,false)); previous=snapshot;
                }
            }
            usleep(5000);
        }
        const auto document=read(directory+"/"+label+".json");
        result[label]={{"pid",child},{"exited",bool(WIFEXITED(wait_status))},
                       {"exit_code",WIFEXITED(wait_status)?WEXITSTATUS(wait_status):-1},
                       {"signal",WIFSIGNALED(wait_status)?WTERMSIG(wait_status):0},
                       {"receipt",read(directory+"/"+label+".receipt")},
                       {"returned",!document.empty()},{"history",history}};
        if (!document.empty()) result[label]["observation"]=json::parse(document);
    }
    std::printf("QTRACE_RUNTIME_RESULT %s\n",result.dump().c_str());
}
