#include "third_party/nlohmann/json.hpp"
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
using nlohmann::json;
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 void *library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
 if(!library){std::fprintf(stderr,"%s\n",dlerror());return 3;}
 using Snapshot=int(*)(const char*,uint64_t,char*,uint64_t,uint64_t*);
 auto capture=reinterpret_cast<Snapshot>(dlsym(library,"qbdi_tracer_snapshot_json"));
 if(!capture)return 4;
 std::ifstream input("/proc/self/stat");std::string stat;std::getline(input,stat);
 std::istringstream fields(stat.substr(stat.rfind(')')+2));std::string epoch;
 for(unsigned index=0;index<20;++index)fields>>epoch;
 json request={{"schema",1},{"expectedPid",getpid()},{"expectedStarttime",epoch},{"includeJava",true},{"maxThreads",32},{"maxFrames",32}};
 const auto text=request.dump();char output[65536]{};uint64_t size=0;
 const int signals[]={SIGSEGV,SIGBUS,SIGABRT,SIGUSR1};struct sigaction before[4]{},after[4]{};
 for(unsigned index=0;index<4;++index)if(sigaction(signals[index],nullptr,&before[index]))return 5;
 errno=123;const int code=capture(text.data(),text.size(),output,sizeof(output),&size);const bool kept_errno=errno==123;
 bool handlers=true;
 for(unsigned index=0;index<4;++index){
  if(sigaction(signals[index],nullptr,&after[index]))return 6;
  handlers&=before[index].sa_handler==after[index].sa_handler && before[index].sa_flags==after[index].sa_flags;
  for(int signal=1;signal<NSIG;++signal)handlers&=sigismember(&before[index].sa_mask,signal)==sigismember(&after[index].sa_mask,signal);
 }
 if(code || size<2 || size>sizeof(output))return 7;
 auto result=json::parse(output,output+size-1);
 json report={{"request",request},{"snapshot",result},{"errno_preserved",kept_errno},{"handlers_preserved",handlers},{"pid_stat",stat}};
 std::puts(report.dump().c_str());
 return result.value("ok",false) && result["java"]["status"]=="unavailable" && result["java"]["reason"]=="vm_unavailable" && kept_errno && handlers ? 0 : 8;
}
