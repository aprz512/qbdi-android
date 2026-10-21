#include "core/vfork_boundary.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>

#define CHECK(value) do { if (!(value)) { std::fprintf(stderr,"CHECK failed: %s\n",#value); std::abort(); } } while(false)

int main() {
    CHECK(!prepare_native_vfork(0,0x2000));
    CHECK(!prepare_native_vfork(0x1000,0));
    CHECK(!prepare_native_vfork(native_vfork_boundary_address(),0x2000));
    std::atomic<unsigned> inside{0}, completed{0};
    auto enter = [&] {
        for (unsigned index=0; index<100; ++index) {
            CHECK(prepare_native_vfork(0x1000,0x2000));
            CHECK(inside.fetch_add(1)==0);
            std::this_thread::yield();
            CHECK(inside.fetch_sub(1)==1);
            finish_native_vfork();
            completed.fetch_add(1);
        }
    };
    std::thread first(enter), second(enter);
    first.join(); second.join();
    CHECK(completed.load()==200);
}
