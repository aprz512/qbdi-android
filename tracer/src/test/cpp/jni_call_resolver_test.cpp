#include "jni/jni_call_resolver.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <thread>
#include <vector>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

size_t interface_function_count(std::string_view interface_name) {
    size_t count = 0;
    for (const auto &function: build_jni_function_table()) {
        if (interface_name == function.struct_name) ++count;
    }
    return count;
}

class FakeJniMemory {
public:
    FakeJniMemory()
            : env_table_(4 + interface_function_count("JNIEnv"), 0),
              vm_table_(3 + interface_function_count("JavaVM"), 0) {
        for (size_t slot = 4; slot < env_table_.size(); ++slot) {
            env_table_[slot] = 0x100000 + slot * 0x10;
        }
        for (size_t slot = 3; slot < vm_table_.size(); ++slot) {
            vm_table_[slot] = 0x200000 + slot * 0x10;
        }
        env_receiver_ = reinterpret_cast<uintptr_t>(env_table_.data());
        vm_receiver_ = reinterpret_cast<uintptr_t>(vm_table_.data());
    }

    JniCallResolver::MemoryReader reader() {
        return [this](uintptr_t address, void *output, size_t size) {
            reads.fetch_add(1, std::memory_order_relaxed);
            if (fail_reads.load(std::memory_order_relaxed)) return false;
            return copy_from(address, output, size, env_receiver_) ||
                   copy_from(address, output, size, vm_receiver_) ||
                   copy_from(address, output, size, env_table_) ||
                   copy_from(address, output, size, vm_table_);
        };
    }

    uintptr_t env() const { return reinterpret_cast<uintptr_t>(&env_receiver_); }
    uintptr_t vm() const { return reinterpret_cast<uintptr_t>(&vm_receiver_); }
    uintptr_t env_target(size_t slot) const { return env_table_.at(slot); }
    uintptr_t vm_target(size_t slot) const { return vm_table_.at(slot); }

    std::atomic<size_t> reads{0};
    std::atomic<bool> fail_reads{false};

private:
    static bool copy_from(uintptr_t address, void *output, size_t size,
                          const uintptr_t &word) {
        const uintptr_t start = reinterpret_cast<uintptr_t>(&word);
        if (address != start || size != sizeof(word)) return false;
        std::memcpy(output, &word, size);
        return true;
    }

    static bool copy_from(uintptr_t address, void *output, size_t size,
                          const std::vector<uintptr_t> &words) {
        const uintptr_t start = reinterpret_cast<uintptr_t>(words.data());
        const uintptr_t end = start + words.size() * sizeof(uintptr_t);
        if (address < start || address > end || size > end - address) return false;
        std::memcpy(output, reinterpret_cast<const void *>(address), size);
        return true;
    }

    std::vector<uintptr_t> env_table_;
    std::vector<uintptr_t> vm_table_;
    uintptr_t env_receiver_ = 0;
    uintptr_t vm_receiver_ = 0;
};

void non_jni_first_call_does_not_consume_env_publication() {
    FakeJniMemory memory;
    JniCallResolver resolver(memory.reader());

    CHECK(resolver.resolve(memory.env(), 0xDEADBEEF) == nullptr);
    const JniFuncInfo *find_class = resolver.resolve(memory.env(), memory.env_target(6));
    CHECK(find_class != nullptr);
    CHECK(std::string_view(find_class->name) == "FindClass");
    CHECK(std::string_view(find_class->struct_name) == "JNIEnv");
}

void target_must_belong_to_the_receiver_table_before_publication() {
    FakeJniMemory memory;
    JniCallResolver resolver(memory.reader());

    CHECK(resolver.resolve(memory.env(), memory.vm_target(6)) == nullptr);
    const JniFuncInfo *get_env = resolver.resolve(memory.vm(), memory.vm_target(6));
    CHECK(get_env != nullptr);
    CHECK(std::string_view(get_env->name) == "GetEnv");
    CHECK(std::string_view(get_env->struct_name) == "JavaVM");
}

void env_and_vm_publish_independently_then_use_read_only_hot_paths() {
    FakeJniMemory memory;
    JniCallResolver resolver(memory.reader());

    const JniFuncInfo *get_version = resolver.resolve(memory.env(), memory.env_target(4));
    CHECK(get_version != nullptr);
    CHECK(std::string_view(get_version->name) == "GetVersion");

    const JniFuncInfo *destroy_vm = resolver.resolve(memory.vm(), memory.vm_target(3));
    CHECK(destroy_vm != nullptr);
    CHECK(std::string_view(destroy_vm->name) == "DestroyJavaVM");

    const size_t reads_after_publication = memory.reads.load();
    memory.fail_reads.store(true);
    CHECK(resolver.resolve(1, memory.env_target(6)) != nullptr);
    CHECK(resolver.resolve(1, memory.vm_target(7)) != nullptr);
    CHECK(memory.reads.load() == reads_after_publication);
}

void concurrent_env_initialization_publishes_one_complete_registry() {
    FakeJniMemory memory;
    JniCallResolver resolver(memory.reader());
    std::atomic<bool> start{false};
    std::atomic<size_t> resolved{0};
    std::vector<std::thread> threads;

    for (size_t index = 0; index < 8; ++index) {
        threads.emplace_back([&] {
            while (!start.load(std::memory_order_acquire)) {}
            const JniFuncInfo *function =
                    resolver.resolve(memory.env(), memory.env_target(6));
            if (function != nullptr && std::string_view(function->name) == "FindClass") {
                resolved.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    start.store(true, std::memory_order_release);
    for (auto &thread: threads) thread.join();
    CHECK(resolved.load() == threads.size());
}

} // namespace

int main() {
    non_jni_first_call_does_not_consume_env_publication();
    target_must_belong_to_the_receiver_table_before_publication();
    env_and_vm_publish_independently_then_use_read_only_hot_paths();
    concurrent_env_initialization_publishes_one_complete_registry();
}
