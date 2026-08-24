#include "jni/jni_function_registry.h"

#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

void binding_publishes_owned_metadata_by_address() {
    JniFunctionRegistry registry;

    CHECK(registry.bind("FindClass", 0x1234));
    const JniFuncInfo *found = registry.find(0x1234);
    CHECK(found != nullptr);
    CHECK(std::string_view(found->name) == "FindClass");
    CHECK(found->address == 0x1234);
    CHECK(registry.is_bound("FindClass"));
    CHECK(registry.find(0x9999) == nullptr);
    CHECK(!registry.bind("missing", 0x2222));
    CHECK(!registry.bind("GetVersion", 0x1234));
    CHECK(!registry.bind("FindClass", 0x5678));
    CHECK(!registry.bind("GetVersion", 0));
    CHECK(registry.size() == 1);
}

} // namespace

int main() {
    binding_publishes_owned_metadata_by_address();
}
