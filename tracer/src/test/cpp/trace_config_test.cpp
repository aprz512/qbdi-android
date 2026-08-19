#include "core/trace_config.h"

#include <cassert>
#include <cstring>

static void assert_invalid(const char *encoded_config) {
    TraceConfig config = parse_trace_config(encoded_config);
    assert(!config.valid);
    assert(!config.error.empty());
}

int main() {
    TraceConfig defaults = default_trace_config();
    assert(defaults.trace.profile == TraceProfile::Fast);
    assert(defaults.trace.compression_enabled);
    assert(defaults.trace.lz4_level == 0);
    assert(defaults.trace.auto_buffer_size);
    assert(defaults.trace.buffer_bytes == 0);
    assert(defaults.trace.hexdump_limit == 32);
    assert(!defaults.trace.memory_enabled());
    assert(!defaults.trace.hexdump_enabled());
    assert(defaults.valid);

    TraceConfig parsed = parse_trace_config(
            "profile=full;compression=0;lz4_level=9;auto_buffer=0;"
            "buffer_mb=64;hexdump_limit=16");
    assert(parsed.trace.profile == TraceProfile::Full);
    assert(!parsed.trace.compression_enabled);
    assert(parsed.trace.lz4_level == 9);
    assert(!parsed.trace.auto_buffer_size);
    assert(parsed.trace.buffer_bytes == 64ULL * 1024 * 1024);
    assert(parsed.trace.hexdump_limit == 16);
    assert(parsed.trace.memory_enabled());
    assert(parsed.trace.hexdump_enabled());
    assert(std::strcmp(trace_profile_name(parsed.trace.profile), "full") == 0);

    TraceConfig automatic = parse_trace_config("profile=balanced;buffer_mb=0");
    assert(automatic.valid);
    assert(automatic.trace.profile == TraceProfile::Balanced);
    assert(automatic.trace.auto_buffer_size);
    assert(automatic.trace.buffer_bytes == 0);
    assert(automatic.trace.memory_enabled());
    assert(!automatic.trace.hexdump_enabled());

    assert_invalid("profile=turbo;buffer_mb=512");
    assert_invalid("lz4_level=9oops");
    assert_invalid("lz4_level=13");
    assert_invalid("buffer_mb=7");
    assert_invalid("buffer_mb=129");
    assert_invalid("hexdump_limit=65");
    assert_invalid("compression=true");
    assert_invalid("unknown_option=1");
}
