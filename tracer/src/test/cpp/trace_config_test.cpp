#include "core/trace_config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

static void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

static void assert_invalid(const char *encoded_config) {
    TraceConfig config = parse_trace_config(encoded_config);
    CHECK(!config.valid);
    CHECK(!config.error.empty());
}

int main() {
    TraceConfig defaults = default_trace_config();
    CHECK(defaults.trace.profile == TraceProfile::Fast);
    CHECK(defaults.trace.compression_enabled);
    CHECK(defaults.trace.lz4_level == 0);
    CHECK(defaults.trace.auto_buffer_size);
    CHECK(defaults.trace.buffer_bytes == 0);
    CHECK(defaults.trace.hexdump_limit == 32);
    CHECK(!defaults.trace.memory_enabled());
    CHECK(!defaults.trace.hexdump_enabled());
    CHECK(!defaults.flight.enabled);
    CHECK(defaults.flight.capacity_bytes == 512ULL * 1024 * 1024);
    CHECK(defaults.flight.chunk_bytes == 256U * 1024);
    CHECK(defaults.flight.max_threads == 256);
    CHECK(defaults.flight.protected_chunks == 4);
    CHECK(defaults.valid);

    TraceConfig flight = parse_trace_config(
            "flight=1;flight_mb=512;flight_chunk_kb=256;flight_max_threads=256;"
            "flight_protected_chunks=4");
    CHECK(flight.valid);
    CHECK(flight.flight.enabled);
    CHECK(flight.flight.capacity_bytes == 512ULL * 1024 * 1024);
    CHECK(flight.flight.chunk_bytes == 256U * 1024);
    CHECK(flight.flight.max_threads == 256);
    CHECK(flight.flight.protected_chunks == 4);

    assert_invalid("flight=2");
    assert_invalid("flight_mb=63");
    assert_invalid("flight_mb=2049");
    assert_invalid("flight_chunk_kb=63");
    assert_invalid("flight_chunk_kb=96");
    assert_invalid("flight_chunk_kb=2048");
    assert_invalid("flight_max_threads=0");
    assert_invalid("flight_max_threads=1025");
    assert_invalid("flight_protected_chunks=0");
    assert_invalid("flight_mb=64;flight_chunk_kb=1024;flight_protected_chunks=65");

    TraceConfig replacement_scenes = parse_trace_config(
            "scenes=replace;scene=init,0x100;scene=jni,0x200;scene=libc,0x300;"
            "scene=algorithm,0x400;scene=integrity,0x500");
    CHECK(replacement_scenes.valid);
    CHECK(replacement_scenes.scenes.size() == 5);
    const char *expected_scene_names[] = {
            "init", "jni", "libc", "algorithm", "integrity"};
    for (size_t index = 0; index < replacement_scenes.scenes.size(); ++index) {
        CHECK(replacement_scenes.scenes[index].index == index);
        CHECK(replacement_scenes.scenes[index].name == expected_scene_names[index]);
        CHECK(replacement_scenes.scenes[index].offset == (index + 1) * 0x100);
    }

    TraceConfig parsed = parse_trace_config(
            "profile=full;compression=0;lz4_level=9;auto_buffer=0;"
            "buffer_mb=64;hexdump_limit=16");
    CHECK(parsed.trace.profile == TraceProfile::Full);
    CHECK(!parsed.trace.compression_enabled);
    CHECK(parsed.trace.lz4_level == 9);
    CHECK(!parsed.trace.auto_buffer_size);
    CHECK(parsed.trace.buffer_bytes == 64ULL * 1024 * 1024);
    CHECK(parsed.trace.hexdump_limit == 16);
    CHECK(parsed.trace.memory_enabled());
    CHECK(parsed.trace.hexdump_enabled());
    CHECK(std::strcmp(trace_profile_name(parsed.trace.profile), "full") == 0);

    TraceConfig automatic = parse_trace_config("profile=balanced;buffer_mb=0");
    CHECK(automatic.valid);
    CHECK(automatic.trace.profile == TraceProfile::Balanced);
    CHECK(automatic.trace.auto_buffer_size);
    CHECK(automatic.trace.buffer_bytes == 0);
    CHECK(automatic.trace.memory_enabled());
    CHECK(!automatic.trace.hexdump_enabled());
    CHECK(automatic.trace.lz4_level == 2);

    TraceConfig full_default_level = parse_trace_config("profile=full");
    CHECK(full_default_level.valid);
    CHECK(full_default_level.trace.lz4_level == 2);
    TraceConfig fast_explicit_level = parse_trace_config("lz4_level=7;profile=fast");
    CHECK(fast_explicit_level.valid);
    CHECK(fast_explicit_level.trace.lz4_level == 7);
    TraceConfig balanced_explicit_level = parse_trace_config("profile=balanced;lz4_level=0");
    CHECK(balanced_explicit_level.valid);
    CHECK(balanced_explicit_level.trace.lz4_level == 0);

    assert_invalid("profile=turbo;buffer_mb=512");
    assert_invalid("lz4_level=9oops");
    assert_invalid("lz4_level=13");
    assert_invalid("buffer_mb=7");
    assert_invalid("buffer_mb=129");
    assert_invalid("hexdump_limit=65");
    assert_invalid("compression=true");
    assert_invalid("unknown_option=1");

#ifndef NDEBUG
    TraceConfig test_failure = parse_trace_config("test_fail_setup=1");
    CHECK(test_failure.valid);
    CHECK(test_failure.test_fail_setup);

    TraceConfig test_buffer = parse_trace_config("test_buffer_bytes=4096");
    CHECK(test_buffer.valid);
    CHECK(!test_buffer.trace.auto_buffer_size);
    CHECK(test_buffer.trace.buffer_bytes == 4096);
    assert_invalid("test_buffer_bytes=4095");
#else
    const char release_test_failure[] = {
            't', 'e', 's', 't', '_', 'f', 'a', 'i', 'l', '_',
            's', 'e', 't', 'u', 'p', '=', '1', '\0'};
    assert_invalid(release_test_failure);
    const char release_test_buffer[] = "test_buffer_bytes=4096";
    assert_invalid(release_test_buffer);
#endif
}
