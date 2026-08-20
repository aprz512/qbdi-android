#include "events/text_trace_writer.h"

#include "core/logging.h"
#include "events/trace_number_formatter.h"

#include <cerrno>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr size_t kMaxTraceEndLineBytes = 512;
std::atomic<uint64_t> g_artifact_sequence{0};

bool mkdirs(const std::string &path) {
    if (path.empty() || path == "/") return true;
    if (::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST) return true;
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || !mkdirs(path.substr(0, slash))) return false;
    return ::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

bool write_all(int fd, const char *data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const ssize_t result = ::write(fd, data + offset, size - offset);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (result == 0) {
            errno = EIO;
            return false;
        }
        offset += static_cast<size_t>(result);
    }
    return true;
}

std::string trace_directory(const TraceContext &context) {
    if (!context.output_directory.empty()) return context.output_directory;
    return "/data/data/" + context.package_name + "/files/qbdi-traces";
}

std::string trace_filename(const TraceContext &context, bool compressed) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const long long millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char offset[2 * sizeof(uintptr_t) + 1]{};
    const int count = std::snprintf(offset, sizeof(offset), "%lx",
                                    static_cast<unsigned long>(context.target_offset));
    if (count < 0 || static_cast<size_t>(count) >= sizeof(offset)) return {};
    return std::to_string(millis) + "_" + std::to_string(context.pid) + "_" +
           std::to_string(context.tid) + "_" + context.scene_name + "_0x" + offset +
           "_" + std::to_string(g_artifact_sequence.fetch_add(1, std::memory_order_relaxed)) +
           (compressed ? ".trace.txt.lz4" : ".trace.txt");
}

TraceMetrics producer_metrics_snapshot(const TraceMetrics &metrics) {
    TraceMetrics snapshot{};
    snapshot.instructions = metrics.instructions;
    snapshot.raw_bytes = metrics.raw_bytes;
    snapshot.cache_hits = metrics.cache_hits;
    snapshot.cache_misses = metrics.cache_misses;
    snapshot.cache_collisions = metrics.cache_collisions;
    snapshot.buffer_swaps = metrics.buffer_swaps;
    snapshot.producer_waits = metrics.producer_waits;
    snapshot.producer_wait_ns = metrics.producer_wait_ns;
    return snapshot;
}

bool write_unsigned_metric(int fd, const char *key, uint64_t value) {
    char line[96];
    const int size = std::snprintf(line, sizeof(line), "%s=%llu\n", key,
                                   static_cast<unsigned long long>(value));
    return size > 0 && static_cast<size_t>(size) < sizeof(line) &&
           write_all(fd, line, static_cast<size_t>(size));
}

bool write_string_metric(int fd, const char *key, const char *value) {
    char line[96];
    const int size = std::snprintf(line, sizeof(line), "%s=%s\n", key, value);
    return size > 0 && static_cast<size_t>(size) < sizeof(line) &&
           write_all(fd, line, static_cast<size_t>(size));
}

bool write_hex_metric(int fd, const char *key, uint64_t value) {
    char line[96];
    const int size = std::snprintf(line, sizeof(line), "%s=0x%llx\n", key,
                                   static_cast<unsigned long long>(value));
    return size > 0 && static_cast<size_t>(size) < sizeof(line) &&
           write_all(fd, line, static_cast<size_t>(size));
}

const char *metrics_profile_name(TraceProfile profile) {
    switch (profile) {
        case TraceProfile::Fast: return "fast";
        case TraceProfile::Balanced: return "balanced";
        case TraceProfile::Full: return "full";
    }
    return "unknown";
}

bool write_rate_metric(int fd, const char *key, unsigned __int128 numerator,
                       unsigned __int128 denominator) {
    char line[128];
    size_t used = 0;
    while (key[used] != '\0') {
        if (used >= sizeof(line) - 1U) return false;
        line[used] = key[used];
        ++used;
    }
    if (used >= sizeof(line) - 1U) return false;
    line[used++] = '=';
    const FixedSixResult result =
        format_fixed_six(line + used, sizeof(line) - used - 1U, numerator, denominator);
    if (!result.ok) return false;
    used += result.size;
    line[used++] = '\n';
    return write_all(fd, line, used);
}

} // namespace

TextTraceWriter::TextTraceWriter(const TraceOptions &options, TraceMetrics *metrics,
                                 TraceWriterBackend *backend, TraceFaultInjector *faults)
    : options_(options), metrics_(metrics), writer_(backend, faults), faults_(faults) {}

TextTraceWriter::~TextTraceWriter() {
    close();
}

bool TextTraceWriter::fail(int error_code) {
    if (facade_error_code_ == 0) {
        if (error_code == 0) error_code = writer_.error_code();
        facade_error_code_ = error_code == 0 ? EIO : error_code;
    }
    facade_failed_ = true;
    return false;
}

int TextTraceWriter::error_code() const noexcept {
    const int writer_error = writer_.error_code();
    return facade_error_code_ != 0 ? facade_error_code_ : writer_error;
}

bool TextTraceWriter::healthy_writer_state() const {
    return !facade_failed_ && !writer_.failed();
}

bool TextTraceWriter::writable_event_state() const {
    return opened_ && began_ && !ended_ && !close_called_ && healthy_writer_state();
}

bool TextTraceWriter::open(const TraceContext &context) {
    return prepare(context) && open_prepared();
}

bool TextTraceWriter::prepare(const TraceContext &context) {
    if (opened_ || close_called_ || metrics_ == nullptr) return false;
    const std::string directory = trace_directory(context);
    const std::string filename = trace_filename(context, options_.compression_enabled);
    if (directory.empty() || filename.empty() || !mkdirs(directory)) return fail();

    path_ = directory + "/" + filename;
    prepared_ = true;
    return true;
}

bool TextTraceWriter::open_prepared() {
    if (!prepared_ || opened_ || close_called_ || metrics_ == nullptr) return false;
    *metrics_ = {};
    if (!writer_.open(path_, options_, metrics_)) {
        QTRACE_E("open trace file failed: %s", path_.c_str());
        return fail(writer_.error_code());
    }
    metrics_->effective_buffer_bytes = writer_.buffer_bytes();
    opened_ = true;
    return true;
}

bool TextTraceWriter::begin(const TraceContext &context) {
    if (!opened_ || began_ || ended_ || close_called_ || !healthy_writer_state()) return false;
    const size_t effective_buffer_bytes = writer_.buffer_bytes();
    if (effective_buffer_bytes == 0) return fail();
    const EncodeResult measured = encoder_.encode_begin(
        nullptr, 0, context, options_.profile, options_.compression_enabled, effective_buffer_bytes);
    if (measured.size == 0) return fail();
    std::string encoded(measured.size, '\0');
    const EncodeResult result = encoder_.encode_begin(
        encoded.data(), encoded.size(), context, options_.profile, options_.compression_enabled,
        effective_buffer_bytes);
    if (!result.ok || !writer_.append(encoded)) return fail();
    began_ = true;
    return true;
}

bool TextTraceWriter::instruction(const TraceContext &context, const InstructionRecord &record) {
    if (!writable_event_state()) return false;
    WritableSpan span = writer_.reserve(kMaxInstructionLineBytes);
    if (span.data == nullptr) return fail();
    const EncodeResult result =
        encoder_.encode_instruction(span.data, span.capacity, context.target_so.c_str(), record);
    if (!result.ok) {
        writer_.commit(0);
        return fail();
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();
    ++metrics_->instructions;
    return true;
}

bool TextTraceWriter::memory(const TraceContext &context, uintptr_t pc,
                             const MemoryRecord &record) {
    if (!writable_event_state()) return false;
    const uintptr_t relative_pc = pc >= context.module_base ? pc - context.module_base : 0;
    char encoded[kMaxInstructionLineBytes];
    const EncodeResult result = encoder_.encode_memory(encoded, sizeof(encoded),
                                                        context.target_so.c_str(), relative_pc,
                                                        record);
    if (!result.ok || !writer_.append(std::string_view(encoded, result.size))) return fail();
    return true;
}

bool TextTraceWriter::append_encoded_event(std::string_view event_type, std::string_view name,
                                           std::string_view detail) {
    if (!writable_event_state()) return false;
    const EncodeResult measured = encoder_.encode_event(nullptr, 0, event_type, name, detail);
    if (measured.size == 0) return fail();
    std::string encoded(measured.size, '\0');
    const EncodeResult result =
        encoder_.encode_event(encoded.data(), encoded.size(), event_type, name, detail);
    if (!result.ok || !writer_.append(encoded)) return fail();
    return true;
}

bool TextTraceWriter::call(const char *category, const std::string &name,
                           const std::string &detail) {
    if (!writable_event_state()) return false;
    std::string qualified_name = category == nullptr ? std::string{} : std::string(category);
    if (!qualified_name.empty() && !name.empty()) qualified_name.push_back('.');
    qualified_name += name;
    return append_encoded_event("CALL", qualified_name, detail);
}

bool TextTraceWriter::rule(const std::string &name, const std::string &detail) {
    if (!writable_event_state()) return false;
    return append_encoded_event("RULE", name, detail);
}

bool TextTraceWriter::error(const std::string &message) {
    if (!writable_event_state()) return false;
    return append_encoded_event("ERROR", {}, message);
}

bool TextTraceWriter::write_raw_line(const std::string &line) {
    if (!writable_event_state()) return false;
    const size_t size = !line.empty() && line.back() == '\n' ? line.size() - 1U : line.size();
    return append_encoded_event(std::string_view(line.data(), size), {}, {});
}

bool TextTraceWriter::end(uint64_t retval, bool ok, long elapsed_ms) {
    if (!opened_ || !began_ || ended_ || close_called_) return false;
    elapsed_ms_ = elapsed_ms > 0 ? static_cast<uint64_t>(elapsed_ms) : 0;
    retval_ = retval;
    if (!healthy_writer_state()) return false;
    WritableSpan span = writer_.reserve(kMaxTraceEndLineBytes);
    if (span.data == nullptr) return fail();

    TraceMetrics footer_metrics = producer_metrics_snapshot(*metrics_);
    ++footer_metrics.buffer_swaps;
    EncodeResult measured{};
    for (size_t attempt = 0; attempt < 32; ++attempt) {
        measured = encoder_.encode_end(nullptr, 0, ok, retval, elapsed_ms_, footer_metrics);
        if (measured.size == 0 || metrics_->raw_bytes >
                                      std::numeric_limits<uint64_t>::max() - measured.size) {
            writer_.commit(0);
            return fail();
        }
        const uint64_t final_raw_bytes = metrics_->raw_bytes + measured.size;
        if (footer_metrics.raw_bytes == final_raw_bytes) break;
        footer_metrics.raw_bytes = final_raw_bytes;
    }
    if (footer_metrics.raw_bytes != metrics_->raw_bytes + measured.size ||
        measured.size > span.capacity) {
        writer_.commit(0);
        return fail();
    }
    const EncodeResult result =
        encoder_.encode_end(span.data, span.capacity, ok, retval, elapsed_ms_, footer_metrics);
    if (!result.ok) {
        writer_.commit(0);
        return fail();
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();
    ended_ = true;
    successful_end_ = ok;
    return true;
}

bool TextTraceWriter::write_metrics_sidecar() {
    const std::string sidecar = path_ + ".metrics";
    const int fd = ::open(sidecar.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) return fail(errno);

    if (faults_ != nullptr) {
        const int injected = faults_->failure(FailurePoint::MetricsSidecar);
        if (injected != 0) {
            fail(injected);
            (void)::close(fd);
            (void)::unlink(sidecar.c_str());
            return false;
        }
    }

    bool ok = write_string_metric(fd, "profile", metrics_profile_name(options_.profile)) &&
              write_hex_metric(fd, "return", retval_) &&
              write_unsigned_metric(fd, "instructions", metrics_->instructions) &&
              write_unsigned_metric(fd, "elapsed_ms", elapsed_ms_) &&
              write_rate_metric(fd, "instructions_per_second",
                                static_cast<unsigned __int128>(metrics_->instructions) * 1000U,
                                elapsed_ms_) &&
              write_unsigned_metric(fd, "raw_bytes", metrics_->raw_bytes) &&
              write_unsigned_metric(fd, "compressed_bytes", metrics_->compressed_bytes) &&
              write_rate_metric(fd, "raw_bytes_per_second",
                                static_cast<unsigned __int128>(metrics_->raw_bytes) * 1000U,
                                elapsed_ms_) &&
              write_rate_metric(fd, "disk_bytes_per_second",
                                static_cast<unsigned __int128>(metrics_->compressed_bytes) * 1000U,
                                elapsed_ms_) &&
              write_rate_metric(fd, "compression_ratio", metrics_->compressed_bytes,
                                metrics_->raw_bytes) &&
              write_unsigned_metric(fd, "cache_hits", metrics_->cache_hits) &&
              write_unsigned_metric(fd, "cache_misses", metrics_->cache_misses) &&
              write_unsigned_metric(fd, "cache_collisions", metrics_->cache_collisions) &&
              write_rate_metric(fd, "cache_hit_rate", metrics_->cache_hits,
                                static_cast<unsigned __int128>(metrics_->cache_hits) +
                                    metrics_->cache_misses) &&
              write_unsigned_metric(fd, "buffer_swaps", metrics_->buffer_swaps) &&
              write_unsigned_metric(fd, "producer_waits", metrics_->producer_waits) &&
              write_unsigned_metric(fd, "producer_wait_ns", metrics_->producer_wait_ns) &&
              write_unsigned_metric(fd, "effective_buffer_bytes",
                                    metrics_->effective_buffer_bytes);
    int operation_error = ok ? 0 : (errno == 0 ? EIO : errno);
    if (::close(fd) != 0 && ok) {
        operation_error = errno == 0 ? EIO : errno;
        ok = false;
    }
    if (!ok) {
        ::unlink(sidecar.c_str());
        return fail(operation_error);
    }
    return ok;
}

bool TextTraceWriter::close() {
    if (close_called_) return close_result_;
    close_called_ = true;
    if (!opened_) return false;

    const bool trace_ok = writer_.finish();
    if (!trace_ok) fail(writer_.error_code());
    opened_ = false;
    const bool metrics_ok = !successful_end_ || !trace_ok || write_metrics_sidecar();
    if (!trace_ok) (void)::unlink((path_ + ".metrics").c_str());
    close_result_ = trace_ok && ended_ && healthy_writer_state() && metrics_ok;
    if (ended_ && !close_result_) facade_failed_ = true;
    return close_result_;
}
