#include "events/binary_trace_writer.h"

#include "core/instruction_cache.h"
#include "core/logging.h"
#include "core/trace_process_lifecycle.h"
#include "events/binary_trace_format.h"
#include "events/trace_number_formatter.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <cstring>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr uint32_t kTargetModuleId = 1;
std::atomic<uint64_t> g_binary_artifact_sequence{0};

bool is_utf8_continuation(unsigned char byte) {
    return (byte & 0xc0U) == 0x80U;
}

size_t call_chunk_end(std::string_view detail, size_t offset) {
    size_t end = offset + std::min(kBinaryMaxCallChunkDetailBytes,
                                   detail.size() - offset);
    if (end == detail.size()) return end;
    while (end > offset && is_utf8_continuation(
                                   static_cast<unsigned char>(detail[end]))) {
        --end;
    }
    // A valid UTF-8 code point is at most four bytes, so this fallback is reachable only for
    // arbitrary/non-UTF-8 bytes. Preserve those bytes exactly and keep progress bounded.
    return end == offset ? offset + kBinaryMaxCallChunkDetailBytes : end;
}

bool mkdirs(char *path) {
    if (path == nullptr || path[0] == '\0') {
        errno = EINVAL;
        return false;
    }
    for (char *cursor = path + 1; *cursor != '\0'; ++cursor) {
        if (*cursor != '/') continue;
        *cursor = '\0';
        if (::mkdir(path, 0755) != 0 && errno != EEXIST) {
            const int operation_error = errno;
            *cursor = '/';
            errno = operation_error;
            return false;
        }
        *cursor = '/';
    }
    if (::mkdir(path, 0755) == 0 || errno == EEXIST) return true;
    return false;
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

bool build_trace_directory(char *output, size_t capacity, const TraceContext &context) {
    const int count = context.output_directory.empty()
                              ? std::snprintf(output, capacity, "/data/data/%s/files/qbdi-traces",
                                              context.package_name.c_str())
                              : std::snprintf(output, capacity, "%s",
                                              context.output_directory.c_str());
    if (count < 0 || static_cast<size_t>(count) >= capacity) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}

bool build_trace_filename(char *output, size_t capacity, const TraceContext &context,
                          bool compressed, uint64_t sequence) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const long long millis =
            std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    const int count = std::snprintf(
            output, capacity, "%lld_%d_%d_%s_0x%lx_%llu%s", millis, context.pid, context.tid,
            context.scene_name.c_str(), static_cast<unsigned long>(context.target_offset),
            static_cast<unsigned long long>(sequence),
            compressed ? ".trace.bin.lz4" : ".trace.bin");
    if (count < 0 || static_cast<size_t>(count) >= capacity) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}

TraceMetrics producer_metrics_snapshot(const TraceMetrics &metrics) {
    TraceMetrics snapshot{};
    snapshot.instructions = metrics.instructions;
    snapshot.encoded_bytes = metrics.encoded_bytes;
    snapshot.cache_hits = metrics.cache_hits;
    snapshot.cache_misses = metrics.cache_misses;
    snapshot.cache_collisions = metrics.cache_collisions;
    snapshot.buffer_swaps = metrics.buffer_swaps;
    snapshot.producer_waits = metrics.producer_waits;
    snapshot.producer_wait_ns = metrics.producer_wait_ns;
    snapshot.effective_buffer_bytes = metrics.effective_buffer_bytes;
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

const char *profile_name(TraceProfile profile) {
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

BinaryTraceWriter::BinaryTraceWriter(const TraceOptions &options, TraceMetrics *metrics,
                                     TraceWriterBackend *backend, TraceFaultInjector *faults)
    : options_(options), metrics_(metrics), dictionary_(), writer_(backend, faults),
      faults_(faults) {}

BinaryTraceWriter::~BinaryTraceWriter() {
    if (trace_process_child_detached()) {
        detach_after_fork_child();
        return;
    }
    close();
}

std::string_view BinaryTraceWriter::path() const noexcept {
    return {path_, path_size_};
}

void BinaryTraceWriter::detach_after_fork_child() noexcept {
    writer_.detach_after_fork_child();
    path_[0] = '\0';
    path_size_ = 0;
    opened_ = false;
    close_called_ = true;
    close_result_ = true;
}

bool BinaryTraceWriter::fail(int error_code) {
    if (facade_error_code_ == 0) {
        if (error_code == 0) error_code = writer_.error_code();
        facade_error_code_ = error_code == 0 ? EIO : error_code;
    }
    facade_failed_ = true;
    return false;
}

int BinaryTraceWriter::error_code() const noexcept {
    const int writer_error = writer_.error_code();
    return facade_error_code_ != 0 ? facade_error_code_ : writer_error;
}

bool BinaryTraceWriter::healthy_writer_state() const {
    return !facade_failed_ && !writer_.failed();
}

bool BinaryTraceWriter::writable_event_state() const {
    return opened_ && began_ && !ended_ && !close_called_ && healthy_writer_state();
}

bool BinaryTraceWriter::open(const TraceContext &context) {
    return prepare(context) && open_prepared();
}

bool BinaryTraceWriter::prepare(const TraceContext &context) {
    if (prepared_ || opened_ || close_called_ || metrics_ == nullptr)
        return false;
    if (faults_ != nullptr) {
        const int injected = faults_->failure(FailurePoint::PathSetup);
        if (injected != 0) return fail(injected);
    }
    char directory[kPathCapacity];
    char filename[kPathCapacity];
    if (!build_trace_directory(directory, sizeof(directory), context)) return fail(errno);
    if (faults_ != nullptr) {
        const int injected = faults_->failure(FailurePoint::DirectoryCreation);
        if (injected != 0) return fail(injected);
    }
    if (!mkdirs(directory)) return fail(errno == 0 ? EIO : errno);
    const uint64_t sequence =
            g_binary_artifact_sequence.fetch_add(1, std::memory_order_relaxed);
    if (!build_trace_filename(filename, sizeof(filename), context,
                              options_.compression_enabled, sequence)) {
        return fail(errno);
    }
    const int path_count = std::snprintf(path_, sizeof(path_), "%s/%s", directory, filename);
    if (path_count < 0 || static_cast<size_t>(path_count) >= sizeof(path_)) {
        path_[0] = '\0';
        return fail(ENAMETOOLONG);
    }
    path_size_ = static_cast<size_t>(path_count);
    run_id_ = sequence;
    prepared_ = true;
    return true;
}

bool BinaryTraceWriter::open_prepared() {
    if (!prepared_ || opened_ || close_called_ || metrics_ == nullptr)
        return false;
    *metrics_ = {};
    dictionary_.reset();
    if (!writer_.open(path(), options_, metrics_)) {
        QTRACE_E("open binary trace file failed: %s", path_);
        return fail(writer_.error_code());
    }
    metrics_->effective_buffer_bytes = writer_.buffer_bytes();
    opened_ = true;
    return true;
}

bool BinaryTraceWriter::begin(const TraceContext &context) {
    if (!opened_ || began_ || ended_ || close_called_ || !healthy_writer_state()) return false;

    WritableSpan span = writer_.reserve(kBinaryStreamHeaderBytes);
    if (span.data == nullptr) return fail();
    BinaryEncodeResult result = encoder_.encode_stream_header(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, options_.profile);
    if (!result.ok) {
        writer_.commit(0);
        return fail();
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();

    span = writer_.reserve(kBinaryMaxTraceBeginRecordBytes);
    if (span.data == nullptr) return fail();
    TraceBeginInfo info{};
    info.profile = options_.profile;
    info.compression_enabled = options_.compression_enabled;
    info.run_id = run_id_;
    info.effective_buffer_bytes = writer_.buffer_bytes();
    result = encoder_.encode_begin(reinterpret_cast<uint8_t *>(span.data), span.capacity,
                                   context, info);
    if (!result.ok) {
        writer_.commit(0);
        return fail();
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();

    span = writer_.reserve(kBinaryMaxModuleDefinitionRecordBytes);
    if (span.data == nullptr) return fail();
    result = encoder_.encode_module_definition(reinterpret_cast<uint8_t *>(span.data),
                                                span.capacity, kTargetModuleId,
                                                context.target_so, context.module_base);
    if (!result.ok) {
        writer_.commit(0);
        return fail();
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();
    began_ = true;
    return true;
}

bool BinaryTraceWriter::instruction(const TraceContext &context, const InstructionRecord &record) {
    if (!writable_event_state()) return false;
    if (record.decoded == nullptr) return fail(EINVAL);
    if (record.memory_count > record.memory.size()) return fail(EINVAL);
    uint32_t metadata_id = 0;
    bool needs_definition = false;
    if (!dictionary_.resolve(record.decoded->opcode, &metadata_id, &needs_definition))
        return fail(EOVERFLOW);
    if (needs_definition) {
        WritableSpan definition_span = writer_.reserve(kBinaryMaxInstructionDefinitionRecordBytes);
        if (definition_span.data == nullptr) return fail();
        const BinaryEncodeResult definition = encoder_.encode_instruction_definition(
                reinterpret_cast<uint8_t *>(definition_span.data), definition_span.capacity,
                metadata_id, *record.decoded);
        if (!definition.ok) {
            writer_.commit(0);
            return fail(EINVAL);
        }
        writer_.commit(definition.size);
        if (writer_.failed()) return fail();
        if (!dictionary_.commit_instruction_definition(record.decoded->opcode, metadata_id))
            return fail(EOVERFLOW);
    }

    WritableSpan span = writer_.reserve(kBinaryMaxInstructionRecordBytes);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_instruction(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, kTargetModuleId, metadata_id,
            record);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    if (writer_.failed()) return fail();
    ++metrics_->instructions;
    for (size_t index = 0; index < record.memory_count; ++index) {
        if (!memory(context, record.pc, record.memory[index])) return false;
    }
    return true;
}

bool BinaryTraceWriter::memory(const TraceContext &context, uintptr_t pc,
                               const MemoryRecord &record) {
    if (!writable_event_state()) return false;
    const uintptr_t relative_pc = pc >= context.module_base ? pc - context.module_base : 0;
    WritableSpan span = writer_.reserve(kBinaryMaxMemoryRecordBytes);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_memory(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, kTargetModuleId, relative_pc,
            record);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    return writer_.failed() ? fail() : true;
}

bool BinaryTraceWriter::append_call(const char *category, std::string_view name,
                                    std::string_view detail) {
    if (!writable_event_state()) return false;
    const std::string_view category_view = category == nullptr ? std::string_view{} : category;
    if (category_view.size() > kBinaryMaxCallCategoryBytes ||
        name.size() > kBinaryMaxCallNameBytes || detail.size() > kBinaryMaxEventDetailBytes) {
        return fail(EINVAL);
    }
    const size_t maximum = kBinaryRecordHeaderBytes + kBinaryCallFixedPayloadBytes +
                           category_view.size() + name.size() + detail.size();
    WritableSpan span = writer_.reserve(maximum);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_call(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, category_view, name, detail);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    return writer_.failed() ? fail() : true;
}

bool BinaryTraceWriter::append_call_chunk(std::string_view category, std::string_view name,
                                          std::string_view detail,
                                          const CallChunkInfo &chunk) {
    const size_t maximum = kBinaryRecordHeaderBytes + kBinaryCallChunkFixedPayloadBytes +
                           category.size() + name.size() + detail.size();
    WritableSpan span = writer_.reserve(maximum);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_call_chunk(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, chunk, category, name,
            detail);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    return writer_.failed() ? fail() : true;
}

bool BinaryTraceWriter::call(const char *category, std::string_view name,
                             std::string_view detail) {
    if (!writable_event_state()) return false;
    const std::string_view category_view = category == nullptr ? std::string_view{} : category;
    if (category_view.size() > kBinaryMaxCallCategoryBytes ||
        name.size() > kBinaryMaxCallNameBytes ||
        detail.size() > kBinaryMaxLogicalCallDetailBytes) {
        return fail(EINVAL);
    }
    if (detail.size() <= kBinaryMaxCallChunkDetailBytes) {
        return append_call(category, name, detail);
    }

    size_t chunk_count = 0;
    for (size_t offset = 0; offset < detail.size();
         offset = call_chunk_end(detail, offset)) {
        ++chunk_count;
    }
    if (chunk_count > UINT16_MAX) return fail(EINVAL);

    uint64_t event_id = next_call_event_id_++;
    if (event_id == 0) event_id = next_call_event_id_++;
    size_t offset = 0;
    for (size_t index = 0; index < chunk_count; ++index) {
        const size_t end = call_chunk_end(detail, offset);
        const CallChunkInfo chunk{event_id, static_cast<uint32_t>(detail.size()),
                                  static_cast<uint16_t>(index),
                                  static_cast<uint16_t>(chunk_count)};
        if (!append_call_chunk(category_view, name, detail.substr(offset, end - offset),
                               chunk)) {
            return false;
        }
        offset = end;
    }
    return true;
}

bool BinaryTraceWriter::append_event(BinaryRecordType type, std::string_view name,
                                     std::string_view detail) {
    if (!writable_event_state()) return false;
    if (name.size() > kBinaryMaxEventNameBytes || detail.size() > kBinaryMaxEventDetailBytes)
        return fail(EINVAL);
    if (detail.size() > kBinaryMaxEventChunkDetailBytes) {
        size_t chunk_count = 0;
        for (size_t offset = 0; offset < detail.size();
             offset = call_chunk_end(detail, offset)) {
            ++chunk_count;
        }
        if (chunk_count < 2 || chunk_count > UINT16_MAX) return fail(EINVAL);
        uint64_t event_id = next_call_event_id_++;
        if (event_id == 0) event_id = next_call_event_id_++;
        size_t offset = 0;
        for (size_t index = 0; index < chunk_count; ++index) {
            const size_t end = call_chunk_end(detail, offset);
            const EventChunkInfo chunk{event_id, static_cast<uint32_t>(detail.size()),
                                       static_cast<uint16_t>(index),
                                       static_cast<uint16_t>(chunk_count)};
            if (!append_event_chunk(type, name, detail.substr(offset, end - offset), chunk))
                return false;
            offset = end;
        }
        return true;
    }
    const size_t maximum = kBinaryRecordHeaderBytes + kBinaryRuleErrorFixedPayloadBytes +
                           name.size() + detail.size();
    WritableSpan span = writer_.reserve(maximum);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_event(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, type, name, detail);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    return writer_.failed() ? fail() : true;
}

bool BinaryTraceWriter::append_event_chunk(BinaryRecordType type, std::string_view name,
                                           std::string_view detail,
                                           const EventChunkInfo &chunk) {
    const size_t maximum = kBinaryRecordHeaderBytes + kBinaryEventChunkFixedPayloadBytes +
                           name.size() + detail.size();
    WritableSpan span = writer_.reserve(maximum);
    if (span.data == nullptr) return fail();
    const BinaryEncodeResult result = encoder_.encode_event_chunk(
            reinterpret_cast<uint8_t *>(span.data), span.capacity, type, chunk, name, detail);
    if (!result.ok) {
        writer_.commit(0);
        return fail(EINVAL);
    }
    writer_.commit(result.size);
    return writer_.failed() ? fail() : true;
}

bool BinaryTraceWriter::rule(const std::string &name, const std::string &detail) {
    return append_event(BinaryRecordType::Rule, name, detail);
}

bool BinaryTraceWriter::error(const std::string &message) {
    return append_event(BinaryRecordType::Error, {}, message);
}

bool BinaryTraceWriter::end(uint64_t retval, bool ok, long elapsed_ms) {
    if (!opened_ || !began_ || ended_ || close_called_) return false;
    elapsed_ms_ = elapsed_ms > 0 ? static_cast<uint64_t>(elapsed_ms) : 0;
    retval_ = retval;
    if (!healthy_writer_state()) return false;
    if (!writer_.drain()) return fail(writer_.error_code());
    TraceMetrics footer_metrics = producer_metrics_snapshot(*metrics_);
    footer_metrics.encoded_bytes += kBinaryTraceEndRecordBytes;
    ++footer_metrics.buffer_swaps;
    if (!writer_.final_file_target(kBinaryTraceEndRecordBytes,
                                   &footer_metrics.compressed_bytes)) {
        return fail(writer_.error_code());
    }
    uint8_t footer[kBinaryTraceEndRecordBytes];
    const BinaryEncodeResult result = encoder_.encode_end(
            footer, sizeof(footer), ok, retval, elapsed_ms_, footer_metrics);
    if (!result.ok || result.size != sizeof(footer)) return fail(EINVAL);
    if (!writer_.final_frame_padding(
                {reinterpret_cast<const char *>(footer), sizeof(footer)},
                &final_padding_bytes_)) {
        return fail(writer_.error_code());
    }
    WritableSpan span = writer_.reserve(sizeof(footer));
    if (span.data == nullptr) return fail();
    std::memcpy(span.data, footer, sizeof(footer));
    writer_.commit(sizeof(footer));
    if (writer_.failed()) return fail();
    ended_ = true;
    successful_end_ = ok;
    return true;
}

bool BinaryTraceWriter::write_metrics_sidecar() {
    if (path_size_ == 0) return fail(ECHILD);
    char sidecar[kPathCapacity + sizeof(".metrics")];
    const int sidecar_size = std::snprintf(sidecar, sizeof(sidecar), "%s.metrics", path_);
    if (sidecar_size < 0 || static_cast<size_t>(sidecar_size) >= sizeof(sidecar))
        return fail(ENAMETOOLONG);
    const int fd = ::open(sidecar, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) return fail(errno);
    if (faults_ != nullptr) {
        const int injected = faults_->failure(FailurePoint::MetricsSidecar);
        if (injected != 0) {
            fail(injected);
            (void)::close(fd);
            (void)::unlink(sidecar);
            return false;
        }
    }

    const bool ok =
            write_unsigned_metric(fd, "metrics_version", 2) &&
            write_string_metric(fd, "profile", profile_name(options_.profile)) &&
            write_hex_metric(fd, "return", retval_) &&
            write_unsigned_metric(fd, "instructions", metrics_->instructions) &&
            write_unsigned_metric(fd, "elapsed_ms", elapsed_ms_) &&
            write_rate_metric(fd, "instructions_per_second",
                              static_cast<unsigned __int128>(metrics_->instructions) * 1000U,
                              elapsed_ms_) &&
            write_unsigned_metric(fd, "encoded_bytes", metrics_->encoded_bytes) &&
            write_unsigned_metric(fd, "compressed_bytes", metrics_->compressed_bytes) &&
            write_rate_metric(fd, "encoded_bytes_per_second",
                              static_cast<unsigned __int128>(metrics_->encoded_bytes) * 1000U,
                              elapsed_ms_) &&
            write_rate_metric(fd, "disk_bytes_per_second",
                              static_cast<unsigned __int128>(metrics_->compressed_bytes) * 1000U,
                              elapsed_ms_) &&
            write_rate_metric(fd, "compression_ratio", metrics_->compressed_bytes,
                              metrics_->encoded_bytes) &&
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
    bool close_ok = ::close(fd) == 0;
    if (!close_ok && ok) operation_error = errno == 0 ? EIO : errno;
    if (!ok || !close_ok) {
        (void)::unlink(sidecar);
        return fail(operation_error);
    }
    return true;
}

bool BinaryTraceWriter::close() {
    if (close_called_) return close_result_;
    close_called_ = true;
    if (!opened_) return false;
    const bool trace_ok = writer_.finish(final_padding_bytes_);
    if (!trace_ok) fail(writer_.error_code());
    opened_ = false;
    const bool metrics_ok = !successful_end_ || !trace_ok || write_metrics_sidecar();
    if ((!trace_ok || !metrics_ok) && path_size_ != 0) {
        char sidecar[kPathCapacity + sizeof(".metrics")];
        const int sidecar_size = std::snprintf(sidecar, sizeof(sidecar), "%s.metrics", path_);
        if (sidecar_size > 0 && static_cast<size_t>(sidecar_size) < sizeof(sidecar))
            (void)::unlink(sidecar);
    }
    close_result_ = trace_ok && ended_ && healthy_writer_state() && metrics_ok;
    if (ended_ && !close_result_) facade_failed_ = true;
    return close_result_;
}
