#pragma once

#include "core/trace_config.h"
#include "events/async_trace_writer.h"
#include "events/binary_trace_encoder.h"
#include "events/trace_dictionary.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"
#include "events/trace_sink.h"

#include <cstdint>
#include <string>
#include <string_view>

class BinaryTraceWriter final : public TraceSink {
public:
    explicit BinaryTraceWriter(const TraceOptions &options, TraceMetrics *metrics,
                               TraceWriterBackend *backend = nullptr,
                               TraceFaultInjector *faults = nullptr);
    ~BinaryTraceWriter();

    BinaryTraceWriter(const BinaryTraceWriter &) = delete;
    BinaryTraceWriter &operator=(const BinaryTraceWriter &) = delete;

    bool open(const TraceContext &context);
    bool prepare(const TraceContext &context);
    bool open_prepared();
    bool begin(const TraceContext &context);
    bool instruction(const TraceContext &context, const InstructionRecord &record) override;
    bool memory(const TraceContext &context, uintptr_t pc, const MemoryRecord &record) override;
    bool call(const char *category, std::string_view name, std::string_view detail) override;
    bool rule(const std::string &name, const std::string &detail) override;
    bool error(const std::string &message) override;
    bool end(uint64_t retval, bool ok, long elapsed_ms);
    bool stop(TraceStopReason reason, long elapsed_ms);
    bool close();
    void detach_after_fork_child() noexcept;

    bool failed() const noexcept override { return !healthy_writer_state(); }
    int error_code() const noexcept;
    std::string_view path() const noexcept;

private:
    enum class TraceTermination : uint8_t { None, Completed, Stopped };

    bool healthy_writer_state() const;
    bool writable_event_state() const;
    bool append_call(const char *category, std::string_view name,
                     std::string_view detail);
    bool append_call_chunk(std::string_view category, std::string_view name,
                           std::string_view detail, const CallChunkInfo &chunk);
    bool append_event(BinaryRecordType type, std::string_view name,
                      std::string_view detail);
    bool append_event_chunk(BinaryRecordType type, std::string_view name,
                            std::string_view detail, const EventChunkInfo &chunk);
    bool finalize_terminal(TraceTermination termination, TraceStopReason stop_reason,
                          uint64_t retval, bool ok, long elapsed_ms);
    bool write_metrics_sidecar();
    bool fail(int error_code = 0);

    TraceOptions options_;
    TraceMetrics *metrics_ = nullptr;
    BinaryTraceEncoder encoder_;
    TraceDictionary dictionary_;
    AsyncTraceWriter writer_;
    TraceFaultInjector *faults_ = nullptr;
    static constexpr size_t kPathCapacity = 4096;
    char path_[kPathCapacity]{};
    size_t path_size_ = 0;
    uint64_t run_id_ = 0;
    uint64_t elapsed_ms_ = 0;
    uint64_t retval_ = 0;
    TraceStopReason stop_reason_{};
    size_t final_padding_bytes_ = 0;
    bool opened_ = false;
    bool began_ = false;
    TraceTermination termination_ = TraceTermination::None;
    bool return_valid_ = false;
    bool close_called_ = false;
    bool close_result_ = false;
    bool facade_failed_ = false;
    bool prepared_ = false;
    int facade_error_code_ = 0;
    uint64_t next_call_event_id_ = 1;
};

#if defined(QTRACE_HOST_TEST)
bool binary_trace_writer_test_default_output_directory(
        std::string_view package, uint32_t uid,
        char *output, size_t capacity) noexcept;
#endif
