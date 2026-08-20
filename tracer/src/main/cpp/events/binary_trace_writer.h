#pragma once

#include "core/trace_config.h"
#include "events/async_trace_writer.h"
#include "events/binary_trace_encoder.h"
#include "events/trace_dictionary.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"

#include <cstdint>
#include <string>

class BinaryTraceWriter {
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
    bool instruction(const TraceContext &context, const InstructionRecord &record);
    bool memory(const TraceContext &context, uintptr_t pc, const MemoryRecord &record);
    bool call(const char *category, const std::string &name, const std::string &detail);
    bool rule(const std::string &name, const std::string &detail);
    bool error(const std::string &message);
    bool end(uint64_t retval, bool ok, long elapsed_ms);
    bool close();
    void detach_after_fork_child() noexcept;

    bool failed() const { return !healthy_writer_state(); }
    int error_code() const noexcept;
    const std::string &path() const;

private:
    bool healthy_writer_state() const;
    bool writable_event_state() const;
    bool append_call(const char *category, const std::string &name,
                     const std::string &detail);
    bool append_event(BinaryRecordType type, std::string_view name,
                      std::string_view detail);
    bool write_metrics_sidecar();
    bool fail(int error_code = 0);

    TraceOptions options_;
    TraceMetrics *metrics_ = nullptr;
    BinaryTraceEncoder encoder_;
    TraceDictionary dictionary_;
    AsyncTraceWriter writer_;
    TraceFaultInjector *faults_ = nullptr;
    std::string *path_ = nullptr;
    uint64_t run_id_ = 0;
    uint64_t elapsed_ms_ = 0;
    uint64_t retval_ = 0;
    bool opened_ = false;
    bool began_ = false;
    bool ended_ = false;
    bool successful_end_ = false;
    bool close_called_ = false;
    bool close_result_ = false;
    bool facade_failed_ = false;
    bool prepared_ = false;
    int facade_error_code_ = 0;
};
