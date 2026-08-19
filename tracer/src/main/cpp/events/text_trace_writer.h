#pragma once

#include "core/trace_config.h"
#include "events/async_trace_writer.h"
#include "events/trace_encoder.h"
#include "events/trace_event.h"
#include "events/trace_metrics.h"
#include "events/trace_record.h"

#include <string>
#include <string_view>

class TextTraceWriter {
public:
    explicit TextTraceWriter(const TraceOptions &options, TraceMetrics *metrics);
    ~TextTraceWriter();

    TextTraceWriter(const TextTraceWriter &) = delete;
    TextTraceWriter &operator=(const TextTraceWriter &) = delete;

    bool open(const TraceContext &context);
    bool begin(const TraceContext &context);
    bool instruction(const TraceContext &context, const InstructionRecord &record);
    bool memory(const TraceContext &context, uintptr_t pc, const MemoryRecord &record);
    bool call(const char *category, const std::string &name, const std::string &detail);
    bool rule(const std::string &name, const std::string &detail);
    bool error(const std::string &message);
    bool write_raw_line(const std::string &line);
    bool end(uint64_t retval, bool ok, long elapsed_ms);
    bool close();
    bool failed() const { return facade_failed_ || writer_.failed(); }

    const std::string &path() const { return path_; }

private:
    bool append_encoded_event(std::string_view event_type, std::string_view name,
                              std::string_view detail);
    bool write_metrics_sidecar() const;
    bool fail();

    TraceOptions options_;
    TraceMetrics *metrics_ = nullptr;
    TraceEncoder encoder_;
    AsyncTraceWriter writer_;
    std::string path_;
    uint64_t elapsed_ms_ = 0;
    bool opened_ = false;
    bool began_ = false;
    bool ended_ = false;
    bool close_called_ = false;
    bool close_result_ = false;
    bool facade_failed_ = false;
};
