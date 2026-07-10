#pragma once

#include "events/trace_event.h"

#include <cstddef>
#include <string>

class TextTraceWriter {
public:
    explicit TextTraceWriter(size_t flush_threshold = 1 << 20);

    ~TextTraceWriter();

    bool open(const TraceContext &context);

    void begin(const TraceContext &context);

    void instruction(const TraceContext &context, const InstructionText &inst);

    void memory(const TraceContext &context, uintptr_t pc, const MemoryAccessText &mem);

    void call(const char *category, const std::string &name, const std::string &detail);

    void rule(const std::string &name, const std::string &detail);

    void error(const std::string &message);

    void end(uint64_t retval, bool ok, long elapsed_ms);

    void flush();

    void write_crash_marker(int signal);

    const std::string &path() const { return path_; }

private:
    void append(const std::string &line);

    int fd_ = -1;
    size_t flush_threshold_;
    std::string buffer_;
    std::string path_;
};
