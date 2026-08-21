#pragma once

#include "events/trace_event.h"
#include "events/trace_record.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

class TraceSink {
public:
    virtual ~TraceSink() = default;

    virtual bool instruction(const TraceContext &, const InstructionRecord &) = 0;
    virtual bool memory(const TraceContext &, uintptr_t, const MemoryRecord &) = 0;
    virtual bool call(const char *, std::string_view, std::string_view) = 0;
    virtual bool rule(const std::string &, const std::string &) = 0;
    virtual bool error(const std::string &) = 0;
    virtual bool failed() const noexcept = 0;
};
