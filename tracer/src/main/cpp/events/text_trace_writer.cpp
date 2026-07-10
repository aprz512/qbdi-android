#include "events/text_trace_writer.h"
#include "core/logging.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

static bool mkdirs(const std::string &path) {
    if (path.empty() || path == "/") return true;
    if (mkdir(path.c_str(), 0755) == 0 || errno == EEXIST) return true;
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return false;
    if (!mkdirs(path.substr(0, slash))) return false;
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

static bool write_all(int fd, const char *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t result = write(fd, data + written, size - written);
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        written += static_cast<size_t>(result);
    }
    return true;
}

TextTraceWriter::TextTraceWriter(size_t flush_threshold) : flush_threshold_(flush_threshold) {
    buffer_.reserve(flush_threshold_ + 4096);
}

TextTraceWriter::~TextTraceWriter() {
    flush();
    if (fd_ >= 0) close(fd_);
}

bool TextTraceWriter::open(const TraceContext &context) {
    char dir[256];
    snprintf(dir, sizeof(dir), "/data/data/%s/files/qbdi-traces", context.package_name.c_str());
    if (!mkdirs(dir)) return false;

    auto now = std::chrono::system_clock::now().time_since_epoch();
    long long millis = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    char file[512];
    snprintf(file, sizeof(file), "%s/%lld_%d_%d_%s_0x%lx.trace.txt", dir, millis, context.pid,
             context.tid, context.scene_name.c_str(), static_cast<unsigned long>(context.target_offset));
    path_ = file;
    fd_ = ::open(path_.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    return fd_ >= 0;
}

void TextTraceWriter::begin(const TraceContext &context) {
    std::ostringstream out;
    out << "TRACE_BEGIN scene=" << context.scene_name
        << " target=" << context.target_so << "+0x" << std::hex << context.target_offset
        << " base=0x" << context.module_base
        << " address=0x" << context.target_address
        << " pid=" << std::dec << context.pid
        << " tid=" << context.tid << "\n";
    append(out.str());
}

void TextTraceWriter::instruction(const TraceContext &context, const InstructionText &inst) {
    std::ostringstream out;
    out << std::dec << inst.sequence << " " << context.target_so << "+0x" << std::hex
        << (inst.pc - context.module_base) << " " << inst.disassembly;
    if (!inst.reads.empty()) out << " | R:" << inst.reads;
    if (!inst.writes.empty()) out << " | W:" << inst.writes;
    for (const auto &mem : inst.memory) {
        out << " | MEM:" << mem.type << " addr=0x" << mem.address
            << " size=" << std::dec << mem.size << " value=0x" << std::hex << mem.value;
    }
    out << "\n";
    append(out.str());
}

void TextTraceWriter::memory(const TraceContext &context, uintptr_t pc, const MemoryAccessText &mem) {
    std::ostringstream out;
    out << "MEM " << context.target_so << "+0x" << std::hex << (pc - context.module_base)
        << " type=" << mem.type << " addr=0x" << mem.address
        << " size=" << std::dec << mem.size << " value=0x" << std::hex << mem.value << "\n";
    append(out.str());
}

void TextTraceWriter::call(const char *category, const std::string &name, const std::string &detail) {
    append(std::string("CALL ") + category + "." + name + " " + detail + "\n");
}

void TextTraceWriter::rule(const std::string &name, const std::string &detail) {
    append("RULE " + name + " " + detail + "\n");
}

void TextTraceWriter::error(const std::string &message) {
    append("ERROR " + message + "\n");
}

void TextTraceWriter::end(uint64_t retval, bool ok, long elapsed_ms) {
    std::ostringstream out;
    out << "TRACE_END status=" << (ok ? "ok" : "failed") << " ret=0x" << std::hex << retval
        << " elapsed_ms=" << std::dec << elapsed_ms << " bytes=" << buffer_.size() << "\n";
    append(out.str());
    flush();
}

void TextTraceWriter::append(const std::string &line) {
    buffer_ += line;
    if (buffer_.size() >= flush_threshold_) flush();
}

void TextTraceWriter::flush() {
    if (fd_ >= 0 && !buffer_.empty()) {
        if (!write_all(fd_, buffer_.data(), buffer_.size())) {
            QTRACE_E("trace write failed: %s", strerror(errno));
        }
        buffer_.clear();
    }
}
