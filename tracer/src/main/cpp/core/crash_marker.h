#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <signal.h>
#include <string>
#include <sys/types.h>

struct CrashMarker {
    uint32_t magic = 0;
    int32_t signal = 0;
    int32_t tid = 0;
};

constexpr uint32_t kCrashMarkerMagic = 0x51435248U;
static_assert(sizeof(CrashMarker) == 12);

bool valid_crash_marker(const CrashMarker &marker) noexcept;

void crash_marker_atfork_prepare() noexcept;
void crash_marker_atfork_parent() noexcept;
void crash_marker_atfork_child() noexcept;

#if defined(QTRACE_HOST_TEST)
void crash_marker_test_force_atfork_error(int error_code) noexcept;
#endif

class CrashMarkerSession {
public:
    CrashMarkerSession() = default;
    ~CrashMarkerSession();

    CrashMarkerSession(const CrashMarkerSession &) = delete;
    CrashMarkerSession &operator=(const CrashMarkerSession &) = delete;

    bool open(const std::string &trace_path) noexcept;
    bool finish() noexcept;
    int error_code() const noexcept { return error_code_; }

private:
    static constexpr size_t kSignalCount = 5;

    std::string path_;
    int fd_ = -1;
    int error_code_ = 0;
    std::array<struct sigaction, kSignalCount> previous_{};
    std::array<bool, kSignalCount> installed_{};
    size_t handler_slot_ = static_cast<size_t>(-1);
    bool opened_ = false;
    bool finish_called_ = false;
    bool finish_result_ = false;
    pid_t owner_pid_ = -1;
};
