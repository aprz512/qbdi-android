#include "core/session_status.h"

#include <cerrno>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr size_t kJsonCapacity = 65536;
constexpr size_t kPackageCapacity = 512;
std::atomic<uint64_t> g_status_publish_sequence{1};

#if defined(QTRACE_HOST_TEST)
struct StatusFault {
    SessionStatusFaultPoint point = SessionStatusFaultPoint::None;
    int error = 0;
};

StatusFault g_status_fault;

bool take_fault(SessionStatusFaultPoint point, int *error) noexcept {
    if (g_status_fault.point != point) return false;
    *error = g_status_fault.error == 0 ? EIO : g_status_fault.error;
    g_status_fault.point = SessionStatusFaultPoint::None;
    return true;
}
#endif

bool append_char(char *buffer, size_t capacity, size_t *used, char value) noexcept {
    if (*used >= capacity) return false;
    buffer[(*used)++] = value;
    return true;
}

bool append_text(char *buffer, size_t capacity, size_t *used, std::string_view text) noexcept {
    if (text.size() > capacity - *used) return false;
    std::memcpy(buffer + *used, text.data(), text.size());
    *used += text.size();
    return true;
}

bool append_unsigned(char *buffer, size_t capacity, size_t *used, uint64_t value) noexcept {
    char digits[32];
    const int count = std::snprintf(digits, sizeof(digits), "%llu",
                                    static_cast<unsigned long long>(value));
    return count > 0 && static_cast<size_t>(count) < sizeof(digits) &&
           append_text(buffer, capacity, used, std::string_view(digits, static_cast<size_t>(count)));
}

bool append_json_string(char *buffer, size_t capacity, size_t *used, std::string_view value) noexcept {
    if (!append_char(buffer, capacity, used, '"')) return false;
    for (unsigned char byte : value) {
        switch (byte) {
            case '"': if (!append_text(buffer, capacity, used, "\\\"")) return false; break;
            case '\\': if (!append_text(buffer, capacity, used, "\\\\")) return false; break;
            case '\b': if (!append_text(buffer, capacity, used, "\\b")) return false; break;
            case '\f': if (!append_text(buffer, capacity, used, "\\f")) return false; break;
            case '\n': if (!append_text(buffer, capacity, used, "\\n")) return false; break;
            case '\r': if (!append_text(buffer, capacity, used, "\\r")) return false; break;
            case '\t': if (!append_text(buffer, capacity, used, "\\t")) return false; break;
            default:
                if (byte < 0x20U) {
                    char escaped[7];
                    const int count = std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
                    if (count != 6 || !append_text(buffer, capacity, used,
                                                   std::string_view(escaped, 6))) return false;
                } else if (!append_char(buffer, capacity, used, static_cast<char>(byte))) {
                    return false;
                }
        }
    }
    return append_char(buffer, capacity, used, '"');
}

bool append_key(char *buffer, size_t capacity, size_t *used, std::string_view key) noexcept {
    return append_json_string(buffer, capacity, used, key) && append_char(buffer, capacity, used, ':');
}

bool append_issue_array(char *buffer, size_t capacity, size_t *used,
                        const std::vector<ConfigurationIssue> &issues) noexcept {
    if (!append_char(buffer, capacity, used, '[')) return false;
    for (size_t index = 0; index < issues.size(); ++index) {
        if (index != 0 && !append_char(buffer, capacity, used, ',')) return false;
        const ConfigurationIssue &issue = issues[index];
        if (!append_char(buffer, capacity, used, '{') ||
            !append_key(buffer, capacity, used, "code") ||
            !append_json_string(buffer, capacity, used, issue.code) ||
            !append_char(buffer, capacity, used, ',') ||
            !append_key(buffer, capacity, used, "path") ||
            !append_json_string(buffer, capacity, used, issue.path) ||
            !append_char(buffer, capacity, used, ',') ||
            !append_key(buffer, capacity, used, "message") ||
            !append_json_string(buffer, capacity, used, issue.message) ||
            !append_char(buffer, capacity, used, '}')) return false;
    }
    return append_char(buffer, capacity, used, ']');
}

bool package_name_is_safe(std::string_view value) noexcept {
    return value.size() <= kPackageCapacity && trace_package_name_is_valid(value);
}

bool session_id_is_uuid(std::string_view value) noexcept {
    return trace_session_id_is_uuid_v4(value);
}

bool artifact_name_is_safe(std::string_view value) noexcept {
    if (value.empty() || value.size() > 255 || value == "." || value == "..") return false;
    for (char character : value) {
        if (character == '/' || character == '\\' || character == '\0') return false;
    }
    return true;
}

bool string_is_valid_utf8(std::string_view value) noexcept {
    size_t index = 0;
    while (index < value.size()) {
        const unsigned char first = static_cast<unsigned char>(value[index++]);
        if (first <= 0x7fU) continue;
        size_t continuation_count = 0;
        uint32_t code_point = 0;
        uint32_t minimum = 0;
        if (first >= 0xc2U && first <= 0xdfU) {
            continuation_count = 1;
            code_point = first & 0x1fU;
            minimum = 0x80U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuation_count = 2;
            code_point = first & 0x0fU;
            minimum = 0x800U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuation_count = 3;
            code_point = first & 0x07U;
            minimum = 0x10000U;
        } else {
            return false;
        }
        if (continuation_count > value.size() - index) return false;
        for (size_t count = 0; count < continuation_count; ++count) {
            const unsigned char continuation = static_cast<unsigned char>(value[index++]);
            if ((continuation & 0xc0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (continuation & 0x3fU);
        }
        if (code_point < minimum || code_point > 0x10ffffU ||
            (code_point >= 0xd800U && code_point <= 0xdfffU)) return false;
    }
    return true;
}

bool snapshot_strings_are_utf8(const SessionStatusSnapshot &snapshot) noexcept {
    if (!string_is_valid_utf8(snapshot.session_id) || !string_is_valid_utf8(snapshot.package) ||
        !string_is_valid_utf8(snapshot.state) || !string_is_valid_utf8(snapshot.reason)) return false;
    for (const ResolvedSceneStatus &scene : snapshot.normalized_scenes) {
        if (!string_is_valid_utf8(scene.name)) return false;
    }
    for (const std::string &artifact : snapshot.artifacts) {
        if (!string_is_valid_utf8(artifact)) return false;
    }
    const auto issues_are_utf8 = [](const std::vector<ConfigurationIssue> &issues) noexcept {
        for (const ConfigurationIssue &issue : issues) {
            if (!string_is_valid_utf8(issue.code) || !string_is_valid_utf8(issue.path) ||
                !string_is_valid_utf8(issue.message)) return false;
        }
        return true;
    };
    return issues_are_utf8(snapshot.warnings) && issues_are_utf8(snapshot.errors);
}

bool write_all(int fd, const char *data, size_t size) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::PartialWrite, &fault)) {
        const size_t partial = size > 1 ? size / 2 : 1;
        if (::write(fd, data, partial) != static_cast<ssize_t>(partial)) return false;
        errno = fault;
        return false;
    }
#endif
    size_t offset = 0;
    while (offset < size) {
        const ssize_t count = ::write(fd, data + offset, size - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) {
            errno = EIO;
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    return true;
}

bool sync_file(int fd, bool directory) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    const SessionStatusFaultPoint point = directory ? SessionStatusFaultPoint::DirectoryFsync
                                                    : SessionStatusFaultPoint::FileFsync;
    if (take_fault(point, &fault)) {
        errno = fault;
        return false;
    }
#else
    (void)directory;
#endif
    return ::fsync(fd) == 0;
}

bool valid_state(std::string_view state) noexcept {
    return state == "installed" || state == "running" || state == "stop_requested" ||
           state == "stopping" || state == "sealed" || state == "stop_incomplete" ||
           state == "warning" || state == "error";
}

bool serialize_status(char *buffer, size_t capacity, size_t *used,
                      const SessionStatusSnapshot &snapshot) noexcept {
    if (snapshot.schema_version != 1 || !package_name_is_safe(snapshot.package) ||
        !session_id_is_uuid(snapshot.session_id) || !valid_state(snapshot.state)) {
        errno = EINVAL;
        return false;
    }
    for (const std::string &artifact : snapshot.artifacts) {
        if (!artifact_name_is_safe(artifact)) {
            errno = EINVAL;
            return false;
        }
    }
    if (!snapshot_strings_are_utf8(snapshot)) {
        errno = EINVAL;
        return false;
    }
    *used = 0;
    const auto comma = [&] { return append_char(buffer, capacity, used, ','); };
    if (!append_char(buffer, capacity, used, '{') ||
        !append_key(buffer, capacity, used, "schemaVersion") || !append_unsigned(buffer, capacity, used, snapshot.schema_version) || !comma() ||
        !append_key(buffer, capacity, used, "sessionId") || !append_json_string(buffer, capacity, used, snapshot.session_id) || !comma() ||
        !append_key(buffer, capacity, used, "generation") || !append_unsigned(buffer, capacity, used, snapshot.generation) || !comma() ||
        !append_key(buffer, capacity, used, "packageName") || !append_json_string(buffer, capacity, used, snapshot.package) || !comma() ||
        !append_key(buffer, capacity, used, "pid") || !append_unsigned(buffer, capacity, used, snapshot.pid) || !comma() ||
        !append_key(buffer, capacity, used, "state") || !append_json_string(buffer, capacity, used, snapshot.state) || !comma() ||
        !append_key(buffer, capacity, used, "reason") || !append_json_string(buffer, capacity, used, snapshot.reason) || !comma() ||
        !append_key(buffer, capacity, used, "transitionMonotonicNs") || !append_unsigned(buffer, capacity, used, snapshot.transition_monotonic_ns) || !comma() ||
        !append_key(buffer, capacity, used, "normalizedScenes") || !append_char(buffer, capacity, used, '[')) goto overflow;
    for (size_t index = 0; index < snapshot.normalized_scenes.size(); ++index) {
        const ResolvedSceneStatus &scene = snapshot.normalized_scenes[index];
        if ((index != 0 && !comma()) || !append_char(buffer, capacity, used, '{') ||
            !append_key(buffer, capacity, used, "name") || !append_json_string(buffer, capacity, used, scene.name) || !comma() ||
            !append_key(buffer, capacity, used, "startOffset") || !append_unsigned(buffer, capacity, used, scene.start_offset) || !comma() ||
            !append_key(buffer, capacity, used, "endOffset") || !append_unsigned(buffer, capacity, used, scene.end_offset) ||
            !append_char(buffer, capacity, used, '}')) goto overflow;
    }
    if (!append_char(buffer, capacity, used, ']') || !comma() ||
        !append_key(buffer, capacity, used, "activeScenes") || !append_char(buffer, capacity, used, '[')) goto overflow;
    for (size_t index = 0; index < snapshot.active_scenes.size(); ++index) {
        const SessionActiveScene &scene = snapshot.active_scenes[index];
        if ((index != 0 && !comma()) || !append_char(buffer, capacity, used, '{') ||
            !append_key(buffer, capacity, used, "sceneIndex") || !append_unsigned(buffer, capacity, used, scene.scene_index) || !comma() ||
            !append_key(buffer, capacity, used, "tid") || !append_unsigned(buffer, capacity, used, scene.tid) || !comma() ||
            !append_key(buffer, capacity, used, "sealed") || !append_text(buffer, capacity, used, scene.sealed ? "true" : "false") ||
            !append_char(buffer, capacity, used, '}')) goto overflow;
    }
    if (!append_char(buffer, capacity, used, ']') || !comma() ||
        !append_key(buffer, capacity, used, "artifacts") || !append_char(buffer, capacity, used, '[')) goto overflow;
    for (size_t index = 0; index < snapshot.artifacts.size(); ++index) {
        if ((index != 0 && !comma()) || !append_json_string(buffer, capacity, used, snapshot.artifacts[index])) goto overflow;
    }
    if (!append_char(buffer, capacity, used, ']') || !comma() ||
        !append_key(buffer, capacity, used, "stopAcknowledged") || !append_text(buffer, capacity, used, snapshot.stop_acknowledged ? "true" : "false") || !comma() ||
        !append_key(buffer, capacity, used, "warnings") || !append_issue_array(buffer, capacity, used, snapshot.warnings) || !comma() ||
        !append_key(buffer, capacity, used, "errors") || !append_issue_array(buffer, capacity, used, snapshot.errors) ||
        !append_char(buffer, capacity, used, '}')) goto overflow;
    return true;

overflow:
    errno = EOVERFLOW;
    return false;
}

} // namespace

#if defined(QTRACE_HOST_TEST)
void session_status_test_inject_fault(SessionStatusFaultPoint point, int error) noexcept {
    g_status_fault = StatusFault{point, error};
}
#endif

void SessionStatusPublisher::record_error(int error) noexcept {
    if (first_error_ == 0) first_error_ = error == 0 ? EIO : error;
}

bool SessionStatusPublisher::open(const TraceConfig &config, uint64_t generation,
                                  std::string_view output_directory) noexcept {
    opened_ = false;
    first_error_ = 0;
    if (!package_name_is_safe(config.package_name) || !session_id_is_uuid(config.session.id) ||
        generation == 0) {
        record_error(EINVAL);
        return false;
    }
    if (output_directory.size() >= sizeof(output_directory_)) {
        record_error(ENAMETOOLONG);
        return false;
    }
    const int directory_count = output_directory.empty()
            ? std::snprintf(output_directory_, sizeof(output_directory_), "/data/data/%s/files/qbdi-traces",
                            config.package_name.c_str())
            : std::snprintf(output_directory_, sizeof(output_directory_), "%.*s",
                            static_cast<int>(output_directory.size()), output_directory.data());
    if (directory_count <= 0 || static_cast<size_t>(directory_count) >= sizeof(output_directory_)) {
        record_error(ENAMETOOLONG);
        return false;
    }
    const int path_count = std::snprintf(path_, sizeof(path_), "%s/session-%s.status.json",
                                         output_directory_, config.session.id.c_str());
    if (path_count <= 0 || static_cast<size_t>(path_count) >= sizeof(path_)) {
        record_error(ENAMETOOLONG);
        return false;
    }
    path_size_ = static_cast<size_t>(path_count);
    std::memcpy(package_, config.package_name.data(), config.package_name.size());
    package_[config.package_name.size()] = '\0';
    std::memcpy(session_id_, config.session.id.data(), config.session.id.size());
    session_id_[config.session.id.size()] = '\0';
    generation_ = generation;
    opened_ = true;
    return true;
}

bool SessionStatusPublisher::publish(const SessionStatusSnapshot &snapshot) noexcept {
    if (!opened_ || snapshot.generation != generation_ || snapshot.package != package_ ||
        snapshot.session_id != session_id_) {
        record_error(EINVAL);
        return false;
    }
    char json[kJsonCapacity];
    size_t json_size = 0;
    if (!serialize_status(json, sizeof(json), &json_size, snapshot)) {
        record_error(errno);
        return false;
    }
    const unsigned long long pid = static_cast<unsigned long long>(::getpid());
    const unsigned long long sequence = static_cast<unsigned long long>(
            g_status_publish_sequence.fetch_add(1, std::memory_order_relaxed));
    char temporary[kPathCapacity];
    const int temporary_count = std::snprintf(temporary, sizeof(temporary), "%s.tmp.%llu.%llu",
                                               path_, pid, sequence);
    if (temporary_count <= 0 || static_cast<size_t>(temporary_count) >= sizeof(temporary)) {
        record_error(ENAMETOOLONG);
        return false;
    }
    const int fd = ::open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        record_error(errno);
        return false;
    }
    bool success = write_all(fd, json, json_size) && sync_file(fd, false);
    const int write_error = success ? 0 : errno;
    if (::close(fd) != 0 && success) {
        success = false;
        errno = errno == 0 ? EIO : errno;
    }
    if (!success) {
        (void)::unlink(temporary);
        record_error(write_error == 0 ? errno : write_error);
        return false;
    }

    const int directory_fd = ::open(output_directory_, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        const int error = errno;
        (void)::unlink(temporary);
        record_error(error);
        return false;
    }
    const int previous_result = ::access(path_, F_OK);
    if (previous_result != 0 && errno != ENOENT) {
        const int error = errno;
        (void)::close(directory_fd);
        (void)::unlink(temporary);
        record_error(error);
        return false;
    }
    const bool had_previous = previous_result == 0;
    if (had_previous) {
        const int backup_count = std::snprintf(backup_path_, sizeof(backup_path_), "%s.bak.%llu.%llu",
                                                path_, pid, sequence);
        if (backup_count <= 0 || static_cast<size_t>(backup_count) >= sizeof(backup_path_) ||
            ::link(path_, backup_path_) != 0) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
    }
#if defined(QTRACE_HOST_TEST)
    int rename_fault = 0;
    if (take_fault(SessionStatusFaultPoint::Rename, &rename_fault)) {
        errno = rename_fault;
        if (had_previous) (void)::unlink(backup_path_);
        (void)::close(directory_fd);
        (void)::unlink(temporary);
        record_error(rename_fault);
        return false;
    }
#endif
    if (::rename(temporary, path_) != 0) {
        const int error = errno;
        if (had_previous) (void)::unlink(backup_path_);
        (void)::close(directory_fd);
        (void)::unlink(temporary);
        record_error(error);
        return false;
    }
    if (!sync_file(directory_fd, true)) {
        const int error = errno;
        if (had_previous) {
            (void)::rename(backup_path_, path_);
            (void)sync_file(directory_fd, true);
        } else {
            (void)::unlink(path_);
            (void)sync_file(directory_fd, true);
        }
        (void)::close(directory_fd);
        record_error(error);
        return false;
    }
    if (had_previous) (void)::unlink(backup_path_);
    if (::close(directory_fd) != 0) {
        record_error(errno);
        return false;
    }
    return true;
}

std::string_view SessionStatusPublisher::path() const noexcept {
    return std::string_view(path_, path_size_);
}

int SessionStatusPublisher::error_code() const noexcept {
    return first_error_;
}
