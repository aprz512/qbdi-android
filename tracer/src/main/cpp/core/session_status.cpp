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
StatusFault g_followup_status_fault;

bool take_fault(SessionStatusFaultPoint point, int *error) noexcept {
    StatusFault *fault = g_status_fault.point == point ? &g_status_fault
                                                        : &g_followup_status_fault;
    if (fault->point != point) return false;
    *error = fault->error == 0 ? EIO : fault->error;
    fault->point = SessionStatusFaultPoint::None;
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
    for (unsigned char character : value) {
        if (character == '/' || character == '\\' || character < 0x20U || character == 0x7fU)
            return false;
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

bool sync_file(int fd, bool directory) noexcept;

bool copy_regular_file(const char *source, const char *destination) noexcept {
    const int source_fd = ::open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_fd < 0) return false;
    struct stat source_status{};
    if (::fstat(source_fd, &source_status) != 0) {
        const int error = errno;
        (void)::close(source_fd);
        errno = error;
        return false;
    }
    if (!S_ISREG(source_status.st_mode) || source_status.st_size <= 0 ||
        static_cast<uint64_t>(source_status.st_size) > kJsonCapacity) {
        (void)::close(source_fd);
        errno = EINVAL;
        return false;
    }
    const int destination_fd = ::open(destination,
                                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                                      0600);
    if (destination_fd < 0) {
        const int error = errno;
        (void)::close(source_fd);
        errno = error;
        return false;
    }

    bool success = true;
    off_t remaining = source_status.st_size;
    char buffer[4096];
    while (success && remaining > 0) {
        const size_t requested = static_cast<size_t>(
                remaining < static_cast<off_t>(sizeof(buffer))
                        ? remaining
                        : static_cast<off_t>(sizeof(buffer)));
        ssize_t count = 0;
        do {
            count = ::read(source_fd, buffer, requested);
        } while (count < 0 && errno == EINTR);
        if (count <= 0 || !write_all(destination_fd, buffer,
                                     static_cast<size_t>(count))) {
            if (count == 0) errno = EIO;
            success = false;
            break;
        }
        remaining -= count;
    }
    if (success) {
        char extra = 0;
        ssize_t count = 0;
        do {
            count = ::read(source_fd, &extra, 1);
        } while (count < 0 && errno == EINTR);
        if (count != 0) {
            if (count > 0) errno = EFBIG;
            success = false;
        }
    }
    if (success && !sync_file(destination_fd, false)) success = false;
    const int operation_error = success ? 0 : (errno == 0 ? EIO : errno);
    if (::close(destination_fd) != 0 && success) {
        success = false;
        errno = errno == 0 ? EIO : errno;
    }
    if (::close(source_fd) != 0 && success) {
        success = false;
        errno = errno == 0 ? EIO : errno;
    }
    if (!success) {
        const int error = operation_error == 0 ? errno : operation_error;
        (void)::unlink(destination);
        errno = error;
    }
    return success;
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

bool rollback_rename(const char *from, const char *to) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::RollbackRename, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::rename(from, to) == 0;
}

bool rollback_unlink(const char *path) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::RollbackUnlink, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::unlink(path) == 0;
}

bool rollback_directory_sync(int directory_fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::RollbackDirFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(directory_fd) == 0;
}

bool marker_file_sync(int fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::MarkerFileFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(fd) == 0;
}

bool marker_prepare_directory_sync(int directory_fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::MarkerPrepareDirFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(directory_fd) == 0;
}

bool marker_commit_rename(const char *from, const char *to) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::MarkerCommitRename, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::rename(from, to) == 0;
}

bool marker_commit_directory_sync(int directory_fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::MarkerCommitDirFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(directory_fd) == 0;
}

bool backup_prepare_directory_sync(int directory_fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::BackupPrepareDirFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(directory_fd) == 0;
}

bool backup_cleanup_directory_sync(int directory_fd) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (take_fault(SessionStatusFaultPoint::BackupCleanupDirFsync, &fault)) {
        errno = fault;
        return false;
    }
#endif
    return ::fsync(directory_fd) == 0;
}

bool create_marker(const char *path, int directory_fd, bool recreate = false) noexcept {
#if defined(QTRACE_HOST_TEST)
    int fault = 0;
    if (recreate && take_fault(SessionStatusFaultPoint::MarkerRecreateOpen, &fault)) {
        errno = fault;
        return false;
    }
#else
    (void)recreate;
#endif
    const int marker_fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker_fd < 0) return false;
#if defined(QTRACE_HOST_TEST)
    if (recreate && take_fault(SessionStatusFaultPoint::MarkerRecreateFileFsync, &fault)) {
        const int error = fault;
        (void)::close(marker_fd);
        (void)::unlink(path);
        errno = error;
        return false;
    }
#endif
    if (!marker_file_sync(marker_fd)) {
        const int error = errno;
        (void)::close(marker_fd);
        errno = error;
        return false;
    }
    if (::close(marker_fd) != 0) return false;
    return marker_prepare_directory_sync(directory_fd);
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
        !append_key(buffer, capacity, used, "deadlineMonotonicNs") || !append_unsigned(buffer, capacity, used, snapshot.deadline_monotonic_ns) || !comma() ||
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
    g_followup_status_fault = StatusFault{};
}

void session_status_test_inject_followup_fault(SessionStatusFaultPoint point, int error) noexcept {
    g_followup_status_fault = StatusFault{point, error};
}
#endif

bool session_status_artifact_basename_is_valid(std::string_view value) noexcept {
    return artifact_name_is_safe(value);
}

bool session_status_string_is_valid_utf8(std::string_view value) noexcept {
    return string_is_valid_utf8(value);
}

void SessionStatusPublisher::record_error(int error) noexcept {
    if (first_error_ == 0) first_error_ = error == 0 ? EIO : error;
}

void SessionStatusPublisher::record_recovery_error(int error) noexcept {
    if (recovery_error_ == 0) recovery_error_ = error == 0 ? EIO : error;
}

bool SessionStatusPublisher::recover_pending_transaction() noexcept {
    const int directory_fd = ::open(output_directory_, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        record_recovery_error(errno);
        return false;
    }
    const auto inspect = [this](const char *path, bool *exists) noexcept {
        if (::access(path, F_OK) == 0) {
            *exists = true;
            return true;
        }
        if (errno == ENOENT) {
            *exists = false;
            return true;
        }
        record_recovery_error(errno);
        return false;
    };
    bool main_exists = false;
    bool backup_exists = false;
    bool backup_prepare_exists = false;
    bool restore_exists = false;
    bool rollback_exists = false;
    bool commit_exists = false;
    if (!inspect(path_, &main_exists) || !inspect(backup_path_, &backup_exists) ||
        !inspect(backup_prepare_path_, &backup_prepare_exists) ||
        !inspect(restore_path_, &restore_exists) || !inspect(rollback_path_, &rollback_exists) ||
        !inspect(commit_path_, &commit_exists)) {
        (void)::close(directory_fd);
        return false;
    }
    if (rollback_exists && commit_exists) {
        record_recovery_error(EINVAL);
        (void)::close(directory_fd);
        return false;
    }

    // The live status remains authoritative until the completed backup copy is
    // renamed away from this prepare name. A crash residue here is therefore
    // never rollback evidence and must not block the next bounded copy.
    if (backup_prepare_exists) {
        if (!rollback_unlink(backup_prepare_path_) ||
            !rollback_directory_sync(directory_fd)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
    }

    // Migrate marker-less states written by an older publisher. A retained
    // backup is rollback evidence; otherwise an existing main file is committed.
    // The selected state is file- and directory-durable before recovery renames.
    if (!rollback_exists && !commit_exists) {
        if (backup_exists) {
            if (!create_marker(rollback_path_, directory_fd)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            rollback_exists = true;
        } else if (main_exists) {
            if (!create_marker(commit_path_, directory_fd)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            commit_exists = true;
        } else {
            if (restore_exists && !rollback_unlink(restore_path_)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            if (restore_exists && !rollback_directory_sync(directory_fd)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            if (::close(directory_fd) != 0) {
                record_recovery_error(errno);
                return false;
            }
            return true;
        }
    }

    if (rollback_exists) {
        if (!backup_exists) {
            // No old status existed. Rollback is a permanent, reusable state:
            // make absence durable, but never delete the evidence afterward.
            if (!rollback_unlink(path_) && errno != ENOENT) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            if (restore_exists && !rollback_unlink(restore_path_)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            if (!rollback_directory_sync(directory_fd)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            if (::close(directory_fd) != 0) {
                record_recovery_error(errno);
                return false;
            }
            return true;
        }

        // Restore through an independently fsynced copy. Android app SELinux
        // domains may not create hard links even between their own app-data
        // files. Every failed retry keeps rollback + backup and can discard and
        // rebuild this copy before repeating the same rename sequence.
        if (restore_exists) {
            if (!rollback_unlink(restore_path_)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            restore_exists = false;
        }
        if (!copy_regular_file(backup_path_, restore_path_)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        if (!rollback_rename(restore_path_, path_)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        if (!rollback_directory_sync(directory_fd)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        if (!marker_commit_rename(rollback_path_, commit_path_)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        if (!marker_commit_directory_sync(directory_fd)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        commit_exists = true;
    }

    // Commit is permanent evidence that main is authoritative. Any backup is
    // cleanup-only and can never be mistaken for rollback state on a later open.
    if (commit_exists) {
        if (::access(path_, F_OK) != 0) {
            record_recovery_error(errno == 0 ? EIO : errno);
            (void)::close(directory_fd);
            return false;
        }
        bool committed_backup_exists = false;
        bool committed_restore_exists = false;
        if (!inspect(backup_path_, &committed_backup_exists) ||
            !inspect(restore_path_, &committed_restore_exists)) {
            (void)::close(directory_fd);
            return false;
        }
        // Seeing the post-rename name in the live namespace does not prove that
        // commit won the crash-consistent directory state. Make that rename
        // durable before deleting the only rollback data.
        if ((committed_backup_exists || committed_restore_exists) &&
            !marker_commit_directory_sync(directory_fd)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
        bool removed = false;
        if (committed_backup_exists) {
            if (!rollback_unlink(backup_path_)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            removed = true;
        }
        if (committed_restore_exists) {
            if (!rollback_unlink(restore_path_)) {
                record_recovery_error(errno);
                (void)::close(directory_fd);
                return false;
            }
            removed = true;
        }
        if (removed && !backup_cleanup_directory_sync(directory_fd)) {
            record_recovery_error(errno);
            (void)::close(directory_fd);
            return false;
        }
    }
    if (::close(directory_fd) != 0) {
        record_recovery_error(errno);
        return false;
    }
    return true;
}

bool SessionStatusPublisher::open(const TraceConfig &config, uint64_t generation,
                                  std::string_view output_directory) noexcept {
    opened_ = false;
    first_error_ = 0;
    recovery_error_ = 0;
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
    const int backup_count = std::snprintf(backup_path_, sizeof(backup_path_), "%s.backup", path_);
    const int backup_prepare_count = std::snprintf(
            backup_prepare_path_, sizeof(backup_prepare_path_), "%s.prepare",
            backup_path_);
    const int restore_count = std::snprintf(restore_path_, sizeof(restore_path_), "%s.restore", path_);
    const int rollback_count = std::snprintf(rollback_path_, sizeof(rollback_path_), "%s.rollback", path_);
    const int commit_count = std::snprintf(commit_path_, sizeof(commit_path_), "%s.commit", path_);
    if (backup_count <= 0 || static_cast<size_t>(backup_count) >= sizeof(backup_path_) ||
        backup_prepare_count <= 0 ||
        static_cast<size_t>(backup_prepare_count) >= sizeof(backup_prepare_path_) ||
        restore_count <= 0 || static_cast<size_t>(restore_count) >= sizeof(restore_path_) ||
        rollback_count <= 0 || static_cast<size_t>(rollback_count) >= sizeof(rollback_path_) ||
        commit_count <= 0 || static_cast<size_t>(commit_count) >= sizeof(commit_path_)) {
        record_error(ENAMETOOLONG);
        return false;
    }
    backup_path_size_ = static_cast<size_t>(backup_count);
    std::memcpy(package_, config.package_name.data(), config.package_name.size());
    package_[config.package_name.size()] = '\0';
    std::memcpy(session_id_, config.session.id.data(), config.session.id.size());
    session_id_[config.session.id.size()] = '\0';
    generation_ = generation;
    if (!recover_pending_transaction()) {
        record_error(recovery_error_);
        return false;
    }
    opened_ = true;
    return true;
}

bool SessionStatusPublisher::publish(const SessionStatusSnapshot &snapshot) noexcept {
    if (!opened_ || snapshot.generation != generation_ || snapshot.package != package_ ||
        snapshot.session_id != session_id_) {
        record_error(EINVAL);
        return false;
    }
    if (!recover_pending_transaction()) {
        record_error(recovery_error_);
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
        if (::access(commit_path_, F_OK) != 0) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
        if (!copy_regular_file(path_, backup_prepare_path_)) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
        if (::rename(backup_prepare_path_, backup_path_) != 0) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(backup_prepare_path_);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
        // The old complete JSON must be durable before either transaction-state
        // or main-path rename is allowed to make it the only rollback source.
        if (!backup_prepare_directory_sync(directory_fd)) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
        if (::rename(commit_path_, rollback_path_) != 0) {
            const int error = errno == 0 ? EIO : errno;
            record_error(error);
            (void)recover_pending_transaction();
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            return false;
        }
        if (!marker_prepare_directory_sync(directory_fd)) {
            const int error = errno == 0 ? EIO : errno;
            record_error(error);
            (void)recover_pending_transaction();
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            return false;
        }
    } else {
        const int rollback_result = ::access(rollback_path_, F_OK);
        if (rollback_result != 0 && errno != ENOENT) {
            const int error = errno == 0 ? EIO : errno;
            (void)::close(directory_fd);
            (void)::unlink(temporary);
            record_error(error);
            return false;
        }
        if (rollback_result != 0 && !create_marker(rollback_path_, directory_fd)) {
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
        record_error(rename_fault);
        (void)recover_pending_transaction();
        (void)::close(directory_fd);
        (void)::unlink(temporary);
        return false;
    }
#endif
    if (::rename(temporary, path_) != 0) {
        const int error = errno;
        record_error(error);
        (void)recover_pending_transaction();
        (void)::close(directory_fd);
        (void)::unlink(temporary);
        return false;
    }
    if (!sync_file(directory_fd, true)) {
        const int error = errno;
        record_error(error);
        (void)recover_pending_transaction();
        (void)::close(directory_fd);
        return false;
    }
    if (!marker_commit_rename(rollback_path_, commit_path_)) {
        const int error = errno == 0 ? EIO : errno;
        record_error(error);
        (void)recover_pending_transaction();
        (void)::close(directory_fd);
        return false;
    }
    if (!marker_commit_directory_sync(directory_fd)) {
        const int error = errno == 0 ? EIO : errno;
        record_error(error);
        (void)recover_pending_transaction();
        (void)::close(directory_fd);
        return false;
    }
    if (had_previous && !rollback_unlink(backup_path_)) {
        const int error = errno == 0 ? EIO : errno;
        record_recovery_error(error);
        record_error(error);
        (void)::close(directory_fd);
        return false;
    }
    if (had_previous && !backup_cleanup_directory_sync(directory_fd)) {
        const int error = errno == 0 ? EIO : errno;
        record_recovery_error(error);
        record_error(error);
        (void)::close(directory_fd);
        return false;
    }
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

int SessionStatusPublisher::recovery_error() const noexcept {
    return recovery_error_;
}

std::string_view SessionStatusPublisher::backup_path() const noexcept {
    return std::string_view(backup_path_, backup_path_size_);
}
