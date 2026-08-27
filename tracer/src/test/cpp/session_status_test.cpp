#include "core/session_status.h"
#include "third_party/nlohmann/json.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

void check(bool condition, const char *expression, int line) {
    if (condition) return;
    std::fprintf(stderr, "CHECK failed at line %d: %s\\n", line, expression);
    std::abort();
}

#define CHECK(expression) check(static_cast<bool>(expression), #expression, __LINE__)

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        char template_path[] = "/tmp/qtrace-status-XXXXXX";
        const char *created = ::mkdtemp(template_path);
        CHECK(created != nullptr);
        path_ = created;
    }

    ~TemporaryDirectory() {
        DIR *directory = ::opendir(path_.c_str());
        if (directory != nullptr) {
            while (dirent *entry = ::readdir(directory)) {
                if (std::strcmp(entry->d_name, ".") == 0 ||
                    std::strcmp(entry->d_name, "..") == 0) continue;
                std::string child = path_ + "/" + entry->d_name;
                (void)::unlink(child.c_str());
            }
            (void)::closedir(directory);
        }
        (void)::rmdir(path_.c_str());
    }

    const std::string &path() const noexcept { return path_; }

private:
    std::string path_;
};

std::string read_text(std::string_view path) {
    const int fd = ::open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    std::string text;
    char buffer[512];
    for (;;) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        CHECK(count >= 0);
        if (count == 0) break;
        text.append(buffer, static_cast<size_t>(count));
    }
    CHECK(::close(fd) == 0);
    return text;
}

bool has_no_temporary_files(const std::string &root) {
    DIR *directory = ::opendir(root.c_str());
    if (directory == nullptr) return false;
    bool clean = true;
    while (dirent *entry = ::readdir(directory)) {
        if (std::strstr(entry->d_name, ".status.json.tmp.") != nullptr) clean = false;
    }
    (void)::closedir(directory);
    return clean;
}

bool directory_is_empty(const std::string &root) {
    DIR *directory = ::opendir(root.c_str());
    if (directory == nullptr) return false;
    bool empty = true;
    while (dirent *entry = ::readdir(directory)) {
        if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0)
            empty = false;
    }
    (void)::closedir(directory);
    return empty;
}

TraceConfig configured_trace() {
    TraceConfig config{};
    config.package_name = "com.example.target";
    config.session.id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    return config;
}

SessionStatusSnapshot sealed_snapshot() {
    SessionStatusSnapshot snapshot{};
    snapshot.schema_version = 1;
    snapshot.session_id = "7d5807cf-cf09-4f21-92de-1ad92802610a";
    snapshot.generation = 3;
    snapshot.package = "com.example.target";
    snapshot.pid = 42;
    snapshot.state = "sealed";
    snapshot.reason = "duration_elapsed";
    snapshot.transition_monotonic_ns = 17;
    snapshot.deadline_monotonic_ns = 99;
    snapshot.normalized_scenes = {{"entry", 16, 32}};
    snapshot.active_scenes = {{0, 77, true}};
    snapshot.artifacts = {"run.trace.bin.lz4"};
    snapshot.stop_acknowledged = true;
    snapshot.warnings = {{"CONFIG_WARNING", "$", "warning text"}};
    snapshot.errors = {{"STATUS_ERROR", "$.status", "error text"}};
    return snapshot;
}

// Catches a publication that omits or corrupts one of the documented fields,
// or leaves a visible temporary file after an otherwise successful update.
void writes_the_complete_session_status_schema_atomically() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    const SessionStatusSnapshot snapshot = sealed_snapshot();
    CHECK(publisher.publish(snapshot));
    const std::string json = read_text(publisher.path());
    const nlohmann::json status = nlohmann::json::parse(json);
    CHECK(status.is_object());
    CHECK(status.at("schemaVersion").is_number_unsigned());
    CHECK(status.at("schemaVersion") == 1);
    CHECK(status.at("sessionId").is_string());
    CHECK(status.at("sessionId") == "7d5807cf-cf09-4f21-92de-1ad92802610a");
    CHECK(status.at("generation").is_number_unsigned());
    CHECK(status.at("generation") == 3);
    CHECK(status.at("packageName").is_string());
    CHECK(status.at("packageName") == "com.example.target");
    CHECK(status.at("pid").is_number_unsigned());
    CHECK(status.at("pid") == 42);
    CHECK(status.at("state").is_string());
    CHECK(status.at("state") == "sealed");
    CHECK(status.at("reason").is_string());
    CHECK(status.at("reason") == "duration_elapsed");
    CHECK(status.at("transitionMonotonicNs").is_number_unsigned());
    CHECK(status.at("transitionMonotonicNs") == 17);
    CHECK(status.at("deadlineMonotonicNs").is_number_unsigned());
    CHECK(status.at("deadlineMonotonicNs") == 99);
    CHECK(status.at("normalizedScenes").is_array());
    CHECK(status.at("normalizedScenes").size() == 1);
    CHECK(status.at("normalizedScenes").at(0).at("name") == "entry");
    CHECK(status.at("normalizedScenes").at(0).at("startOffset") == 16);
    CHECK(status.at("normalizedScenes").at(0).at("endOffset") == 32);
    CHECK(status.at("activeScenes").is_array());
    CHECK(status.at("activeScenes").size() == 1);
    CHECK(status.at("activeScenes").at(0).at("sceneIndex") == 0);
    CHECK(status.at("activeScenes").at(0).at("tid") == 77);
    CHECK(status.at("activeScenes").at(0).at("sealed") == true);
    CHECK(status.at("artifacts").is_array());
    CHECK(status.at("artifacts").at(0) == "run.trace.bin.lz4");
    CHECK(status.at("stopAcknowledged").is_boolean());
    CHECK(status.at("stopAcknowledged") == true);
    CHECK(status.at("warnings").is_array());
    CHECK(status.at("warnings").at(0).at("code") == "CONFIG_WARNING");
    CHECK(status.at("warnings").at(0).at("path") == "$");
    CHECK(status.at("warnings").at(0).at("message") == "warning text");
    CHECK(status.at("errors").is_array());
    CHECK(status.at("errors").at(0).at("code") == "STATUS_ERROR");
    CHECK(status.at("errors").at(0).at("path") == "$.status");
    CHECK(status.at("errors").at(0).at("message") == "error text");
    CHECK(has_no_temporary_files(root.path()));
}

// Catches a directory durability failure that leaves a newly renamed first
// status visible even though no previous valid status existed to recover.
void directory_sync_failure_without_a_previous_status_leaves_no_status_file() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
    CHECK(!publisher.publish(sealed_snapshot()));
    CHECK(::access(std::string(publisher.path()).c_str(), F_OK) != 0);
    const std::string rollback_marker = std::string(publisher.path()) + ".rollback";
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);
    CHECK(publisher.error_code() == EIO);
    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(::access(std::string(recovered.path()).c_str(), F_OK) != 0);
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);
    CHECK(recovered.publish(sealed_snapshot()));
    CHECK(::access(rollback_marker.c_str(), F_OK) != 0);
    CHECK(::access((std::string(recovered.path()) + ".commit").c_str(), F_OK) == 0);
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
}

// Catches a first-status rollback whose unlink succeeded but whose directory
// fsync failed: recovery still needs a durable marker to retry that fsync.
void no_previous_rollback_directory_sync_retains_a_recoverable_marker() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    const std::string rollback_marker = std::string(publisher.path()) + ".rollback";
    session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::RollbackDirFsync, EPERM);
    CHECK(!publisher.publish(sealed_snapshot()));
    CHECK(publisher.error_code() == EIO);
    CHECK(publisher.recovery_error() == EPERM);
    CHECK(::access(std::string(publisher.path()).c_str(), F_OK) != 0);
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);

    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(::access(std::string(recovered.path()).c_str(), F_OK) != 0);
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);
    CHECK(has_no_temporary_files(root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
}

// Catches a protocol that unlinks its only transaction state and then depends
// on recreating that evidence after the cleanup directory fsync fails.
void committed_state_does_not_depend_on_cleanup_recreation() {
    for (const SessionStatusFaultPoint recreate_failure : {
                 SessionStatusFaultPoint::MarkerRecreateOpen,
                 SessionStatusFaultPoint::MarkerRecreateFileFsync,
         }) {
        TemporaryDirectory root;
        SessionStatusPublisher publisher;
        CHECK(publisher.open(configured_trace(), 3, root.path()));
        const std::string committed_marker = std::string(publisher.path()) + ".commit";
        session_status_test_inject_fault(SessionStatusFaultPoint::MarkerCleanupDirFsync, EIO);
        session_status_test_inject_followup_fault(recreate_failure, EPERM);
        CHECK(publisher.publish(sealed_snapshot()));
        CHECK(publisher.error_code() == 0);
        CHECK(publisher.recovery_error() == 0);
        CHECK(::access(committed_marker.c_str(), F_OK) == 0);
        session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);

        SessionStatusPublisher recovered;
        CHECK(recovered.open(configured_trace(), 3, root.path()));
        CHECK(read_text(recovered.path()).find("\"state\":\"sealed\"") != std::string::npos);
        SessionStatusSnapshot next = sealed_snapshot();
        next.state = "running";
        CHECK(recovered.publish(next));
        CHECK(read_text(recovered.path()).find("\"state\":\"running\"") != std::string::npos);
        CHECK(::access(committed_marker.c_str(), F_OK) == 0);
        CHECK(has_no_temporary_files(root.path()));
    }
}

// Catches recovery treating a durable rollback state as disposable cleanup.
// Re-entry must keep it until a later first publication commits.
void rollback_state_is_reentrant_until_a_publication_commits() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    const std::string rollback_marker = std::string(publisher.path()) + ".rollback";
    session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::RollbackDirFsync, EPERM);
    CHECK(!publisher.publish(sealed_snapshot()));
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);

    SessionStatusPublisher cleanup_failed;
    CHECK(cleanup_failed.open(configured_trace(), 3, root.path()));
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);
    CHECK(::access(std::string(cleanup_failed.path()).c_str(), F_OK) != 0);

    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(::access(rollback_marker.c_str(), F_OK) == 0);
    CHECK(recovered.publish(sealed_snapshot()));
    CHECK(::access(rollback_marker.c_str(), F_OK) != 0);
    CHECK(::access((std::string(recovered.path()) + ".commit").c_str(), F_OK) == 0);
    CHECK(has_no_temporary_files(root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
}

// Catches an update that creates an old-status hard link but performs the
// dangerous replacement rename before that recovery evidence is durable.
void old_status_backup_is_durable_before_replacement() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    CHECK(publisher.publish(sealed_snapshot()));
    const std::string before = read_text(publisher.path());
    SessionStatusSnapshot next = sealed_snapshot();
    next.state = "running";
    session_status_test_inject_fault(SessionStatusFaultPoint::BackupPrepareDirFsync, EBUSY);
    CHECK(!publisher.publish(next));
    CHECK(publisher.error_code() == EBUSY);
    CHECK(read_text(publisher.path()) == before);
    CHECK(::access(std::string(publisher.backup_path()).c_str(), F_OK) == 0);

    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(read_text(recovered.path()) == before);
    CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);
}

// Catches backup cleanup ambiguity restoring the old JSON after the replacement
// and committed transaction state are already durable.
void committed_update_cleanup_failure_keeps_the_new_status_on_reentry() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    CHECK(publisher.publish(sealed_snapshot()));
    SessionStatusSnapshot next = sealed_snapshot();
    next.state = "running";
    session_status_test_inject_fault(SessionStatusFaultPoint::BackupCleanupDirFsync, EBUSY);
    CHECK(!publisher.publish(next));
    CHECK(publisher.error_code() == EBUSY);
    CHECK(publisher.recovery_error() == EBUSY);
    CHECK(read_text(publisher.path()).find("\"state\":\"running\"") != std::string::npos);

    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(read_text(recovered.path()).find("\"state\":\"running\"") != std::string::npos);
    CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);
}

// Catches a commit-state rename being treated as durable before its directory
// fsync, or reporting that publication fault as a recovery failure. Re-entry may
// observe the old or new durable name after a crash, but either state is complete.
void commit_state_directory_sync_failure_is_reentrant() {
    for (const bool had_previous : {false, true}) {
        TemporaryDirectory root;
        SessionStatusPublisher publisher;
        CHECK(publisher.open(configured_trace(), 3, root.path()));
        if (had_previous) CHECK(publisher.publish(sealed_snapshot()));
        SessionStatusSnapshot next = sealed_snapshot();
        next.state = "running";
        session_status_test_inject_fault(SessionStatusFaultPoint::MarkerCommitDirFsync, EIO);
        CHECK(!publisher.publish(next));
        CHECK(publisher.error_code() == EIO);
        CHECK(publisher.recovery_error() == 0);

        session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
        SessionStatusPublisher recovered;
        CHECK(recovered.open(configured_trace(), 3, root.path()));
        CHECK(read_text(recovered.path()).find("\"state\":\"running\"") != std::string::npos);
        CHECK(::access((std::string(recovered.path()) + ".commit").c_str(), F_OK) == 0);
        CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);
    }
}

// Catches recovery deleting rollback data based only on the live `.commit`
// name after the commit-state rename directory fsync failed. A second fsync
// failure must leave backup intact and report only through recovery_error().
void commit_state_is_durable_before_backup_cleanup() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    CHECK(publisher.publish(sealed_snapshot()));
    SessionStatusSnapshot next = sealed_snapshot();
    next.state = "running";
    session_status_test_inject_fault(SessionStatusFaultPoint::MarkerCommitDirFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::MarkerCommitDirFsync, EPERM);
    CHECK(!publisher.publish(next));
    CHECK(publisher.error_code() == EIO);
    CHECK(publisher.recovery_error() == EPERM);
    CHECK(::access(std::string(publisher.backup_path()).c_str(), F_OK) == 0);

    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(read_text(recovered.path()).find("\"state\":\"running\"") != std::string::npos);
    CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);

    TemporaryDirectory cleanup_root;
    SessionStatusPublisher cleanup_publisher;
    CHECK(cleanup_publisher.open(configured_trace(), 3, cleanup_root.path()));
    CHECK(cleanup_publisher.publish(sealed_snapshot()));
    session_status_test_inject_fault(SessionStatusFaultPoint::MarkerCommitDirFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::BackupCleanupDirFsync,
                                               EBUSY);
    CHECK(!cleanup_publisher.publish(next));
    CHECK(cleanup_publisher.error_code() == EIO);
    CHECK(cleanup_publisher.recovery_error() == EBUSY);
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    SessionStatusPublisher cleanup_recovered;
    CHECK(cleanup_recovered.open(configured_trace(), 3, cleanup_root.path()));
    CHECK(read_text(cleanup_recovered.path()).find("\"state\":\"running\"") !=
          std::string::npos);
}

// Catches a failure path that replaces the last good JSON with a partial file,
// leaves a temporary sibling behind, or overwrites the first diagnostic errno.
void failed_publications_preserve_the_previous_status_and_latch_first_errno() {
    constexpr SessionStatusFaultPoint failures[] = {
            SessionStatusFaultPoint::PartialWrite,
            SessionStatusFaultPoint::FileFsync,
            SessionStatusFaultPoint::Rename,
            SessionStatusFaultPoint::DirectoryFsync,
    };
    for (SessionStatusFaultPoint failure : failures) {
        TemporaryDirectory root;
        SessionStatusPublisher publisher;
        CHECK(publisher.open(configured_trace(), 3, root.path()));
        CHECK(publisher.publish(sealed_snapshot()));
        const std::string before = read_text(publisher.path());
        session_status_test_inject_fault(failure, EIO);
        SessionStatusSnapshot next = sealed_snapshot();
        next.state = "running";
        CHECK(!publisher.publish(next));
        CHECK(read_text(publisher.path()) == before);
        CHECK(has_no_temporary_files(root.path()));
        CHECK(publisher.error_code() == EIO);
        session_status_test_inject_fault(SessionStatusFaultPoint::Rename, EXDEV);
        CHECK(!publisher.publish(next));
        CHECK(publisher.error_code() == EIO);
        session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    }
}

// Catches rollback silently deleting the only retained valid JSON when its
// restore rename fails after the replacement itself was already renamed.
void failed_rollback_retains_the_old_backup_until_the_next_open_recovers_it() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    CHECK(publisher.publish(sealed_snapshot()));
    const std::string before = read_text(publisher.path());
    SessionStatusSnapshot next = sealed_snapshot();
    next.state = "running";
    session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::RollbackRename, EPERM);
    CHECK(!publisher.publish(next));
    CHECK(publisher.error_code() == EIO);
    CHECK(publisher.recovery_error() == EPERM);
    CHECK(read_text(publisher.backup_path()) == before);
    CHECK(has_no_temporary_files(root.path()));

    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(read_text(recovered.path()) == before);
    CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);
    CHECK(has_no_temporary_files(root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
}

// Catches rollback fsync/unlink failures that otherwise discard the recovery
// marker or backup before a later publisher can restore the prior state.
void rollback_failures_are_recovered_by_the_next_open() {
    for (const SessionStatusFaultPoint rollback_failure : {
                 SessionStatusFaultPoint::RollbackDirFsync,
                 SessionStatusFaultPoint::RollbackUnlink,
         }) {
        TemporaryDirectory root;
        SessionStatusPublisher publisher;
        CHECK(publisher.open(configured_trace(), 3, root.path()));
        CHECK(publisher.publish(sealed_snapshot()));
        const std::string before = read_text(publisher.path());
        SessionStatusSnapshot next = sealed_snapshot();
        next.state = "running";
        session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
        session_status_test_inject_followup_fault(rollback_failure, EPERM);
        CHECK(!publisher.publish(next));
        CHECK(publisher.error_code() == EIO);
        CHECK(publisher.recovery_error() == EPERM);
        CHECK(read_text(publisher.backup_path()) == before);
        SessionStatusPublisher recovered;
        CHECK(recovered.open(configured_trace(), 3, root.path()));
        CHECK(read_text(recovered.path()) == before);
        CHECK(::access(std::string(recovered.backup_path()).c_str(), F_OK) != 0);
        CHECK(has_no_temporary_files(root.path()));
        session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
    }

    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::DirectoryFsync, EIO);
    session_status_test_inject_followup_fault(SessionStatusFaultPoint::RollbackUnlink, EPERM);
    CHECK(!publisher.publish(sealed_snapshot()));
    CHECK(publisher.error_code() == EIO);
    CHECK(publisher.recovery_error() == EPERM);
    SessionStatusPublisher recovered;
    CHECK(recovered.open(configured_trace(), 3, root.path()));
    CHECK(::access(std::string(recovered.path()).c_str(), F_OK) != 0);
    CHECK(::access((std::string(recovered.path()) + ".rollback").c_str(), F_OK) == 0);
    CHECK(has_no_temporary_files(root.path()));
    session_status_test_inject_fault(SessionStatusFaultPoint::None, 0);
}

// Catches validation gaps that would let status output escape the app-private
// directory through a session id, package, or artifact path component.
void rejects_unsafe_names_before_creating_a_status_file() {
    TemporaryDirectory root;
    constexpr const char *unsafe_packages[] = {
            ".", "..", ".com.example", "com.example.", "com..example",
            "com/example", "com\\example", "com.example\x01target",
    };
    for (const char *package : unsafe_packages) {
        TraceConfig config = configured_trace();
        config.package_name = package;
        SessionStatusPublisher publisher;
        CHECK(!publisher.open(config, 3, root.path()));
        CHECK(publisher.error_code() == EINVAL);
        CHECK(publisher.path().empty());
        CHECK(directory_is_empty(root.path()));
    }

    TraceConfig config = configured_trace();
    config.session.id = "not-a-uuid";
    SessionStatusPublisher publisher;
    CHECK(!publisher.open(config, 3, root.path()));
    CHECK(publisher.error_code() == EINVAL);

    CHECK(publisher.open(configured_trace(), 3, root.path()));
    constexpr const char *unsafe_artifacts[] = {
            ".", "..", "../trace.bin", "trace/part.bin", "trace\\part.bin", "trace\x1f.bin",
    };
    for (const char *artifact : unsafe_artifacts) {
        SessionStatusSnapshot snapshot = sealed_snapshot();
        snapshot.artifacts = {artifact};
        CHECK(!publisher.publish(snapshot));
        CHECK(publisher.error_code() == EINVAL);
        CHECK(has_no_temporary_files(root.path()));
    }
}

// Catches a different valid session identity being serialized into a status
// file that belongs to the opened package/session/generation tuple.
void rejects_snapshots_that_do_not_match_the_opened_session() {
    TemporaryDirectory root;
    SessionStatusPublisher publisher;
    CHECK(publisher.open(configured_trace(), 3, root.path()));
    SessionStatusSnapshot snapshot = sealed_snapshot();
    snapshot.session_id = "6d5807cf-cf09-4f21-92de-1ad92802610a";
    CHECK(!publisher.publish(snapshot));
    CHECK(publisher.error_code() == EINVAL);
    CHECK(directory_is_empty(root.path()));
}

// Catches a publisher accepting UUID-shaped values that the configuration
// parser must reject because their version or RFC 4122 variant is wrong.
void rejects_session_ids_that_are_not_lowercase_non_nil_uuid_v4() {
    constexpr const char *invalid_ids[] = {
            "7d5807cf-cf09-5f21-92de-1ad92802610a",
            "7d5807cf-cf09-4f21-72de-1ad92802610a",
            "00000000-0000-0000-0000-000000000000",
    };
    for (const char *id : invalid_ids) {
        TemporaryDirectory root;
        TraceConfig config = configured_trace();
        config.session.id = id;
        SessionStatusPublisher publisher;
        CHECK(!publisher.open(config, 3, root.path()));
        CHECK(publisher.error_code() == EINVAL);
        CHECK(directory_is_empty(root.path()));
    }
}

// Catches raw non-UTF-8 bytes reaching JSON output through any caller-owned
// string field. Rejecting before create is safer than emitting invalid JSON.
void rejects_non_utf8_snapshot_strings_before_creating_a_status_file() {
    const std::string invalid_utf8("\x80", 1);
    for (unsigned int field = 0; field != 9; ++field) {
        TemporaryDirectory root;
        SessionStatusPublisher publisher;
        CHECK(publisher.open(configured_trace(), 3, root.path()));
        SessionStatusSnapshot snapshot = sealed_snapshot();
        if (field == 0) snapshot.reason = invalid_utf8;
        if (field == 1) snapshot.normalized_scenes[0].name = invalid_utf8;
        if (field == 2) snapshot.warnings[0].message = invalid_utf8;
        if (field == 3) snapshot.artifacts[0] = invalid_utf8;
        if (field == 4) snapshot.warnings[0].code = invalid_utf8;
        if (field == 5) snapshot.warnings[0].path = invalid_utf8;
        if (field == 6) snapshot.errors[0].code = invalid_utf8;
        if (field == 7) snapshot.errors[0].path = invalid_utf8;
        if (field == 8) snapshot.errors[0].message = invalid_utf8;
        CHECK(!publisher.publish(snapshot));
        CHECK(publisher.error_code() == EINVAL);
        CHECK(directory_is_empty(root.path()));
    }
}

} // namespace

int main() {
    writes_the_complete_session_status_schema_atomically();
    failed_publications_preserve_the_previous_status_and_latch_first_errno();
    no_previous_rollback_directory_sync_retains_a_recoverable_marker();
    committed_state_does_not_depend_on_cleanup_recreation();
    rollback_state_is_reentrant_until_a_publication_commits();
    old_status_backup_is_durable_before_replacement();
    committed_update_cleanup_failure_keeps_the_new_status_on_reentry();
    commit_state_directory_sync_failure_is_reentrant();
    commit_state_is_durable_before_backup_cleanup();
    failed_rollback_retains_the_old_backup_until_the_next_open_recovers_it();
    rollback_failures_are_recovered_by_the_next_open();
    directory_sync_failure_without_a_previous_status_leaves_no_status_file();
    rejects_unsafe_names_before_creating_a_status_file();
    rejects_snapshots_that_do_not_match_the_opened_session();
    rejects_session_ids_that_are_not_lowercase_non_nil_uuid_v4();
    rejects_non_utf8_snapshot_strings_before_creating_a_status_file();
}
