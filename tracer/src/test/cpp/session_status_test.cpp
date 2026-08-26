#include "core/session_status.h"

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
    CHECK(json.find("\"schemaVersion\":1") != std::string::npos);
    CHECK(json.find("\"sessionId\":\"7d5807cf-cf09-4f21-92de-1ad92802610a\"") != std::string::npos);
    CHECK(json.find("\"generation\":3") != std::string::npos);
    CHECK(json.find("\"packageName\":\"com.example.target\"") != std::string::npos);
    CHECK(json.find("\"pid\":42") != std::string::npos);
    CHECK(json.find("\"state\":\"sealed\"") != std::string::npos);
    CHECK(json.find("\"reason\":\"duration_elapsed\"") != std::string::npos);
    CHECK(json.find("\"transitionMonotonicNs\":17") != std::string::npos);
    CHECK(json.find("\"normalizedScenes\":[{\"name\":\"entry\",\"startOffset\":16,\"endOffset\":32}]") != std::string::npos);
    CHECK(json.find("\"activeScenes\":[{\"sceneIndex\":0,\"tid\":77,\"sealed\":true}]") != std::string::npos);
    CHECK(json.find("\"artifacts\":[\"run.trace.bin.lz4\"]") != std::string::npos);
    CHECK(json.find("\"stopAcknowledged\":true") != std::string::npos);
    CHECK(json.find("\"warnings\":[{\"code\":\"CONFIG_WARNING\",\"path\":\"$\",\"message\":\"warning text\"}]") != std::string::npos);
    CHECK(json.find("\"errors\":[{\"code\":\"STATUS_ERROR\",\"path\":\"$.status\",\"message\":\"error text\"}]") != std::string::npos);
    CHECK(has_no_temporary_files(root.path()));
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

// Catches validation gaps that would let status output escape the app-private
// directory through a session id, package, or artifact path component.
void rejects_unsafe_names_before_creating_a_status_file() {
    TemporaryDirectory root;
    TraceConfig config = configured_trace();
    config.package_name = "com.example/escape";
    SessionStatusPublisher publisher;
    CHECK(!publisher.open(config, 3, root.path()));
    CHECK(publisher.error_code() == EINVAL);

    config = configured_trace();
    config.session.id = "not-a-uuid";
    CHECK(!publisher.open(config, 3, root.path()));
    CHECK(publisher.error_code() == EINVAL);

    CHECK(publisher.open(configured_trace(), 3, root.path()));
    SessionStatusSnapshot snapshot = sealed_snapshot();
    snapshot.artifacts = {"../trace.bin"};
    CHECK(!publisher.publish(snapshot));
    CHECK(publisher.error_code() == EINVAL);
    CHECK(has_no_temporary_files(root.path()));
}

} // namespace

int main() {
    writes_the_complete_session_status_schema_atomically();
    failed_publications_preserve_the_previous_status_and_latch_first_errno();
    rejects_unsafe_names_before_creating_a_status_file();
}
