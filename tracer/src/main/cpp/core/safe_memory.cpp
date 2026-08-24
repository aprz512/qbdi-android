#include "core/safe_memory.h"

#include <cctype>
#include <sstream>
#include <sys/uio.h>
#include <unistd.h>

bool safe_read_memory(uintptr_t address, void *buffer, size_t size) {
    if (address == 0 || buffer == nullptr || size == 0) return false;
    iovec local{buffer, size};
    iovec remote{reinterpret_cast<void *>(address), size};
    ssize_t read = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return read == static_cast<ssize_t>(size);
}

bool safe_write_memory(uintptr_t address, const void *buffer, size_t size) {
    if (address == 0 || buffer == nullptr || size == 0) return false;
    iovec local{const_cast<void *>(buffer), size};
    iovec remote{reinterpret_cast<void *>(address), size};
    ssize_t written = process_vm_writev(getpid(), &local, 1, &remote, 1, 0);
    return written == static_cast<ssize_t>(size);
}

std::optional<std::string> copy_c_string(uintptr_t address, size_t max_len,
                                         bool allow_common_whitespace) {
    if (address < 0x1000 || max_len == 0) return std::nullopt;
    std::string result;
    result.reserve(max_len);
    for (size_t offset = 0; offset < max_len; ++offset) {
        char value = 0;
        if (!safe_read_memory(address + offset, &value, 1)) return std::nullopt;
        if (value == '\0') return result;
        const auto byte = static_cast<unsigned char>(value);
        if ((byte < 0x20 || byte == 0x7f) &&
            !(allow_common_whitespace && (value == '\n' || value == '\t'))) {
            return std::nullopt;
        }
        result.push_back(value);
    }
    return std::nullopt;
}

std::string preview_c_string(uintptr_t address, size_t max_len) {
    const auto copied = copy_c_string(address, max_len);
    if (copied) return *copied;

    std::string buffer(max_len, 0);
    if (!safe_read_memory(address, buffer.data(), max_len)) return "<unreadable>";
    for (const char value : buffer) {
        if (value == '\0') break;
        if (!std::isprint(static_cast<unsigned char>(value))) return "<non-printable>";
    }
    return "<unreadable>";
}

std::string hex_preview(uintptr_t address, size_t size, size_t max_len) {
    size_t read_size = size < max_len ? size : max_len;
    unsigned char bytes[64] = {};
    if (read_size > sizeof(bytes)) read_size = sizeof(bytes);
    if (!safe_read_memory(address, bytes, read_size)) return "<unreadable>";
    std::ostringstream out;
    out << std::hex;
    for (size_t i = 0; i < read_size; ++i) {
        if (i != 0) out << ' ';
        out.width(2);
        out.fill('0');
        out << static_cast<unsigned int>(bytes[i]);
    }
    return out.str();
}
