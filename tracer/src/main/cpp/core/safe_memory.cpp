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

std::string preview_c_string(uintptr_t address, size_t max_len) {
    std::string buffer(max_len, 0);
    if (!safe_read_memory(address, buffer.data(), max_len)) return "<unreadable>";
    size_t end = 0;
    while (end < buffer.size() && buffer[end] != 0) {
        if (!std::isprint(static_cast<unsigned char>(buffer[end]))) return "<non-printable>";
        ++end;
    }
    return buffer.substr(0, end);
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
