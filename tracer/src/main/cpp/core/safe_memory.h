#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

bool safe_read_memory(uintptr_t address, void *buffer, size_t size);
bool safe_write_memory(uintptr_t address, const void *buffer, size_t size);
std::string preview_c_string(uintptr_t address, size_t max_len = 96);
std::string hex_preview(uintptr_t address, size_t size, size_t max_len = 32);
