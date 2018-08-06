#pragma once
#include <Windows.h>

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size);

bool is_code(BYTE *loadedData, size_t loadedSize);
