#pragma once
#include <windows.h>

namespace pesieve {
	namespace util {
		/*
		Scans the buffer of given size, in a search of the supplied pattern.
		If the number of iterations is not specified (0) it scans full space, otherwise it takes only max_iter number of steps.
		Returns the pointer to the found pattern, or nullptr if not found.
		*/
		BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter = 0);

		bool is_32bit_code(BYTE *loadedData, size_t loadedSize);
		bool is_64bit_code(BYTE *loadedData, size_t loadedSize);

		bool is_code(BYTE *loadedData, size_t loadedSize);

		bool is_executable(DWORD mapping_type, DWORD protection);

		bool is_readable(DWORD mapping_type, DWORD protection);
	};
}
