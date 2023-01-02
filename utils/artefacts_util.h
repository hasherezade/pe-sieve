#pragma once
#include <windows.h>

#define CODE_PATTERN_NOT_FOUND (-1)

namespace pesieve {
	namespace util {
		/*
		Scans the buffer of given size, in a search of the supplied pattern.
		If the number of iterations is not specified (0) it scans full space, otherwise it takes only max_iter number of steps.
		Returns the pointer to the found pattern, or nullptr if not found.
		*/
		BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter = 0);

		/*
		Scans the buffer searching for the hardcoded 32-bit code patterns. If found, returns the patten ID, otherwise returns CODE_PATTERN_NOT_FOUND
		*/
		DWORD is_32bit_code(BYTE *loadedData, size_t loadedSize);

		/*
		Scans the buffer searching for the hardcoded 64-bit code patterns. If found, returns the patten ID, otherwise returns CODE_PATTERN_NOT_FOUND
		*/
		DWORD is_64bit_code(BYTE *loadedData, size_t loadedSize);

		/*
		Scans the buffer searching for any hardcoded code patterns (both 32 and 64 bit).
		*/
		bool is_code(BYTE *loadedData, size_t loadedSize);

		bool is_executable(DWORD mapping_type, DWORD protection);

		bool is_readable(DWORD mapping_type, DWORD protection);

		bool is_normal_inaccessible(DWORD state, DWORD mapping_type, DWORD protection);
	};
}
