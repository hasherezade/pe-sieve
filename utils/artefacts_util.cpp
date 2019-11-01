#include "artefacts_util.h"

#ifdef _DEBUG
	#include <iostream>
#endif

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (max_iter != 0 && i > max_iter) break;
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

bool is_32bit_code(BYTE *loadedData, size_t loadedSize)
{
	BYTE prolog32_pattern[] = {
		0x55, // PUSH EBP
		0x8b, 0xEC // MOV EBP, ESP
	};

	BYTE prolog32_2_pattern[] = {
		0x55, // PUSH EBP
		0x89, 0xE5 // MOV EBP, ESP
	};

	bool pattern_found = false;
	if (find_pattern(loadedData, loadedSize, prolog32_pattern, sizeof(prolog32_pattern))) {
		pattern_found = true;
	}
	else if (find_pattern(loadedData, loadedSize, prolog32_2_pattern, sizeof(prolog32_2_pattern))) {
		pattern_found = true;
	}
	return pattern_found;
}

bool is_64bit_code(BYTE *loadedData, size_t loadedSize)
{
	BYTE prolog64_pattern[] = {
		0x40, 0x53, // PUSH RBX
		0x48, 0x83, 0xEC // SUB RSP, ??
	};
	bool pattern_found = false;
	if (find_pattern(loadedData, loadedSize, prolog64_pattern, sizeof(prolog64_pattern))) {
		pattern_found = true;
	}
	return pattern_found;
}

bool is_code(BYTE *loadedData, size_t loadedSize)
{
	if (is_32bit_code(loadedData, loadedSize)) {
		return true;
	}
	if (is_64bit_code(loadedData, loadedSize)) {
		return true;
	}
	return false;
}
