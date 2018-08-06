#include "artefacts_util.h"

#ifdef _DEBUG
	#include <iostream>
#endif

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

bool is_code(BYTE *loadedData, size_t loadedSize)
{
	BYTE prolog32_pattern[] = {
		0x55, // PUSH EBP
		0x8b, 0xEC // MOV EBP, ESP
	};

	BYTE prolog64_pattern[] = {
		0x40, 0x53, // PUSH RBX
		0x48, 0x83, 0xEC // SUB RSP, ??
	};

	bool pattern_found = false;

	if (find_pattern(loadedData, loadedSize, prolog32_pattern, sizeof(prolog32_pattern))) {
#ifdef _DEBUG
		std::cout << std::hex << memPage.region_start << ": contains 32bit shellcode" << std::endl;
#endif
		pattern_found = true;
	}
	else if (find_pattern(loadedData, loadedSize, prolog64_pattern, sizeof(prolog64_pattern))) {
#ifdef _DEBUG
		std::cout << std::hex << memPage.region_start << ": contains 64bit shellcode" << std::endl;
#endif
		pattern_found = true;
	}
	return pattern_found;
}