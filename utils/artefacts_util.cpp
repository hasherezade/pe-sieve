#include "artefacts_util.h"
#include <peconv.h>

#ifdef _DEBUG
	#include <iostream>
#endif

BYTE* pesieve::util::find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (max_iter != 0 && i > max_iter) break;
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

namespace pesieve {
	typedef struct {
		BYTE *ptr;
		size_t size;
	} t_pattern;
};

bool pesieve::util::is_32bit_code(BYTE *loadedData, size_t loadedSize)
{
	BYTE prolog32_pattern[] = {
		0x55, // PUSH EBP
		0x8b, 0xEC // MOV EBP, ESP
	};

	BYTE prolog32_2_pattern[] = {
		0x55, // PUSH EBP
		0x89, 0xE5 // MOV EBP, ESP
	};

	BYTE prolog32_3_pattern[] = {
		0x60, // PUSHAD
		0x89, 0xE5 // MOV EBP, ESP
	};

	t_pattern patterns[] = {
		{ prolog32_pattern,   sizeof(prolog32_pattern) },
		{ prolog32_2_pattern, sizeof(prolog32_2_pattern) },
		{ prolog32_3_pattern, sizeof(prolog32_3_pattern) }
	};

	bool pattern_found = false;
	for (size_t i = 0; i < _countof(patterns); i++) {
		if (find_pattern(loadedData, loadedSize, patterns[i].ptr, patterns[i].size)) {
			pattern_found = true;
			//std::cout << "Found 32bit pattern: " << i << "\n";
			break;
		}
	}
	return pattern_found;
}

bool pesieve::util::is_64bit_code(BYTE *loadedData, size_t loadedSize)
{
	BYTE prolog64_pattern[] = {
		0x40, 0x53,       // PUSH RBX
		0x48, 0x83, 0xEC // SUB RSP, <BYTE>
	};
	BYTE prolog64_2_pattern[] = {
		0x55,            // PUSH RBP
		0x48, 0x8B, 0xEC // MOV RBP, RSP
	};
	BYTE prolog64_3_pattern[] = {
		0x40, 0x55,      // PUSH RBP
		0x48, 0x83, 0xEC // SUB RSP, <BYTE>
	};
	BYTE prolog64_4_pattern[] = {
		0x53,            // PUSH RBX
		0x48, 0x81, 0xEC // SUB RSP, <DWORD>
	};

	t_pattern patterns[] = {
		{ prolog64_pattern,   sizeof(prolog64_pattern) },
		{ prolog64_2_pattern, sizeof(prolog64_2_pattern) },
		{ prolog64_3_pattern, sizeof(prolog64_3_pattern) },
		{ prolog64_4_pattern, sizeof(prolog64_4_pattern) }
	};

	bool pattern_found = false;
	for (size_t i = 0; i < _countof(patterns); i++) {
		if (find_pattern(loadedData, loadedSize, patterns[i].ptr, patterns[i].size)) {
			pattern_found = true;
			//std::cout << "Found 64bit pattern: " << i << "\n";
			break;
		}
	}
	return pattern_found;
}

bool pesieve::util::is_code(BYTE *loadedData, size_t loadedSize)
{
	if (peconv::is_padding(loadedData, loadedSize, 0)) {
		return false;
	}
	if (is_32bit_code(loadedData, loadedSize)) {
		return true;
	}
	if (is_64bit_code(loadedData, loadedSize)) {
		return true;
	}
	return false;
}

bool pesieve::util::is_executable(DWORD mapping_type, DWORD protection)
{
	bool is_any_exec = false;

	if (mapping_type == MEM_IMAGE) {
		is_any_exec = (protection & SECTION_MAP_EXECUTE)
			|| (protection & SECTION_MAP_EXECUTE_EXPLICIT);

		if (is_any_exec) {
			return true;
		}
		// if false continue checking, because if the access was changed, MEM_IMAGE can has the same protection as other pages...
	}

	is_any_exec = (protection & PAGE_EXECUTE_READWRITE)
		|| (protection & PAGE_EXECUTE_READ)
		|| (protection & PAGE_EXECUTE)
		|| (protection & PAGE_EXECUTE_WRITECOPY);

	return is_any_exec;
}
