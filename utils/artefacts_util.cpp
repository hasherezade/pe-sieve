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
	BYTE prolog64_5_pattern[] = {
		0x48, 0x83, 0xE4, 0xF0 // AND rsp, FFFFFFFFFFFFFFF0; Align RSP to 16 bytes
	};
	BYTE prolog64_6_pattern[] = {
		0x57,            // PUSH RDI
		0x48, 0x89, 0xE7 // MOV RDI, RSP
	};
	BYTE prolog64_7_pattern[] = {
		 0x48, 0x8B, 0xC4, // MOV RAX, RSP
		 0x48, 0x89, 0x58, 0x08, // MOV QWORD PTR [RAX + 8], RBX
		 0x4C, 0x89, 0x48, 0x20, // MOV QWORD PTR [RAX + 0X20], R9
		 0x4C, 0x89, 0x40, 0x18, // MOV QWORD PTR [RAX + 0X18], R8
		 0x48, 0x89, 0x50, 0x10, // MOV QWORD PTR [RAX + 0X10], RDX
		 0x55, // PUSH RBP
		 0x56, // PUSH RSI
		 0x57, // PUSH RDI 
		 0x41, 0x54, // PUSH R12
		 0x41, 0x55, // PUSH R13
		 0x41, 0x56, // PUSH R14
		 0x41, 0x57 // PUSH R15
	};

	t_pattern patterns[] = {
		{ prolog64_pattern,   sizeof(prolog64_pattern) },
		{ prolog64_2_pattern, sizeof(prolog64_2_pattern) },
		{ prolog64_3_pattern, sizeof(prolog64_3_pattern) },
		{ prolog64_4_pattern, sizeof(prolog64_4_pattern) },
		{ prolog64_5_pattern, sizeof(prolog64_5_pattern) },
		{ prolog64_6_pattern, sizeof(prolog64_6_pattern) },
		{ prolog64_7_pattern, sizeof(prolog64_7_pattern) }
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
	const bool is_any_exec = (protection & PAGE_EXECUTE_READWRITE)
		|| (protection & PAGE_EXECUTE_READ)
		|| (protection & PAGE_EXECUTE)
		|| (protection & PAGE_EXECUTE_WRITECOPY);
	return is_any_exec;
}

bool pesieve::util::is_readable(DWORD mapping_type, DWORD protection)
{
	const bool is_read = (protection & PAGE_READWRITE)
		|| (protection & PAGE_READONLY);
	return is_read;
}

bool pesieve::util::is_normal_inaccessible(DWORD state, DWORD mapping_type, DWORD protection)
{
	if ((state & MEM_COMMIT) == 0) {
		//not committed
		return false;
	}
	if (mapping_type != MEM_IMAGE && (mapping_type != MEM_MAPPED) && mapping_type != MEM_PRIVATE) {
		// invalid mapping type
		return false;
	}
	if (protection & PAGE_NOACCESS) {
		// inaccessible found
		return true;
	}
	return false;
}
