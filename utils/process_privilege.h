#pragma once

#include <Windows.h>

typedef enum {
	INTEGRITY_UNKNOWN = -1,
	INTEGRITY_LOW = 0,
	INTEGRITY_MEDIUM, //1
	INTEGRITY_HIGH, //2
	INTEGRITY_SYSTEM //3
} process_integrity_t;

bool set_debug_privilege(DWORD process_id);

process_integrity_t get_integrity_level(HANDLE hProcess);
