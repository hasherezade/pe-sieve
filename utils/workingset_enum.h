#pragma once

#include <windows.h>
#include <set>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

namespace pesieve {
	namespace util {
		size_t enum_workingset(HANDLE processHandle, std::set<ULONGLONG> &region_bases);
	};
};
