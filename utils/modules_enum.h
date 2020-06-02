#pragma once

#include <windows.h>
#include <stdexcept>

namespace pesieve {
	namespace util {

		size_t enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters); //throws exceptions
	};
};
