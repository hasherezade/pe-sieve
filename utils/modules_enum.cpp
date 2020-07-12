#include "modules_enum.h"

#include <psapi.h>
#pragma comment(lib,"psapi.lib")

size_t pesieve::util::enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters) //throws exceptions
{
	if (hProcess == nullptr) {
		return 0;
	}
	const char err_msg[] = "Could not enumerate modules. ";
	DWORD cbNeeded;
#ifdef _WIN64
	if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {
		throw std::runtime_error(err_msg);
		return 0;
	}
#else
	/*
	Some old, 32-bit versions of Windows do not have EnumProcessModulesEx,
	but we can use EnumProcessModules for the 32-bit version: it will work the same and prevent the compatibility issues.
	*/
	if (!EnumProcessModules(hProcess, hMods, hModsMax, &cbNeeded)) {
		throw std::runtime_error(err_msg);
		return 0;
	}
#endif
	const size_t modules_count = cbNeeded / sizeof(HMODULE);
	return modules_count;
}
