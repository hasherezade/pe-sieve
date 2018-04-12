#include "modules_enum.h"

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

size_t enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters) //throws exceptions
{
	if (hProcess == nullptr) return 0;

	DWORD cbNeeded;
#ifdef _WIN64
	if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {
		throw std::exception("Could not enumerate modules in the process. ", GetLastError());
		return 0;
	}
#else
	if (!EnumProcessModules(hProcess, hMods, hModsMax, &cbNeeded)) {
		throw std::exception("Could not enumerate modules in the process. ", GetLastError());
		return 0;
	}
#endif
	const size_t modules_count = cbNeeded / sizeof(HMODULE);
	return modules_count;
}
