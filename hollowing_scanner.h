#pragma once

#include <Windows.h>

#include "scanner.h"

class HollowingScanner : public ModuleScanner {
public:
	HollowingScanner(HANDLE hProc, std::string dir, std::string moduleName)
		: ModuleScanner(hProc, dir, moduleName)
	{
	}

	virtual t_scan_status scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size);
};
