#pragma once

#include <Windows.h>

#include "scanner.h"

class HollowingScanner : public ModuleScanner {
public:
	HollowingScanner(HANDLE hProc, std::string dir)
		: ModuleScanner(hProc, dir)
	{
	}

	virtual t_scan_status scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size);
};
