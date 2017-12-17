#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include "scanner.h"

class HollowingScanner : public Scanner {
public:
	HollowingScanner(HANDLE hProc, std::string dir)
		: Scanner(hProc, dir)
	{
	}

	virtual t_scan_status scanModule(MODULEENTRY32 &module_entry, PBYTE original_module, size_t module_size);
};
