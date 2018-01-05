#pragma once

#include <Windows.h>

#include "scan_report.h"

class ModuleScanner {
public:
	ModuleScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}

	virtual ModuleScanReport* scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size) = 0;

protected:
	HANDLE processHandle;
};
