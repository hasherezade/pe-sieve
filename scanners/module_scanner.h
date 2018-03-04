#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "module_data.h"

class ModuleScanner {
public:
	ModuleScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}
	virtual ~ModuleScanner() {}

	virtual ModuleScanReport* scanRemote(ModuleData &moduleData, RemoteModuleData &remoteModData) = 0;

protected:
	HANDLE processHandle;
};
