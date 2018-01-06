#pragma once

#include <Windows.h>
#include <map>

#include "peconv.h"

#include "scan_report.h"

class ModuleScanner {
public:
	ModuleScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}
	virtual ~ModuleScanner() {}

	virtual ModuleScanReport* scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size) = 0;

protected:
	HANDLE processHandle;
};

class ProcessScanner {
public:
	ProcessScanner(HANDLE procHndl, t_params _args)
		: args(_args)
	{
		this->processHandle = procHndl;
		this->exportsMap = nullptr;
		ProcessScanReport *process_report = new ProcessScanReport(this->args.pid);
	}

	~ProcessScanner()
	{
		delete exportsMap;
	}

	ProcessScanReport* scanRemote();
	size_t dumpAllModified(ProcessScanReport &process_report, std::string directory);

protected:
	size_t enum_modules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters);
	t_scan_status get_scan_status(ModuleScanReport *report);

	HANDLE processHandle;
	size_t hModsMax;
	t_params args;
	peconv::ExportsMapper* exportsMap;
};
