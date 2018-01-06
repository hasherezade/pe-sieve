#pragma once

#include <Windows.h>
#include <map>

#include "peconv.h"

#include "scan_report.h"

class ModuleData {

public:
	ModuleData(HANDLE _processHandle, HMODULE _module)
		: processHandle(_processHandle), moduleHandle(_module),
		is_module_named(false), original_size(0), original_module(nullptr)
	{
		memset(szModName, 0, MAX_PATH);
	}

	~ModuleData()
	{
		peconv::free_pe_buffer(original_module, original_size);
	}

	bool loadOriginal();
	bool reloadWow64();

	HANDLE processHandle;
	HMODULE moduleHandle;
	char szModName[MAX_PATH];
	bool is_module_named;

	PBYTE original_module;
	size_t original_size;
};

class ModuleScanner {
public:
	ModuleScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}
	virtual ~ModuleScanner() {}

	virtual ModuleScanReport* scanRemote(ModuleData &moduleData) = 0;

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
	t_scan_status scan_for_hollows(PBYTE modBaseAddr, ProcessScanReport *process_report);


protected:
	size_t enum_modules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters);
	t_scan_status get_scan_status(ModuleScanReport *report);

	HANDLE processHandle;
	size_t hModsMax;
	t_params args;
	peconv::ExportsMapper* exportsMap;
};
