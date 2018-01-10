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

	bool convertPath();
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
	}

	~ProcessScanner()
	{
	}

	ProcessScanReport* scanRemote(); //throws exceptions

protected:
	size_t enumModules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters); //throws exceptions

	t_scan_status scanForHollows(ModuleData& modData, ProcessScanReport& process_report);
	t_scan_status scanForHooks(ModuleData& modData, ProcessScanReport& process_report);

	HANDLE processHandle;
	size_t hModsMax;
	t_params args;
};

