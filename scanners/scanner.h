#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "scan_report.h"

#include "module_data.h"

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
	size_t scanModules(ProcessScanReport &pReport); //throws exceptions
	size_t scanWorkingSet(ProcessScanReport &pReport);  //throws exceptions

	size_t enumModules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters);  //throws exceptions

	t_scan_status scanForHollows(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report);
	t_scan_status scanForHooks(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report);

	HANDLE processHandle;
	size_t hModsMax;
	t_params args;
};

