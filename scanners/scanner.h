#pragma once

#include <windows.h>
#include <map>

#include <peconv.h>
#include "scan_report.h"
#include "module_data.h"

namespace pesieve {

	class ProcessScanner {
	public:
		ProcessScanner(HANDLE procHndl, pesieve::t_params _args)
			: args(_args), isDEP(false)
		{
			this->processHandle = procHndl;
			ZeroMemory(ignoredModules, _countof(ignoredModules));
			pesieve::util::delim_list_to_multi_sz(args.modules_ignored, PARAM_LIST_SEPARATOR, ignoredModules, _countof(ignoredModules));
		}

		~ProcessScanner()
		{
		}

		ProcessScanReport* scanRemote(); //throws exceptions

		static t_scan_status scanForHollows(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report);
		static t_scan_status scanForHooks(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, bool scan_data);
		static t_scan_status scanForIATHooks(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, bool filter);

	protected:
		size_t scanModules(ProcessScanReport &pReport); //throws exceptions
		size_t scanModulesIATs(ProcessScanReport &pReport); //throws exceptions
		size_t scanWorkingSet(ProcessScanReport &pReport);  //throws exceptions

		ModuleScanReport* scanForMappingMismatch(ModuleData& modData, ProcessScanReport& process_report);

		bool resolveHooksTargets(ProcessScanReport& process_report);
		bool filterDotNetReport(ProcessScanReport& process_report);

		HANDLE processHandle;
		bool isDEP;
		size_t hModsMax;
		pesieve::t_params args;

		char ignoredModules[MAX_MODULE_BUF_LEN];
	};

}; //namespace pesieve
