#pragma once

#include <windows.h>
#include <map>

#include <peconv.h>
#include "scan_report.h"
#include "module_data.h"

namespace pesieve {

	//!  The root scanner, responsible for enumerating all the elements to be scanned within a given process, and performing apropriate scans on them.
	class ProcessScanner {
	public:

		/**
		A constructor of ProcessScanner.
		\param procHndl : a HANDLE to the process to be scanned (must be opened with appropriate access rights)
		\param is_reflection : a flag indicating if the given handle (procHndl) leads to a raw process, or the process reflection
		\param args : the configuration of the scan (defined as t_params)
		*/
		ProcessScanner(HANDLE procHndl, bool is_reflection, pesieve::t_params _args)
			: args(_args), isDEP(false), isReflection(is_reflection)
		{
			this->processHandle = procHndl;
			pesieve::util::delim_list_to_multi_sz(args.modules_ignored, PARAM_LIST_SEPARATOR, ignoredModules);
		}

		~ProcessScanner()
		{
		}

		//!  The main function of ProcessScanner, deploying the scan. Throws exceptions in case of a failure.
		/**
		\return pointer to the generated report of type ProcessScanReport
		*/
		ProcessScanReport* scanRemote(); //throws exceptions

		static t_scan_status scanForHollows(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report);
		static t_scan_status scanForHooks(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, bool scan_data, bool scan_inaccessible);
		static t_scan_status scanForIATHooks(HANDLE hProcess, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, t_iat_scan_mode filter);

	protected:
		size_t scanModules(ProcessScanReport &pReport); //throws exceptions
		size_t scanModulesIATs(ProcessScanReport &pReport); //throws exceptions
		size_t scanWorkingSet(ProcessScanReport &pReport);  //throws exceptions

		ModuleScanReport* scanForMappingMismatch(ModuleData& modData, ProcessScanReport& process_report);

		bool resolveHooksTargets(ProcessScanReport& process_report);
		bool filterDotNetReport(ProcessScanReport& process_report);

		HANDLE processHandle;
		bool isDEP;
		const bool isReflection;
		size_t hModsMax;
		pesieve::t_params args;

		std::string ignoredModules;
	};

}; //namespace pesieve
