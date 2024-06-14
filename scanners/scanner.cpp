#include "scanner.h"

#include <sstream>
#include <fstream>
#include <string>
#include <locale>
#include <codecvt>

#include <tlhelp32.h>

#include "../utils/format_util.h"
#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
#include "../utils/modules_enum.h"
#include "../utils/process_privilege.h"
#include "../utils/process_util.h"

#include "headers_scanner.h"
#include "code_scanner.h"
#include "iat_scanner.h"
#include "workingset_scanner.h"
#include "mapping_scanner.h"
#include "hook_targets_resolver.h"
#include "thread_scanner.h"

using namespace pesieve;
using namespace pesieve::util;

namespace pesieve {

	bool validate_param_str(PARAM_STRING& strparam)
	{
		if (!strparam.buffer || strparam.length == 0) {
			return false;
		}
		if (IsBadReadPtr(strparam.buffer, strparam.length)) {
			return false;
		}
		return true;
	}

	namespace util {

		void print_scantime(std::stringstream& stream, size_t timeInMs)
		{
			float seconds = ((float)timeInMs / 1000);
			float minutes = ((float)timeInMs / 60000);
			stream << std::dec << timeInMs << " ms.";
			if (seconds > 0.5) {
				stream << " = " << seconds << " sec.";
			}
			if (minutes > 0.5) {
				stream << " = " << minutes << " min.";
			}
		}

	}; // namespace util

	void print_scan_time(const char* scanned_element, size_t total_time)
	{
		std::stringstream ss;
		ss << "[*] "<< scanned_element << " scanned in ";
		util::print_scantime(ss, total_time);
		std::cout << ss.str() << std::endl;
	}

};

pesieve::ProcessScanner::ProcessScanner(HANDLE procHndl, bool is_reflection, pesieve::t_params _args)
	: args(_args), isDEP(false), isReflection(is_reflection), symbols(procHndl)
{
	this->processHandle = procHndl;
	if (validate_param_str(args.modules_ignored)) {
		pesieve::util::string_to_list(args.modules_ignored.buffer, PARAM_LIST_SEPARATOR, ignoredModules);
	}
}

t_scan_status pesieve::ProcessScanner::scanForHollows(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	is_process_wow64(processHandle, &isWow64);
#endif
	HeadersScanner scanner(processHandle, modData, remoteModData);
	HeadersScanReport *scan_report = scanner.scanRemote();
	if (!scan_report) {
		return SCAN_ERROR;
	}
	
	if (scan_report->archMismatch && isWow64) {
#ifdef _DEBUG
		std::cout << "Arch mismatch, reloading..." << std::endl;
#endif
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = scanner.scanRemote();
		}
	}
	scan_report->moduleFile = modData.szModName;
	scan_report->isInPEB = modData.isModuleInPEBList();

	t_scan_status is_replaced = ModuleScanReport::get_scan_status(scan_report);
	if (is_replaced && !scan_report->isHdrReplaced()) {
		is_replaced = SCAN_NOT_SUSPICIOUS;
	}
	process_report.appendReport(scan_report);
	return is_replaced;
}

t_scan_status pesieve::ProcessScanner::scanForIATHooks(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, t_iat_scan_mode filter)
{
	const peconv::ExportsMapper *expMap = process_report.exportsMap;
	if (!expMap) {
		return SCAN_ERROR;
	}

	if (process_report.isModuleReplaced(modData.moduleHandle)) {
#ifdef _DEBUG
		std::cout << "Cannot scan replaced module for IAT hooks!\n";
#endif
		return SCAN_ERROR;
	}
	IATScanner scanner(processHandle, modData, remoteModData, *expMap, process_report.modulesInfo, filter);
	IATScanReport *scan_report = scanner.scanRemote();
	if (!scan_report) {
		return SCAN_ERROR;
	}
	t_scan_status scan_res = ModuleScanReport::get_scan_status(scan_report);
	scan_report->moduleFile = modData.szModName;
	process_report.appendReport(scan_report);
	return scan_res;
}

t_scan_status pesieve::ProcessScanner::scanForHooks(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, bool scan_data, bool scan_inaccessible)
{
	CodeScanner scanner(processHandle, modData, remoteModData);
	scanner.setScanData(scan_data);
	scanner.setScanInaccessible(scan_inaccessible);
	CodeScanReport *scan_report = scanner.scanRemote();
	if (!scan_report) {
		return SCAN_ERROR;
	}
	t_scan_status is_hooked = ModuleScanReport::get_scan_status(scan_report);

	scan_report->moduleFile = modData.szModName;
	process_report.appendReport(scan_report);
	return is_hooked;
}

bool pesieve::ProcessScanner::resolveHooksTargets(ProcessScanReport& process_report)
{
	HookTargetResolver hookResolver(process_report);
	std::set<ModuleScanReport*> &code_reports = process_report.reportsByType[ProcessScanReport::REPORT_CODE_SCAN];
	size_t resolved_count = hookResolver.resolveAllHooks(code_reports);
	return (resolved_count > 0);
}

inline bool set_non_suspicious(const std::set<ModuleScanReport*> &scan_reports, bool dnet_modules_only)
{
	bool is_set = false;
	std::set<ModuleScanReport*>::iterator itr;
	for (itr = scan_reports.begin(); itr != scan_reports.end(); ++itr) {
		ModuleScanReport* report = *itr;
		if (!report) {
			//this should never happen
			continue;
		}
		if (dnet_modules_only && !report->isDotNetModule) {
			continue;
		}
		if (report->status == SCAN_SUSPICIOUS) {
			report->status = SCAN_NOT_SUSPICIOUS;
			is_set = true;
		}
	}
	return is_set;
}

bool pesieve::ProcessScanner::filterDotNetReport(ProcessScanReport& process_report)
{
	if (!process_report.isManaged // Not a .NET process
		|| this->args.dotnet_policy == pesieve::PE_DNET_NONE) // .NET policy not set
	{
		return false; // no filtering needed
	}
	bool is_set = false;
	if (this->args.dotnet_policy == pesieve::PE_DNET_SKIP_MAPPING
		|| this->args.dotnet_policy == pesieve::PE_DNET_SKIP_ALL)
	{
		// set hook modules as not suspicious
		const std::set<ModuleScanReport*> &reports = process_report.reportsByType[ProcessScanReport::REPORT_MAPPING_SCAN];
		is_set = set_non_suspicious(reports, true);
	}
	if (this->args.dotnet_policy == pesieve::PE_DNET_SKIP_HOOKS
		|| this->args.dotnet_policy == pesieve::PE_DNET_SKIP_ALL)
	{
		// set hook modules as not suspicious
		const std::set<ModuleScanReport*> &reports = process_report.reportsByType[ProcessScanReport::REPORT_CODE_SCAN];
		is_set = set_non_suspicious(reports, false);
	}
	if (this->args.dotnet_policy == pesieve::PE_DNET_SKIP_SHC
		|| this->args.dotnet_policy == pesieve::PE_DNET_SKIP_ALL)
	{
		// set shellcodes detected by mempage scan as not suspicious
		const std::set<ModuleScanReport*> &reports = process_report.reportsByType[ProcessScanReport::REPORT_MEMPAGE_SCAN];
		const bool is_set1 = set_non_suspicious(reports, false);

		// set shellcodes detected by thread scan as not-suspicious
		const std::set<ModuleScanReport*>& reports2 = process_report.reportsByType[ProcessScanReport::REPORT_THREADS_SCAN];
		const bool is_set2 = set_non_suspicious(reports2, false);
		is_set = is_set1 || is_set2;
	}
	return is_set;
}

ProcessScanReport* pesieve::ProcessScanner::scanRemote()
{
	this->isDEP = is_DEP_enabled(this->processHandle);

	const bool is_64bit = pesieve::util::is_process_64bit(this->processHandle);

	ProcessScanReport *pReport = new ProcessScanReport(this->args.pid, is_64bit, this->isReflection, &this->args);

	char image_buf[MAX_PATH] = { 0 };
	GetProcessImageFileNameA(this->processHandle, image_buf, MAX_PATH);
	pReport->mainImagePath = device_path_to_win32_path(image_buf);

	std::stringstream errorsStr;

	// scan modules
	size_t modulesScanned = 0;
	try {
		modulesScanned = scanModules(*pReport);
	} catch (std::exception &e) {
		modulesScanned = 0;
		errorsStr << e.what();
	}

	// scan working set
	size_t regionsScanned = 0;
	try {
		regionsScanned = scanWorkingSet(*pReport);
	} catch (std::exception &e) {
		regionsScanned = 0;
		errorsStr << e.what();
	}

	// scan IATs
	size_t iatsScanned = 0;
	if (args.iat) {
		try {
			iatsScanned = scanModulesIATs(*pReport);
		}
		catch (std::exception& e) {
			iatsScanned = 0;
			errorsStr << e.what();
		}
	}

	// scan threads
	size_t threadsScanned = 0;
	if (args.threads) {
		try {
			threadsScanned = scanThreads(*pReport);
		}
		catch (std::exception& e) {
			threadsScanned = 0;
			errorsStr << e.what();
		}
	}

	// throw error only if none of the scans was successful
	if (!modulesScanned && !iatsScanned && !regionsScanned && !threadsScanned) {
		throw std::runtime_error(errorsStr.str());
	}
	//post-process hooks
	resolveHooksTargets(*pReport);

	//post-process detection reports according to the .NET policy
	filterDotNetReport(*pReport);
	return pReport;
}

size_t pesieve::ProcessScanner::scanWorkingSet(ProcessScanReport &pReport) //throws exceptions
{
	if (!util::count_workingset_entries(this->processHandle)) {
		throw std::runtime_error("Could not query the working set. ");
		return 0;
	}
	process_details proc_details(this->isReflection, this->isDEP);

	DWORD start_tick = GetTickCount();
	std::set<mem_region_info> region_bases;
	size_t pages_count = util::enum_workingset(processHandle, region_bases);
	if (!args.quiet) {
		std::cout << "Scanning workingset: " << std::dec << pages_count << " memory regions." << std::endl;
	}
	size_t counter = 0;
	//now scan all the nodes:

	for (auto set_itr = region_bases.begin(); set_itr != region_bases.end(); ++set_itr, ++counter) {
		const mem_region_info region = *set_itr;

		WorkingSetScanner scanner(this->processHandle, proc_details, region, this->args, pReport);
		WorkingSetScanReport *my_report = scanner.scanRemote();
		if (!my_report) {
			continue;
		}
		my_report->is_listed_module = pReport.hasModule((ULONGLONG) my_report->module);
		// this is a code section inside a PE file that was already detected
		if (!my_report->has_pe 
			&& (pReport.hasModuleContaining((ULONGLONG)my_report->module, my_report->moduleSize))
			)
		{
			my_report->status = SCAN_NOT_SUSPICIOUS;
		}

		pReport.appendReport(my_report);
	}
	if (!args.quiet) {
		const DWORD total_time = GetTickCount() - start_tick;
		print_scan_time("Workingset", total_time);
	}
	return counter;
}

ModuleScanReport* pesieve::ProcessScanner::scanForMappingMismatch(ModuleData& modData, ProcessScanReport& process_report)
{
	MappingScanner scanner(processHandle, modData);
	MappingScanReport *scan_report = scanner.scanRemote();

	process_report.appendReport(scan_report);
	return scan_report;
}

size_t pesieve::ProcessScanner::scanModules(ProcessScanReport &pReport)  //throws exceptions
{
	HMODULE hMods[1024] = { 0 };
	const size_t modules_count = enum_modules(this->processHandle, hMods, sizeof(hMods), LIST_MODULES_ALL);
	if (modules_count == 0) {
		return 0;
	}
	if (args.imprec_mode != PE_IMPREC_NONE || args.iat != pesieve::PE_IATS_NONE) {
		pReport.exportsMap = new peconv::ExportsMapper();
	}

	size_t counter = 0;
	for (counter = 0; counter < modules_count; counter++) {
		if (processHandle == nullptr) break;
		const HMODULE module_base = hMods[counter];
		//load module from file:
		ModuleData modData(processHandle, module_base, true, args.use_cache);
		ModuleScanReport *mappingScanReport = this->scanForMappingMismatch(modData, pReport);

		//load the original file to make the comparisons:
		if (!modData.loadOriginal()) {
			if (!args.quiet) {
				std::cout << "[!][" << args.pid << "] Suspicious: could not read the module file!" << std::endl;
			}
			//make a report that finding original module was not possible
			pReport.appendReport(new UnreachableModuleReport(module_base, 0, modData.szModName));
			continue;
		}
		if (modData.isDotNet()) {
			// the process contains at least one .NET module. Treat it as managed process:
			pReport.isManaged = true;
		}
		// Don't scan modules that are in the ignore list
		const std::string plainName = peconv::get_file_name(modData.szModName);
		if (is_in_list(plainName, this->ignoredModules)) {
			// ...but add such modules to the exports lookup:
			if (pReport.exportsMap) {
				pReport.exportsMap->add_to_lookup(modData.szModName, (HMODULE)modData.original_module, (ULONGLONG)modData.moduleHandle);
			}
			if (!args.quiet) {
				std::cout << "[*] Skipping ignored: " << std::hex << (ULONGLONG)modData.moduleHandle << " : " << modData.szModName << std::endl;
			}
			pReport.appendReport(new SkippedModuleReport(modData.moduleHandle, modData.original_size, modData.szModName));
			continue;
		}

		if (!args.quiet) {
			std::cout << "[*] Scanning: " << modData.szModName;
			if (modData.isDotNet()) {
				std::cout << " (.NET) ";
			}
			std::cout << std::endl;
		}
		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, this->isReflection, module_base);
		if (!remoteModData.isInitialized()) {
			//make a report that initializing remote module was not possible
			pReport.appendReport(new MalformedHeaderReport(module_base, 0, modData.szModName));
			continue;
		}
		t_scan_status is_hollowed = scanForHollows(processHandle, modData, remoteModData, pReport);
		if (is_hollowed == SCAN_ERROR) {
			continue;
		}
		if (is_hollowed == SCAN_NOT_SUSPICIOUS) {
			//if the content does not differ, ignore the different name of the mapped file
			mappingScanReport->status = SCAN_NOT_SUSPICIOUS;
		}

		// the module is not hollowed, so we can add it to the exports lookup:
		if (pReport.exportsMap) {
			pReport.exportsMap->add_to_lookup(modData.szModName, (HMODULE) modData.original_module, (ULONGLONG) modData.moduleHandle);
		}

		if (!args.no_hooks //if hooks not disabled
			&& (is_hollowed == SCAN_NOT_SUSPICIOUS) // and process is not hollowed
			) 
		{
			const bool scan_data = ((this->args.data >= pesieve::PE_DATA_SCAN_ALWAYS) && (this->args.data != pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY))
				|| (!this->isDEP && (this->args.data == pesieve::PE_DATA_SCAN_NO_DEP));
			
			const bool scan_inaccessible = (this->isReflection && (this->args.data >= PE_DATA_SCAN_INACCESSIBLE));
			scanForHooks(processHandle, modData, remoteModData, pReport, scan_data, scan_inaccessible);
		}
	}
	return counter;
}

size_t pesieve::ProcessScanner::scanModulesIATs(ProcessScanReport &pReport) //throws exceptions
{
	if (!pReport.exportsMap) {
		return 0; // this feature cannot work without Exports Map
	}
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(this->processHandle, hMods, sizeof(hMods), LIST_MODULES_ALL);
	if (modules_count == 0) {
		return 0;
	}
	if (!args.quiet) {
		std::cout << "Scanning for IAT hooks: " << modules_count << " modules." << std::endl;
	}
	DWORD start_tick = GetTickCount();
	size_t counter = 0;
	for (counter = 0; counter < modules_count; counter++) {
		if (!processHandle) break; // this should never happen

		const HMODULE module_base = hMods[counter];
		//load module from file:
		ModuleData modData(processHandle, module_base, true, args.use_cache);

		// Don't scan modules that are in the ignore list
		std::string plainName = peconv::get_file_name(modData.szModName);
		if (is_in_list(plainName, this->ignoredModules)) {
			continue;
		}

		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, this->isReflection, module_base);
		if (remoteModData.isInitialized() == false) {
			//make a report that initializing remote module was not possible
			pReport.appendReport(new MalformedHeaderReport(module_base, 0, modData.szModName));
			continue;
		}

		// do the IAT scan:
		scanForIATHooks(processHandle, modData, remoteModData, pReport, this->args.iat);
	}
	if (!args.quiet) {
		const DWORD total_time = GetTickCount() - start_tick;
		print_scan_time("IATs", total_time);
	}
	return counter;
}


size_t pesieve::ProcessScanner::scanThreads(ProcessScanReport& pReport) //throws exceptions
{
	if (!this->symbols.InitSymbols()) {
		std::cerr << "Failed to initialize symbols!\n";
		return 0;
	}

	const DWORD pid = pReport.pid; //original PID, not a reflection!

	const bool is_64bit = pesieve::util::is_process_64bit(this->processHandle);
#ifndef _WIN64
	if (is_64bit) return 0;
#endif

	if (!args.quiet) {
		std::cout << "Scanning threads." << std::endl;
	}
	DWORD start_tick = GetTickCount();

	std::vector<thread_info> threads_info;
	if (!pesieve::util::fetch_threads_info(pid, threads_info)) { //extended info, but doesn't work on old Windows...

		if (!pesieve::util::fetch_threads_by_snapshot(pid, threads_info)) { // works on old Windows, but gives less data..

			if (!args.quiet) {
				std::cout << "[-] Failed enumerating threads." << std::endl;
			}
			return 0;
		}
	}

	std::vector<thread_info>::iterator itr;
	for (itr = threads_info.begin(); itr != threads_info.end(); ++itr) {
		const thread_info &info = *itr;
		
		ThreadScanner scanner(this->processHandle, this->isReflection, info,  pReport.modulesInfo, pReport.exportsMap);
		ThreadScanReport* report = scanner.scanRemote();
		pReport.appendReport(report);
	}
	if (!args.quiet) {
		const DWORD total_time = GetTickCount() - start_tick;
		print_scan_time("Threads", total_time);
	}
	return 0;
}
