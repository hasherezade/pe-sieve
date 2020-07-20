#include "scanner.h"

#include <sstream>
#include <fstream>

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

#include <string>
#include <locale>
#include <codecvt>

#include <psapi.h>
#pragma comment(lib,"psapi.lib")

using namespace pesieve;
using namespace pesieve::util;

t_scan_status pesieve::ProcessScanner::scanForHollows(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	is_process_wow64(processHandle, &isWow64);
#endif
	HeadersScanner hollows(processHandle, modData, remoteModData);
	HeadersScanReport *scan_report = hollows.scanRemote();
	if (!scan_report) {
		process_report.appendReport(new UnreachableModuleReport(processHandle, modData.moduleHandle, modData.original_size, modData.szModName));
		return SCAN_ERROR;
	}
	
	if (scan_report->archMismatch && isWow64) {
#ifdef _DEBUG
		std::cout << "Arch mismatch, reloading..." << std::endl;
#endif
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = hollows.scanRemote();
		}
	}
	scan_report->moduleFile = modData.szModName;

	t_scan_status is_suspicious = ModuleScanReport::get_scan_status(scan_report);
	if (is_suspicious && !scan_report->isHdrReplaced()) {
		is_suspicious = SCAN_NOT_SUSPICIOUS;
	}
	process_report.appendReport(scan_report);
	return is_suspicious;
}

t_scan_status pesieve::ProcessScanner::scanForIATHooks(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report, bool filter)
{
	const peconv::ExportsMapper *expMap = process_report.exportsMap;
	if (!expMap) {
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

t_scan_status pesieve::ProcessScanner::scanForHooks(HANDLE processHandle, ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	CodeScanner hooks(processHandle, modData, remoteModData);

	CodeScanReport *scan_report = hooks.scanRemote();
	if (!scan_report) return SCAN_ERROR;

	t_scan_status is_hooked = ModuleScanReport::get_scan_status(scan_report);

	scan_report->moduleFile = modData.szModName;
	process_report.appendReport(scan_report);
	return is_hooked;
}

bool pesieve::ProcessScanner::resolveHooksTargets(ProcessScanReport& process_report)
{
	HookTargetResolver hookResolver(process_report, this->processHandle);
	const std::set<ModuleScanReport*> &code_reports = process_report.reportsByType[ProcessScanReport::REPORT_CODE_SCAN];
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
	if (!process_report.isManaged || this->args.dotnet_policy == pesieve::PE_DNET_NONE) {
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
		// set shellcodes as not suspicious
		const std::set<ModuleScanReport*> &reports = process_report.reportsByType[ProcessScanReport::REPORT_MEMPAGE_SCAN];
		is_set = set_non_suspicious(reports, false);
	}
	return is_set;
}

ProcessScanReport* pesieve::ProcessScanner::scanRemote()
{
	this->isDEP = is_DEP_enabled(this->processHandle);

	const bool is_64bit = pesieve::util::is_process_64bit(this->processHandle);

	ProcessScanReport *pReport = new ProcessScanReport(this->args.pid, is_64bit);

	char image_buf[MAX_PATH] = { 0 };
	GetProcessImageFileNameA(this->processHandle, image_buf, MAX_PATH);
	pReport->mainImagePath = device_path_to_win32_path(image_buf);

	std::stringstream errorsStr;

	// scan modules
	size_t modulesScanned = 0;
	size_t iatsScanned = 0;
	try {
		modulesScanned = scanModules(*pReport);
		if (args.iat) {
			iatsScanned = scanModulesIATs(*pReport);
		}
	} catch (std::exception &e) {
		modulesScanned = 0;
		iatsScanned = 0;
		errorsStr << e.what();
	}

	// scan working set
	size_t regionsScanned = 0;
	try {
		//dont't scan your own working set
		if (peconv::get_process_id(this->processHandle) != GetCurrentProcessId()) {
			regionsScanned = scanWorkingSet(*pReport);
		}
	} catch (std::exception &e) {
		regionsScanned = 0;
		errorsStr << e.what();
	}

	// throw error only if none of the scans was successful
	if (!modulesScanned && !iatsScanned && !regionsScanned) {
		throw std::runtime_error(errorsStr.str());
	}
	//post-process hooks
	resolveHooksTargets(*pReport);

	//post-process .NET modules
	filterDotNetReport(*pReport);
	return pReport;
}

size_t pesieve::ProcessScanner::scanWorkingSet(ProcessScanReport &pReport) //throws exceptions
{
	PSAPI_WORKING_SET_INFORMATION wsi_1 = { 0 };
	BOOL result = QueryWorkingSet(this->processHandle, (LPVOID)&wsi_1, sizeof(PSAPI_WORKING_SET_INFORMATION));
	if (result == FALSE && GetLastError() != ERROR_BAD_LENGTH) {
		/**
		Allow to proceed on ERROR_BAD_LENGTH.
		ERROR_BAD_LENGTH may occur if the scanner is 32 bit and running on a 64 bit system.
		In case of any different error, break.
		*/
		throw std::runtime_error("Could not query the working set. ");
		return 0;
	}
#ifdef _DEBUG
	std::cout << "Number of entries: " << std::dec << wsi_1.NumberOfEntries << std::endl;
#endif

	DWORD start_tick = GetTickCount();
	std::set<ULONGLONG> region_bases;
	size_t pages_count = enum_workingset(processHandle, region_bases);
	if (!args.quiet) {
		std::cout << "Scanning workingset: " << std::dec << pages_count << " memory regions." << std::endl;
	}
	size_t counter = 0;
	//now scan all the nodes:
	std::set<ULONGLONG>::iterator set_itr;
	for (set_itr = region_bases.begin(); set_itr != region_bases.end(); ++set_itr, ++counter) {
		const ULONGLONG region_base = *set_itr;

		MemPageData memPage(this->processHandle, region_base);

		memPage.is_listed_module = pReport.hasModule(region_base);
		memPage.is_dep_enabled = this->isDEP;

		WorkingSetScanner memPageScanner(this->processHandle, memPage, this->args, pReport);
		WorkingSetScanReport *my_report = memPageScanner.scanRemote();
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
		DWORD total_time = GetTickCount() - start_tick;
		std::cout << "[*] Workingset scanned in " << std::dec << total_time << " ms" << std::endl;
	}
	return counter;
}

ModuleScanReport* pesieve::ProcessScanner::scanForMappingMismatch(ModuleData& modData, ProcessScanReport& process_report)
{
	MappingScanner mappingScanner(processHandle, modData);

	MappingScanReport *scan_report = mappingScanner.scanRemote();
	t_scan_status is_doppel = ModuleScanReport::get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	return scan_report;
}

size_t pesieve::ProcessScanner::scanModules(ProcessScanReport &pReport)  //throws exceptions
{
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(this->processHandle, hMods, sizeof(hMods), args.modules_filter);
	if (modules_count == 0) {
		return 0;
	}
	if (args.imprec_mode != PE_IMPREC_NONE || args.iat != pesieve::PE_IATS_NONE) {
		pReport.exportsMap = new peconv::ExportsMapper();
	}

	size_t counter = 0;
	for (counter = 0; counter < modules_count; counter++) {
		if (processHandle == nullptr) break;

		//load module from file:
		ModuleData modData(processHandle, hMods[counter]);
		ModuleScanReport *mappingScanReport = this->scanForMappingMismatch(modData, pReport);

		//load the original file to make the comparisons:
		if (!modData.loadOriginal()) {
			if (!args.quiet) {
				std::cout << "[!][" << args.pid << "] Suspicious: could not read the module file!" << std::endl;
			}
			//make a report that finding original module was not possible
			pReport.appendReport(new UnreachableModuleReport(processHandle, hMods[counter], 0, modData.szModName));
			continue;
		}

		// Don't scan modules that are in the ignore list
		std::string plainName = peconv::get_file_name(modData.szModName);
		if (is_in_list(plainName.c_str(), this->ignoredModules)) {
			// ...but add such modules to the exports lookup:
			if (pReport.exportsMap && modData.loadOriginal()) {
				pReport.exportsMap->add_to_lookup(modData.szModName, (HMODULE)modData.original_module, (ULONGLONG)modData.moduleHandle);
			}
			if (!args.quiet) {
				std::cout << "[*] Skipping ignored: " << std::hex << (ULONGLONG)modData.moduleHandle << " : " << modData.szModName << std::endl;
			}
			pReport.appendReport(new SkippedModuleReport(processHandle, modData.moduleHandle, modData.original_size, modData.szModName));
			continue;
		}
		if (!args.quiet) {
			std::cout << "[*] Scanning: " << modData.szModName << std::endl;
		}
		if (modData.isDotNet()) {
			pReport.isManaged = true;
#ifdef _DEBUG
			std::cout << "[*] Skipping a .NET module: " << modData.szModName << std::endl;
#endif
			pReport.appendReport(new SkippedModuleReport(processHandle, modData.moduleHandle, modData.original_size, modData.szModName));
			continue;
		}
		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, hMods[counter]);
		if (remoteModData.isInitialized() == false) {
			//make a report that initializing remote module was not possible
			pReport.appendReport(new MalformedHeaderReport(processHandle, hMods[counter], 0, modData.szModName));
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
		if (pReport.exportsMap != nullptr) {
			pReport.exportsMap->add_to_lookup(modData.szModName, (HMODULE) modData.original_module, (ULONGLONG) modData.moduleHandle);
		}
		// if hooks not disabled and process is not hollowed, check for hooks:
		if (!args.no_hooks && (is_hollowed == SCAN_NOT_SUSPICIOUS)) {
			scanForHooks(processHandle, modData, remoteModData, pReport);
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
	const size_t modules_count = enum_modules(this->processHandle, hMods, sizeof(hMods), args.modules_filter);
	if (modules_count == 0) {
		return 0;
	}

	size_t counter = 0;
	for (counter = 0; counter < modules_count; counter++) {
		if (processHandle == nullptr) break;

		//load module from file:
		ModuleData modData(processHandle, hMods[counter]);

		// Don't scan modules that are in the ignore list
		std::string plainName = peconv::get_file_name(modData.szModName);
		if (is_in_list(plainName.c_str(), this->ignoredModules)) {
			continue;
		}

		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, hMods[counter]);
		if (remoteModData.isInitialized() == false) {
			//make a report that initializing remote module was not possible
			pReport.appendReport(new MalformedHeaderReport(processHandle, hMods[counter], 0, modData.szModName));
			continue;
		}

		bool filterSysHooks = (this->args.iat == pesieve::PE_IATS_FILTERED) ? true : false;
		t_scan_status is_iat_patched = scanForIATHooks(processHandle, modData, remoteModData, pReport, filterSysHooks);
		if (is_iat_patched == SCAN_ERROR) {
			continue;
		}
	}
	return counter;
}
