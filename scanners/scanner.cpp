#include "scanner.h"

#include <sstream>
#include <fstream>

#include "../utils/util.h"
#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
#include "../utils/modules_enum.h"

#include "hollowing_scanner.h"
#include "hook_scanner.h"
#include "mempage_scanner.h"
#include "mapping_scanner.h"

#include <string>
#include <locale>
#include <codecvt>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

t_scan_status ProcessScanner::scanForHollows(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HollowingScanner hollows(processHandle, modData, remoteModData);
	HeadersScanReport *scan_report = hollows.scanRemote();
	if (scan_report == nullptr) {
		process_report.appendReport(new MalformedHeaderReport(processHandle, modData.moduleHandle, modData.original_size));
		return SCAN_ERROR;
	}
	t_scan_status is_hollowed = ModuleScanReport::get_scan_status(scan_report);

	if (scan_report->archMismatch && isWow64) {
#ifdef _DEBUG
		std::cout << "Arch mismatch, reloading..." << std::endl;
#endif
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = hollows.scanRemote();
		}
		is_hollowed = ModuleScanReport::get_scan_status(scan_report);
	}
	process_report.appendReport(scan_report);
	return is_hollowed;
}

t_scan_status ProcessScanner::scanForHooks(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	HookScanner hooks(processHandle, modData, remoteModData);

	CodeScanReport *scan_report = hooks.scanRemote();
	t_scan_status is_hooked = ModuleScanReport::get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	
	if (is_hooked != SCAN_SUSPICIOUS) {
		return is_hooked;
	}
	return is_hooked;
}

ProcessScanReport* ProcessScanner::scanRemote()
{
	ProcessScanReport *pReport = new ProcessScanReport(this->args.pid);

	char image_buf[MAX_PATH] = { 0 };
	GetProcessImageFileNameA(this->processHandle, image_buf, MAX_PATH);
	pReport->mainImagePath = device_path_to_win32_path(image_buf);

	std::stringstream errorsStr;

	// scan modules
	bool modulesScanned = true;
	try {
		size_t scanned = scanModules(*pReport);
		if (scanned == 0) {
			modulesScanned = false;
			errorsStr << "No modules found!";
		}
	} catch (std::exception &e) {
		modulesScanned = false;
		errorsStr << e.what();
	}

	// scan working set
	bool workingsetScanned = true;
	try {
		//dont't scan your own working set
		if (GetProcessId(this->processHandle) != GetCurrentProcessId()) {
			scanWorkingSet(*pReport);
		}
	} catch (std::exception &e) {
		workingsetScanned = false;
		errorsStr << e.what();
	}

	// throw error only if both scans has failed:
	if (!modulesScanned && !modulesScanned) {
		throw std::runtime_error(errorsStr.str());
	}
	return pReport;
}

size_t ProcessScanner::scanWorkingSet(ProcessScanReport &pReport) //throws exceptions
{
	PSAPI_WORKING_SET_INFORMATION wsi_1 = { 0 };
	BOOL result = QueryWorkingSet(this->processHandle, (LPVOID)&wsi_1, sizeof(PSAPI_WORKING_SET_INFORMATION));
	if (result == FALSE && GetLastError() != ERROR_BAD_LENGTH) {
		throw std::runtime_error("Could not scan the working set in the process. ");
		return 0;
	}
#ifdef _DEBUG
	std::cout << "Number of entries: " << std::dec << wsi_1.NumberOfEntries << std::endl;
#endif

#ifdef _DEBUG
	DWORD start_tick = GetTickCount();
#endif
	std::set<ULONGLONG> region_bases;
	size_t pages_count = enum_workingset(processHandle, region_bases);
	if (!args.quiet) {
		std::cout << "Scanning workingset: " << std::dec << pages_count << " memory regions." << std::endl;
	}
	size_t counter = 0;
	//now scan all the nodes:
	std::set<ULONGLONG>::iterator set_itr;
	for (set_itr = region_bases.begin(); set_itr != region_bases.end(); set_itr++) {
		ULONGLONG region_base = *set_itr;

		MemPageData memPage(this->processHandle, region_base);
		//if it was already scanned, it means the module was on the list of loaded modules
		memPage.is_listed_module = pReport.hasModule(region_base);

		MemPageScanner memPageScanner(this->processHandle, memPage, this->args.shellcode);
		MemPageScanReport *my_report = memPageScanner.scanRemote();

		counter++;
		if (my_report == nullptr) continue;

		my_report->is_listed_module = pReport.hasModule((ULONGLONG) my_report->module);
		// this is a code section inside a PE file that was already detected
		if (!my_report->has_pe && pReport.hasModuleContaining((ULONGLONG)my_report->module)) {
			my_report->status = SCAN_NOT_SUSPICIOUS;
		}

		pReport.appendReport(my_report);
		/*if (ModuleScanReport::get_scan_status(my_report) == SCAN_SUSPICIOUS) {
			if (my_report->is_manually_loaded) {
				pReport.summary.implanted++;
			}
		}*/
	}
#ifdef _DEBUG
	DWORD total_time = GetTickCount() - start_tick;
	std::cout << "Workingset scan time: " << std::dec << total_time << std::endl;
#endif

	return counter;
}

ModuleScanReport* ProcessScanner::scanForMappingMismatch(ModuleData& modData, ProcessScanReport& process_report)
{
	MappingScanner mappingScanner(processHandle, modData);

	MappingScanReport *scan_report = mappingScanner.scanRemote();
	t_scan_status is_doppel = ModuleScanReport::get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	return scan_report;
}

size_t ProcessScanner::scanModules(ProcessScanReport &pReport)  //throws exceptions
{
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(this->processHandle, hMods, sizeof(hMods), args.modules_filter);
	if (modules_count == 0) {
		return 0;
	}
	if (args.imp_rec) {
		pReport.exportsMap = new peconv::ExportsMapper();
	}

	size_t counter = 0;
	for (counter = 0; counter < modules_count; counter++) {
		if (processHandle == nullptr) break;

		//load module from file:
		ModuleData modData(processHandle, hMods[counter]);

		ModuleScanReport *mappingScanReport = this->scanForMappingMismatch(modData, pReport);

		if (!modData.loadOriginal()) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			//make a report that finding original module was not possible
			pReport.appendReport(new UnreachableModuleReport(processHandle, hMods[counter], 0));
			continue;
		}
		if (!args.quiet) {
			std::cout << "[*] Scanning: " << modData.szModName << std::endl;
		}

		if (modData.isDotNet()) {
#ifdef _DEBUG
			std::cout << "[*] Skipping a .NET module: " << modData.szModName << std::endl;
#endif
			pReport.appendReport(new SkippedModuleReport(processHandle, modData.moduleHandle, modData.original_size));
			continue;
		}
		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, hMods[counter]);
		if (remoteModData.isInitialized() == false) {
			//make a report that initializing remote module was not possible
			pReport.appendReport(new MalformedHeaderReport(processHandle, hMods[counter], 0));
			continue;
		}
		t_scan_status is_hollowed = scanForHollows(modData, remoteModData, pReport);
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
			scanForHooks(modData, remoteModData, pReport);
		}
	}
	return counter;
}
