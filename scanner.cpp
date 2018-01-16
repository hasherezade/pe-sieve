#include "scanner.h"


#include <sstream>
#include <fstream>

#include "utils/util.h"

#include "hollowing_scanner.h"
#include "hook_scanner.h"
#include "utils/path_converter.h"

#include <string>
#include <locale>
#include <codecvt>

//---
bool ModuleData::convertPath()
{
	std::string my_path =  convert_to_win32_path(this->szModName);
	if (my_path.length() == 0) {
		return false;
	}
	// store the new path in the buffer:
	memset(this->szModName, 0, MAX_PATH);

	// store the new path in the buffer:
	size_t max_len = my_path.length();
	if (max_len > MAX_PATH) max_len = MAX_PATH;

	memcpy(this->szModName, my_path.c_str(), max_len);
	return true;
}

bool ModuleData::loadOriginal()
{
	if (!GetModuleFileNameExA(processHandle, this->moduleHandle, szModName, MAX_PATH)) {
		is_module_named = false;
		const char unnamed[] = "unnamed";
		memcpy(szModName, unnamed, sizeof(unnamed));
	}
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (original_module != nullptr) {
		return true;
	}
	// try to convert path:
	if (!convertPath()) {
		return false;
	}
	std::cout << "[OK] Converted the path: " << szModName << std::endl;
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}

bool ModuleData::reloadWow64()
{
	bool is_converted = convert_to_wow64_path(szModName);
	if (!is_converted) return false;

	//reload it and check again...
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}

//---

t_scan_status get_scan_status(ModuleScanReport *report)
{
	if (report == nullptr) {
		return SCAN_ERROR;
	}
	return report->status;
}


t_scan_status ProcessScanner::scanForHollows(ModuleData& modData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HollowingScanner hollows(processHandle);
	HeadersScanReport *scan_report = hollows.scanRemote(modData);
	if (scan_report == nullptr) {
		process_report.summary.errors++;
		return SCAN_ERROR;
	}
	t_scan_status is_hollowed = get_scan_status(scan_report);

	if (is_hollowed == SCAN_MODIFIED && isWow64) {
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = hollows.scanRemote(modData);
		}
		is_hollowed = get_scan_status(scan_report);
	}
	process_report.appendReport(scan_report);
	if (is_hollowed == SCAN_ERROR) {
		process_report.summary.errors++;
	}
	if (is_hollowed == SCAN_MODIFIED) {
		process_report.summary.replaced++;
	}
	if (!args.quiet && is_hollowed != SCAN_MODIFIED && scan_report->epModified) {
		std::cout << "[WARNING] Entry Point overwritten!" << std::endl;
	}
	return is_hollowed;
}

t_scan_status ProcessScanner::scanForHooks(ModuleData& modData, ProcessScanReport& process_report)
{
	HookScanner hooks(processHandle);
	CodeScanReport *scan_report = hooks.scanRemote(modData);
	t_scan_status is_hooked = get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	
	if (is_hooked == SCAN_MODIFIED) {
		process_report.summary.hooked++;
	}
	if (is_hooked == SCAN_ERROR) {
		process_report.summary.errors++;
	}
	return is_hooked;
}

ProcessScanReport* ProcessScanner::scanRemote()
{
	ProcessScanReport *pReport = new ProcessScanReport(this->args.pid);
	scanModules(pReport);
	scanWorkingSet(pReport);
	return pReport;
}

ProcessScanReport* ProcessScanner::scanWorkingSet(ProcessScanReport *pReport)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	size_t page_size = si.dwPageSize;

	PSAPI_WORKING_SET_INFORMATION wsi_1 = { 0 };
	QueryWorkingSet(this->processHandle, (LPVOID)&wsi_1, sizeof(PSAPI_WORKING_SET_INFORMATION));
#ifdef _DEBUG
	std::cout << "Number of Entries: " << wsi_1.NumberOfEntries << std::endl;
#endif
#if !defined(_WIN64)
    wsi_1.NumberOfEntries--;
#endif
	const size_t entry_size = sizeof(PSAPI_WORKING_SET_BLOCK);
	DWORD wsi_size = (int)(wsi_1.NumberOfEntries) * entry_size + entry_size + 1024; // The 1024 is to allow for working set growth
	PSAPI_WORKING_SET_INFORMATION* wsi = (PSAPI_WORKING_SET_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wsi_size);

	if (!QueryWorkingSet(this->processHandle, (LPVOID)wsi, wsi_size)) {
		pReport->summary.errors++;
		std::cout << "[-] Could not scan the working set in the process" << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, wsi);
		return pReport;
	}

	BYTE hdrs[peconv::MAX_HEADER_SIZE] = { 0 };

	for (size_t counter = 0; counter < wsi->NumberOfEntries; counter++) {
		ULONGLONG page = (ULONGLONG)wsi->WorkingSetInfo[counter].VirtualPage;
		DWORD protection = (DWORD)wsi->WorkingSetInfo[counter].Protection;

		if ((protection & 2) == 0 || (protection & 4) == 0) {
			//not WX
			continue;
		}
		ULONGLONG page_addr = page * page_size;

		if (peconv::read_remote_pe_header(this->processHandle,(BYTE*) page_addr, hdrs, peconv::MAX_HEADER_SIZE)) {
			pReport->appendReport(new RwxModuleReport(processHandle, (HMODULE)page_addr));
			pReport->summary.suspicious++;
		}
	}
	HeapFree(GetProcessHeap(), 0, wsi);
	return pReport;
}

size_t ProcessScanner::enumModules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters)
{
	HANDLE hProcess = this->processHandle;
	if (hProcess == nullptr) return 0;

	DWORD cbNeeded;
	if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {
		DWORD last_err = GetLastError();
		throw std::exception("[-] Could not enumerate modules in the process", last_err);
		return 0;
	}
	const size_t modules_count = cbNeeded / sizeof(HMODULE);
	return modules_count;
}

ProcessScanReport* ProcessScanner::scanModules(ProcessScanReport *pReport)
{
	if (pReport == nullptr) {
		pReport = new ProcessScanReport(this->args.pid);
	}
	t_report &report = pReport->summary;
	HMODULE hMods[1024];
	const size_t modules_count = enumModules(hMods, sizeof(hMods), args.modules_filter);
	if (modules_count == 0) {
		report.errors++;
		return pReport;
	}
	if (args.imp_rec) {
		pReport->exportsMap = new peconv::ExportsMapper();
	}

	report.scanned = 0;
	for (size_t i = 0; i < modules_count; i++, report.scanned++) {
		if (processHandle == NULL) break;

		ModuleData modData(processHandle, hMods[i]);

		if (!modData.loadOriginal()) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			//make a report that finding original module was not possible
			pReport->appendReport(new UnreachableModuleReport(processHandle, hMods[i]));
			report.suspicious++;
			continue;
		}
		if (!args.quiet) {
			std::cout << "[*] Scanning: " << modData.szModName << std::endl;
		}
		t_scan_status is_hollowed = scanForHollows(modData, *pReport);
		if (is_hollowed == SCAN_ERROR) {
			continue;
		}
		if (pReport->exportsMap != nullptr) {
			pReport->exportsMap->add_to_lookup(modData.szModName, (HMODULE) modData.original_module, (ULONGLONG) modData.moduleHandle);
		}
		if (args.no_hooks) {
			continue; // don't scan for hooks
		}
		//if not hollowed, check for hooks:
		if (is_hollowed == SCAN_NOT_MODIFIED) {
			scanForHooks(modData, *pReport);
		}
		
	}
	return pReport;
}

