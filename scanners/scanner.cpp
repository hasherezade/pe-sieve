#include "scanner.h"

#include <sstream>
#include <fstream>

#include "../utils/util.h"
#include "../utils/path_converter.h"

#include "hollowing_scanner.h"
#include "hook_scanner.h"
#include "mempage_scanner.h"

#include <string>
#include <locale>
#include <codecvt>

t_scan_status ProcessScanner::scanForHollows(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HollowingScanner hollows(processHandle);
	HeadersScanReport *scan_report = hollows.scanRemote(modData, remoteModData);
	if (scan_report == nullptr) {
		process_report.summary.errors++;
		return SCAN_ERROR;
	}
	t_scan_status is_hollowed = ModuleScanReport::get_scan_status(scan_report);

	if (scan_report->archMismatch && isWow64) {
#ifdef _DEBUG
		std::cout << "Arch mismatch, reloading..." << std::endl;
#endif
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = hollows.scanRemote(modData, remoteModData);
		}
		is_hollowed = ModuleScanReport::get_scan_status(scan_report);
	}
	process_report.appendReport(scan_report);
	if (is_hollowed == SCAN_SUSPICIOUS) {
		process_report.summary.replaced++;
	}
	if (!args.quiet && is_hollowed != SCAN_SUSPICIOUS && scan_report->epModified) {
		std::cout << "[WARNING] Entry Point overwritten!" << std::endl;
	}
	return is_hollowed;
}

t_scan_status ProcessScanner::scanForHooks(ModuleData& modData, RemoteModuleData &remoteModData, ProcessScanReport& process_report)
{
	HookScanner hooks(processHandle);

	CodeScanReport *scan_report = hooks.scanRemote(modData, remoteModData);
	t_scan_status is_hooked = ModuleScanReport::get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	
	if (is_hooked != SCAN_SUSPICIOUS) {
		return is_hooked;
	}
	process_report.summary.hooked++;
	return is_hooked;
}

ProcessScanReport* ProcessScanner::scanRemote()
{
	ProcessScanReport *pReport = new ProcessScanReport(this->args.pid);
	scanModules(pReport);
	//dont't scan your own working set
	if (GetProcessId(this->processHandle) != GetCurrentProcessId()) {
		scanWorkingSet(pReport);
	}
	return pReport;
}

ProcessScanReport* ProcessScanner::scanWorkingSet(ProcessScanReport *pReport)
{
	if (pReport == nullptr) {
		pReport = new ProcessScanReport(this->args.pid);
	}
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	size_t page_size = si.dwPageSize;

	PSAPI_WORKING_SET_INFORMATION wsi_1 = { 0 };
	BOOL result = QueryWorkingSet(this->processHandle, (LPVOID)&wsi_1, sizeof(PSAPI_WORKING_SET_INFORMATION));
	if (result == FALSE && GetLastError() != ERROR_BAD_LENGTH) {
		std::cout << "[-] Could not scan the working set in the process. Error: " << GetLastError() << std::endl;
		return nullptr;
	}
#ifdef _DEBUG
	std::cout << "Number of Entries: " << wsi_1.NumberOfEntries << std::endl;
#endif
#if !defined(_WIN64)
	wsi_1.NumberOfEntries--;
#endif
	const size_t entry_size = sizeof(PSAPI_WORKING_SET_BLOCK);
	//TODO: check it!!
	ULONGLONG wsi_size = wsi_1.NumberOfEntries * entry_size * 2; // Double it to allow for working set growth
	PSAPI_WORKING_SET_INFORMATION* wsi = (PSAPI_WORKING_SET_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wsi_size);

	if (!QueryWorkingSet(this->processHandle, (LPVOID)wsi, (DWORD)wsi_size)) {
		pReport->summary.errors++;
		std::cout << "[-] Could not scan the working set in the process. Error: " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, wsi);
		return pReport;
	}

	MemPageScanner workingSetScanner(this->processHandle);

	for (size_t counter = 0; counter < wsi->NumberOfEntries; counter++) {
		ULONGLONG page = (ULONGLONG)wsi->WorkingSetInfo[counter].VirtualPage;
		DWORD protection = (DWORD)wsi->WorkingSetInfo[counter].Protection;

		//calculate the real address of the page:
		ULONGLONG page_addr = page * page_size;

		MemPageData memPage(this->processHandle, page_addr, page_size, protection);
		//if it was already scanned, it means the module was on the list of loaded modules
		memPage.is_listed_module = pReport->hasModule((HMODULE)page_addr);
		
		MemPageScanReport *my_report = workingSetScanner.scanRemote(memPage);
		if (my_report == nullptr) continue;

		pReport->appendReport(my_report);
		if (ModuleScanReport::get_scan_status(my_report) == SCAN_SUSPICIOUS) {
			if (my_report->is_manually_loaded) {
				pReport->summary.implanted++;
			}
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

		//load module from file:
		ModuleData modData(processHandle, hMods[i]);

		if (!modData.loadOriginal()) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			//make a report that finding original module was not possible
			pReport->appendReport(new UnreachableModuleReport(processHandle, hMods[i]));
			pReport->summary.detached++;
			continue;
		}
		if (!args.quiet) {
			std::cout << "[*] Scanning: " << modData.szModName << std::endl;
		}
		if (modData.isDotNet()) {
			std::cout << "[*] Skipping a .NET module: " << modData.szModName << std::endl;
			//pReport->summary.skipped++;
			continue;
		}
		//load data about the remote module
		RemoteModuleData remoteModData(processHandle, hMods[i]);
		if (remoteModData.isInitialized() == false) {
			pReport->summary.errors++;
			continue;
		}
		t_scan_status is_hollowed = scanForHollows(modData, remoteModData, *pReport);
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
		if (is_hollowed == SCAN_NOT_SUSPICIOUS) {
			scanForHooks(modData, remoteModData, *pReport);
		}
	}
	return pReport;
}

