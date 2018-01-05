// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include "pe_sieve.h"
#include "peconv.h"

#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <fstream>

#include "hook_scanner.h"
#include "hollowing_scanner.h"
#include "process_privilege.h"

#include "util.h"

bool make_dump_dir(const std::string directory)
{
	if (CreateDirectoryA(directory.c_str(), NULL) 
		||  GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return true;
	}
	return false;
}

std::string make_dir_name(const DWORD process_id)
{
	std::stringstream stream;
	stream << "process_";
	stream << process_id;
	return stream.str();
}

HANDLE open_process(DWORD processID)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,
		FALSE, processID
	);
	if (hProcess != nullptr) {
		return hProcess;
	}
	DWORD last_err = GetLastError();
	if (last_err == ERROR_ACCESS_DENIED) {
		if (set_debug_privilege(processID)) {
			//try again to open
			hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,
				FALSE, processID
			);
			if (hProcess != nullptr) {
				return hProcess;
			}
		}
		std::cerr << "[-][" << processID << "] Could not open the process Error: " << last_err << std::endl;
		std::cerr << "-> Access denied. Try to run the scanner as Administrator." << std::endl;
		return nullptr;
	}
	if (last_err == ERROR_INVALID_PARAMETER) {
		std::cerr << "-> Is this process still running?" << std::endl;
	}
	return hProcess;
}

size_t enum_modules(IN HANDLE hProcess, OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters)
{
	DWORD cbNeeded;
	if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {

		BOOL isCurrWow64 = FALSE;
		IsWow64Process(GetCurrentProcess(), &isCurrWow64);
		BOOL isRemoteWow64 = FALSE;
		IsWow64Process(hProcess, &isRemoteWow64);

		DWORD last_err = GetLastError();
		std::cerr << "[-] Could not enumerate modules in the process. Error: " << last_err << std::endl;
		if (last_err == ERROR_PARTIAL_COPY && isCurrWow64 && !isRemoteWow64) {
			std::cerr << "-> Try to use the 64bit version of the scanner." << std::endl;
		}
		return 0;
	}
	const size_t modules_count = cbNeeded / sizeof(HMODULE);
	return modules_count;
}

size_t report_patches(PatchList &patchesList, std::string reportPath)
{
	std::ofstream patch_report;
	patch_report.open(reportPath);
	if (patch_report.is_open() == false) {
		std::cout << "[-] Could not open the file: "<<  reportPath << std::endl;
	}
	
	size_t patches = patchesList.reportPatches(patch_report, ';');

	if (patch_report.is_open()) {
		patch_report.close();
	}
	return patches;
}

size_t dump_all_modified(HANDLE &processHandle, std::map<ULONGLONG, std::string> &modified_modules, peconv::ExportsMapper* exportsMap)
{
	size_t dumped = 0;
	std::map<ULONGLONG, std::string>::iterator itr = modified_modules.begin();

	for (; itr != modified_modules.end(); itr++ ) {
		ULONGLONG modBaseAddr = itr->first;
		std::string dumpFileName = itr->second;

		if (peconv::dump_remote_pe(
			dumpFileName.c_str(), //output file
			processHandle, 
			(PBYTE) modBaseAddr, 
			true, //unmap
			exportsMap
			))
		{
			dumped++;
		} else {
			std::cerr << "Failed dumping module!" << std::endl;
		}
	}
	return dumped;
}

t_scan_status get_scan_status(ModuleScanReport *report)
{
	if (report == nullptr) {
		return SCAN_ERROR;
	}
	return report->status;
}

ProcessScanReport* check_modules_in_process(const t_params args)
{
	ProcessScanReport *process_report = new ProcessScanReport(args.pid);
	t_report &report = process_report->summary;

	HANDLE processHandle = open_process(args.pid);
	if (processHandle == nullptr) {
		report.errors++;
		return process_report;
	}
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(processHandle, hMods, sizeof(hMods), args.filter);
	if (modules_count == 0) {
		report.errors++;
		return process_report;
	}

	//check all modules in the process, including the main module:
	
	std::string directory = make_dir_name(args.pid);
	if (!args.quiet) {
		if (!make_dump_dir(directory)) {
			directory = "";
		}
	}
	std::map<ULONGLONG, std::string> modified_modules;

	peconv::ExportsMapper* exportsMap = nullptr;
	if (args.imp_rec) {
		exportsMap = new peconv::ExportsMapper();
	}
	char szModName[MAX_PATH];

	report.scanned = 0;
	for (size_t i = 0; i < modules_count; i++, report.scanned++) {
		if (processHandle == NULL) break;
		
		bool is_module_named = true;

		if (!GetModuleFileNameExA(processHandle, hMods[report.scanned], szModName, MAX_PATH)) {
			std::cerr << "[!][" << args.pid <<  "] Cannot fetch module name" << std::endl;
			is_module_named = false;
			const char unnamed[] = "unnamed";
			memcpy(szModName, unnamed, sizeof(unnamed));
		}
		if (!args.quiet) {
			std::cout << "[*][" << args.pid <<  "] Scanning: " << szModName << std::endl;
		}
		ULONGLONG modBaseAddr = (ULONGLONG)hMods[i];
		std::string dumpFileName = make_dump_path(modBaseAddr, szModName, directory);

		//load the same module, but from the disk: 
		size_t module_size = 0;
		BYTE* original_module = nullptr;
		if (is_module_named) {
			original_module = peconv::load_pe_module(szModName, module_size, false, false);
		}
		if (original_module == nullptr) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			modified_modules[modBaseAddr] = dumpFileName;
			//TODO: make a report that finding original module was not possible
			report.suspicious++;
			continue;
		}
		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		t_scan_status is_hollowed = SCAN_NOT_MODIFIED;

		HollowingScanner hollows(processHandle);
		HeadersScanReport *scan_report = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
		is_hollowed = get_scan_status(scan_report);

		if (is_hollowed == SCAN_MODIFIED) {
			if (isWow64) {
				//it can be caused by Wow64 path overwrite, check it...
				bool is_converted = convert_to_wow64_path(szModName);
#ifdef _DEBUG
				std::cout << "Reloading Wow64..." << std::endl;
#endif
				//reload it and check again...
				peconv::free_pe_buffer(original_module, module_size);
				original_module = peconv::load_pe_module(szModName, module_size, false, false);

				delete scan_report; // delete previous report
				scan_report = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			}

			is_hollowed = get_scan_status(scan_report);
			if (is_hollowed == SCAN_MODIFIED) {
				if (!args.quiet) {
					std::cout << "[*][" << args.pid <<  "] The module is replaced by a different PE!" << std::endl;
				}
				report.replaced++;
				modified_modules[modBaseAddr] = dumpFileName;
			}
		}

		process_report->appendReport(scan_report);

		if (exportsMap != nullptr) {
			exportsMap->add_to_lookup(szModName, (HMODULE) original_module, modBaseAddr);
		}
		//if not hollowed, check for hooks:
		if (is_hollowed == SCAN_NOT_MODIFIED) {
			PatchList patchesList;
			HookScanner hooks(processHandle);
			CodeScanReport *scan_report = hooks.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			is_hooked = get_scan_status(scan_report);
			process_report->appendReport(scan_report);

			if (is_hooked == SCAN_MODIFIED) {
				if (!args.quiet) {
					std::cout << "[*][" << args.pid <<  "] The module is hooked!" << std::endl;
				}
				report.hooked++;
				modified_modules[modBaseAddr] = dumpFileName;
				if (!args.quiet) {
					report_patches(scan_report->patchesList, dumpFileName + ".tag");
				}
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			std::cerr << "[-][" << args.pid <<  "] ERROR while checking the module: " << szModName << std::endl;
			report.errors++;
		}
		peconv::free_pe_buffer(original_module, module_size);
	}
	if (!args.no_dump && !args.quiet) {
		dump_all_modified(processHandle, modified_modules, exportsMap);
	}
	if (exportsMap != nullptr) {
		delete exportsMap;
		exportsMap = nullptr;
	}
	return process_report;
}

std::string info()
{
	std::stringstream stream;
	stream << "version: " << VERSION;
#ifdef _WIN64
	stream << " (x64)" << "\n\n";
#else
	stream << " (x86)" << "\n\n";
#endif
	stream << "~ from hasherezade with love ~\n";
	stream << "Detects inline hooks and other in-memory PE modifications\n";
	stream << "URL: " << URL << "\n";
	stream << "---\n";
	return stream.str();
}

