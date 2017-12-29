// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <fstream>

#include "hook_scanner.h"
#include "hollowing_scanner.h"
#include "process_privilege.h"

#include "util.h"

#include "peconv.h"

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
		std::cerr << "[-] Could not open the process. Error: " << last_err << std::endl;
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


size_t dump_all_modified(std::map<ULONGLONG, std::string> &modified_modules, peconv::ExportsMapper& exportsMap, HANDLE &processHandle)
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
			&exportsMap
			))
		{
			dumped++;
		} else {
			std::cerr << "Failed dumping module!" << std::endl;
		}
	}
	return dumped;
}

size_t check_modules_in_process(const DWORD process_id, const DWORD filters)
{
	HANDLE processHandle = open_process(process_id);
	if (processHandle == nullptr) {
		return 0;
	}
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(processHandle, hMods, sizeof(hMods), filters);
	if (modules_count == 0) {
		return 0;
	}

	size_t hooked_modules = 0;
	size_t hollowed_modules = 0;
	size_t error_modules = 0;
	size_t suspicious = 0;

	std::cerr << "---" << std::endl;
	//check all modules in the process, including the main module:

	std::string directory = make_dir_name(process_id);
	if (!make_dump_dir(directory)) {
		directory = "";
	}
	std::map<ULONGLONG, std::string> modified_modules;

	peconv::ExportsMapper exportsMap;
	char szModName[MAX_PATH];
	size_t i = 0;
	for (; i < modules_count; i++) {
		if (processHandle == NULL) break;

		bool is_module_named = true;

		if (!GetModuleFileNameExA(processHandle, hMods[i], szModName, MAX_PATH)) {
			std::cerr << "Cannot fetch module name" << std::endl;
			is_module_named = false;
			const char unnamed[] = "unnamed";
			memcpy(szModName, unnamed, sizeof(unnamed));
		}
		std::cout << "[*] Scanning: " << szModName << std::endl;

		ULONGLONG modBaseAddr = (ULONGLONG)hMods[i];
		std::string dumpFileName = make_dump_path(modBaseAddr, szModName, directory);

		//load the same module, but from the disk: 
		size_t module_size = 0;
		BYTE* original_module = nullptr;
		if (is_module_named) {
			original_module = peconv::load_pe_module(szModName, module_size, false, false);
		}
		if (original_module == nullptr) {
			std::cout << "[!] Suspicious: could not read the module file! Dumping the virtual image..." << std::endl;
			modified_modules[modBaseAddr] = dumpFileName;
			suspicious++;
			continue;
		}

		exportsMap.add_to_lookup(szModName, (HMODULE) original_module, modBaseAddr);

		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		t_scan_status is_hollowed = SCAN_NOT_MODIFIED;

		HollowingScanner hollows(processHandle);
		is_hollowed = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
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
			}
			is_hollowed = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			if (is_hollowed) {
				std::cout << "[*] The module is replaced by a different PE!" << std::endl;
				hollowed_modules++;
				modified_modules[modBaseAddr] = dumpFileName;
			}
		}
		//if not hollowed, check for hooks:
		if (is_hollowed == SCAN_NOT_MODIFIED) {
			PatchList patchesList;
			HookScanner hooks(processHandle, patchesList);
			t_scan_status is_hooked = hooks.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			if (is_hooked == SCAN_MODIFIED) {
				std::cout << "[*] The module is hooked!" << std::endl;
				hooked_modules++;
				modified_modules[modBaseAddr] = dumpFileName;
				report_patches(patchesList, dumpFileName + ".tag");
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			std::cerr << "[-] ERROR while checking the module: " << szModName << std::endl;
			error_modules++;
		}
		peconv::free_pe_buffer(original_module, module_size);
	}

	dump_all_modified(modified_modules, exportsMap, processHandle);

	//summary:
	size_t total_modified = hooked_modules + hollowed_modules + suspicious;
	std::cout << "---" << std::endl;
	std::cout << "SUMMARY: \n" << std::endl;
	std::cout << "Total scanned:    " << i << std::endl;
	std::cout << "-\n";
	std::cout << "Hooked:           " << hooked_modules << std::endl;
	std::cout << "Replaced:         " << hollowed_modules << std::endl;
	std::cout << "Other suspicious: " << suspicious << std::endl;
	std::cout << "-\n";
	std::cout << "Total modified:   " << total_modified << std::endl;
	if (error_modules) {
		std::cerr << "[!] Reading errors: " << error_modules << std::endl;
	}
	if (total_modified > 0) {
		std::cout << "\nDumps saved to the directory: " << directory << std::endl;
	}
	std::cout << "---" << std::endl;
	return total_modified;
}

void banner(char *version)
{
	char logo[] = "\
.______    _______           _______. __   ___________    ____  _______ \n\
|   _  \\  |   ____|         /       ||  | |   ____\\   \\  /   / |   ____|\n\
|  |_)  | |  |__    ______ |   (----`|  | |  |__   \\   \\/   /  |  |__   \n\
|   ___/  |   __|  |______| \\   \\    |  | |   __|   \\      /   |   __|  \n\
|  |      |  |____      .----)   |   |  | |  |____   \\    /    |  |____ \n\
| _|      |_______|     |_______/    |__| |_______|   \\__/     |_______|\n\n";

	std::cout << logo;
	std::cout << "version: " << version;
#ifdef _WIN64
	std::cout << " (x64)" << "\n\n";
#else
	std::cout << " (x86)" << "\n\n";
#endif
	std::cout << "~ from hasherezade with love ~\n";
	std::cout << "Detects inline hooks and other in-memory PE modifications\n---\n";
	std::cout << "Args: <PID> ";
#ifdef _WIN64
	std::cout <<"[*module_filter]";
#endif
	std::cout << "\n";
	std::cout << "PID: (decimal) PID of the target application\n";
#ifdef _WIN64
	std::cout << "module_filter:\n\t0 - no filter\n\t1 - 32bit\n\t2 - 64bit\n\t3 - all (default)\n";
	std::cout << "* - optional\n";
#endif
	std::cout << "---" << std::endl;
}

int main(int argc, char *argv[])
{
	char *version = "0.0.8.4";
	if (argc < 2) {
		banner(version);
		system("pause");
		return 0;
	}
	DWORD pid = atoi(argv[1]);
	std::cout << "PID: " << pid << std::endl;

	DWORD filters = LIST_MODULES_ALL;
	if (argc >= 3) {
		filters = atoi(argv[2]);
		if (filters > LIST_MODULES_ALL) {
			filters = LIST_MODULES_ALL;
		}
	}
	std::cout << "Module filter: " << filters << std::endl;
	check_modules_in_process(pid, filters);

	system("pause");
	return 0;
}

