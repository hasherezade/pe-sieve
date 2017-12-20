// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <fstream>

#include "hook_scanner.h"
#include "hollowing_scanner.h"

#include "util.h"

#include "peconv.h"
using namespace peconv;

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
	return hProcess;
}

bool dump_modified_module(HANDLE processHandle, ULONGLONG modBaseAddr, std::string dumpPath)
{
	if (!dump_remote_pe(dumpPath.c_str(), processHandle, (PBYTE)modBaseAddr, true)) {
		std::cerr << "Failed dumping module!" << std::endl;
		return false;
	}
	return true;
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

size_t check_modules_in_process(DWORD process_id)
{
	HANDLE processHandle = open_process(process_id);
	if (processHandle == nullptr) {
		std::cerr << "[-] Could not open process. Error: " << GetLastError() << std::endl;
		return 0;
	}
#ifdef _WIN64
	BOOL isWow6 = FALSE;
	if (IsWow64Process(processHandle, &isWow6)) {
		if (isWow6) {
			std::cerr << "[WARNING] You are trying to scan a 32bit process by a 64bit scanner!\n";
			std::cerr << "Use a 32bit scanner instead!" << std::endl;
		}
	}
#endif
	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (!EnumProcessModulesEx(processHandle, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT | LIST_MODULES_64BIT)) {
		std::cerr << "[-] Could not enumerate modules in the process. Error: " << GetLastError() << std::endl;
		return 0;
	}
	const size_t modules_count = cbNeeded / sizeof(HMODULE);

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
		std::string dumpFileName = make_module_path(modBaseAddr, szModName, directory);

		//load the same module, but from the disk: 
		size_t module_size = 0;
		BYTE* original_module = nullptr;
		if (is_module_named) {
			original_module = load_pe_module(szModName, module_size, false, false);
		}
		if (original_module == nullptr) {
			std::cout << "[!] Suspicious: could not read the module file! Dumping the virtual image..." << std::endl;
			dump_modified_module(processHandle, modBaseAddr, dumpFileName);
			suspicious++;
			continue;
		}

		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		t_scan_status is_hollowed = SCAN_NOT_MODIFIED;

		HollowingScanner hollows(processHandle);
		is_hollowed = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
		if (is_hollowed == SCAN_MODIFIED) {
			std::cout << "[*] The module is replaced by a different PE!" << std::endl;
			hollowed_modules++;
			dump_modified_module(processHandle, modBaseAddr, dumpFileName);
		}
		else {
			PatchList patchesList;
			HookScanner hooks(processHandle, patchesList);
			t_scan_status is_hooked = hooks.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			if (is_hooked == SCAN_MODIFIED) {
				std::cout << "[*] The module is hooked!" << std::endl;
				hooked_modules++;
				dump_modified_module(processHandle, modBaseAddr, dumpFileName);
				report_patches(patchesList, dumpFileName + ".tag");
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			std::cerr << "[-] ERROR while checking the module: " << szModName << std::endl;
			error_modules++;
		}
		VirtualFree(original_module, module_size, MEM_FREE);

	}

	//summary:
	size_t total_modified = hooked_modules + hollowed_modules + suspicious;
	std::cout << "---" << std::endl;
	std::cout << "Summary: \n" << std::endl;
	std::cout << "Total scanned: " << i << std::endl;
	std::cout << "Hooked:  " << hooked_modules << std::endl;
	std::cout << "Replaced:  " << hollowed_modules << std::endl;
	std::cout << "Other suspicious: " << suspicious << std::endl;
	std::cout << "Total modified: " << total_modified << std::endl;
	if (error_modules) {
		std::cerr << "[!] Reading errors: " << error_modules << std::endl;
	}
	if (total_modified > 0) {
		std::cout << "Dumps saved to the directory: " << directory << std::endl;
	}
	std::cout << "---" << std::endl;
	return total_modified;
}

void banner(char *version)
{
	char logo[] =
"\
   __             __      ____         __       \n\
  / /  ___  ___  / /__   / _(_)__  ___/ /__ ____\n\
 / _ \\/ _ \\/ _ \\/  '_/  / _/ / _ \\/ _  / -_) __/\n\
/_//_/\\___/\\___/_/\\_\\__/_//_/_//_/\\_,_/\\__/_/   \n\
                   /___/ ";

	std::cout << logo;
	std::cout << " version: " << version << "\n\n";
	std::cout << "~ from hasherezade with love ~\n";
	std::cout << "Detects inline hooks and other in-memory PE modifications\n---\n";
	std::cout << "Args: <PID>\n";
	std::cout << "PID: (decimal) PID of the target application\n";
	std::cout << "---" << std::endl;
}

int main(int argc, char *argv[])
{
	char *version = "0.0.7.9";
	if (argc < 2) {
		banner(version);
		system("pause");
		return 0;
	}

	DWORD pid = atoi(argv[1]);
	printf("PID: %d\n", pid);
	/*
	char filename[MAX_PATH] = { 0 };
	sprintf(filename,"PID_%d_modules.txt", pid);
	bool isLogging = make_log_file(filename);
	*/
	check_modules_in_process(pid);
	/*if (isLogging) {
		close_log_file();
		std::cout << "Report saved to the file: " << filename << std::endl;
	}*/
	system("pause");
	return 0;
}

