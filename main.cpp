// Enumerates all the hooked modules in the process with a given PID
// saves the list in the log with the given format:
// <module_start>,<module_end>,<module_name>
// CC-BY: hasherezade

#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <TlHelp32.h>

#include "tinylogger.h"
#include "hook_scanner.h"
#include "hollowing_scanner.h"

#include <sstream>

#include "peconv.h"
#include <psapi.h>
#include <tchar.h>

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

size_t check_modules_in_process(DWORD process_id)
{
	HANDLE processHandle = open_process(process_id);
	if (processHandle == nullptr) {
		std::cerr << "[-] Could not open process. Error: " << GetLastError() << std::endl;
		return 0;
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (!EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded)) {
		std::cerr << "[-] Could not enumerate modules in the process. Error: " << GetLastError() << std::endl;
		return 0;
	}
	size_t modules_counter = cbNeeded / sizeof(HMODULE);

	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (hProcessSnapShot == INVALID_HANDLE_VALUE) {
		std::cerr << "[-] Could not create modules snapshot. Error: " << GetLastError() << std::endl;
		std::cout << "---" << std::endl;
		return 0;
	}

	size_t hooked_modules = 0;
	size_t hollowed_modules = 0;
	size_t error_modules = 0;
	size_t suspicious = 0;
	size_t modules = 1;

	MODULEENTRY32 module_entry = { 0 };
	module_entry.dwSize = sizeof(module_entry);

	std::cerr << "---" << std::endl;

	//check all modules in the process, including the main module:
	if (!Module32First(hProcessSnapShot, &module_entry)) {
		CloseHandle(processHandle);

		std::cerr << "[-] Could not enumerate modules in process. Error: " << GetLastError() << std::endl;
		return 0;
	}

	std::string directory = make_dir_name(process_id);
	if (!make_dump_dir(directory)) {
		directory = "";
	}

	HollowingScanner hollows(processHandle, directory);
	HookScanner hooks(processHandle, directory);

	do {		
		modules++;
		if (processHandle == NULL) break;

		std::cout << "[*] Scanning: " << module_entry.szExePath << std::endl;

		//load the same module, but from the disk:
		size_t module_size = 0;
		BYTE* original_module = load_pe_module(module_entry.szExePath, module_size, false, false);
		if (original_module == NULL) {
			std::cout << "[!] Suspicious: could not read the module file! Dumping the virtual image..." << std::endl;
			std::string mod_name = make_module_path((ULONGLONG)module_entry.modBaseAddr, directory);
			std::cout << mod_name << std::endl;
			if (!dump_remote_pe(mod_name.c_str(), processHandle, module_entry.modBaseAddr, true)) {
				std::cerr << "Failed dumping module!" << std::endl;
			}
			suspicious++;
			continue;
		}

		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		t_scan_status is_hollowed = hollows.scanRemote(module_entry.modBaseAddr, original_module, module_size);
		if (is_hollowed == SCAN_MODIFIED) {
			std::cout << "[*] The module is replaced by a different PE!" << std::endl;
			hollowed_modules++;
			log_module_info(module_entry);
		} else {
			t_scan_status is_hooked = hooks.scanRemote(module_entry.modBaseAddr, original_module, module_size);
			if (is_hooked == SCAN_MODIFIED) {
				std::cout << "[*] The module is hooked!" << std::endl;
				hooked_modules++;
				log_module_info(module_entry);
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			std::cerr << "[-] ERROR while checking the module: " << module_entry.szExePath << std::endl;
			error_modules++;
		}
		VirtualFree(original_module, module_size, MEM_FREE);

	} while (Module32Next(hProcessSnapShot, &module_entry));

	//close the handles
	CloseHandle(processHandle);
	CloseHandle(hProcessSnapShot);

	//summary:
	size_t total_modified = hooked_modules + hollowed_modules + suspicious;
	std::cout << "---" << std::endl;
	std::cout << "Summary: \n" << std::endl;
	std::cout << "Total scanned: " << modules << std::endl;
	std::cout << "Hooked:  " << hooked_modules << std::endl;
	std::cout << "Hollowed:  " << hollowed_modules << std::endl;
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

int main(int argc, char *argv[])
{
	char *version = "0.0.7.8";
	if (argc < 2) {
		printf("[hook_finder v%s]\n", version);
		printf("A small tool allowing to detect and examine inline hooks\n---\n");
		printf("Args: <PID>\n");
		printf("PID: (decimal) PID of the target application\n");
		printf("---\n");
		system("pause");
		return 0;
	}

	DWORD pid = atoi(argv[1]);
	printf("PID: %d\n", pid);

	char filename[MAX_PATH] = { 0 };
	sprintf(filename,"PID_%d_modules.txt", pid);
	bool isLogging = make_log_file(filename);

	size_t num = check_modules_in_process(pid);
	if (isLogging) {
		close_log_file();
		std::cout << "Report saved to the file: " << filename << std::endl;
	}
	system("pause");
	return 0;
}

