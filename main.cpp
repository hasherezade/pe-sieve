// Enumerates all the hooked modules in the process with a given PID
// saves the list in the log with the given format:
// <module_start>,<module_end>,<module_name>
// CC-BY: hasherezade
// WARNING: this is alpha version!

#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <TlHelp32.h>

#include "tinylogger.h"
#include "hook_scanner.h"
#include "hollowing_scanner.h"

#include "peconv.h"
using namespace peconv;

bool make_dump_dir(const DWORD process_id, OUT char *directory)
{
	sprintf(directory, "process_%d", process_id);
	if (CreateDirectoryA(directory, NULL) ||  GetLastError() == ERROR_ALREADY_EXISTS) {
		printf("[+] Directory created\n");
		return true;
	}
	memset(directory, 0, MAX_PATH);
	return false;
}

size_t check_modules_in_process(DWORD process_id)
{
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (hProcessSnapShot == INVALID_HANDLE_VALUE) {
		printf("[-] Could not create modules snapshot. Error: %d\n", GetLastError());
		return 0;
	}
	HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
	if (processHandle == NULL)  {
		printf("[-] Could not open the process for reading. Error: %d\n", GetLastError());
		return 0;
	}

	//make a directory to store the dumps:
	char directory[MAX_PATH] = { 0 };
	bool is_dir = make_dump_dir(process_id, directory);

	size_t hooked_modules = 0;
	size_t hollowed_modules = 0;
	size_t error_modules = 0;
	size_t modules = 1;

	MODULEENTRY32 module_entry = { 0 };
	module_entry.dwSize = sizeof(module_entry);

	printf("---\n");

	//check all modules in the process, including the main module:
	if (!Module32First(hProcessSnapShot, &module_entry)) {
		CloseHandle(processHandle);
		printf("[-] Could not enumerate modules in process. Error: %d\n", GetLastError());
		return 0;
	}
	do {		
		modules++;
		if (processHandle == NULL) break;

		//load the same module, but from the disk:
		printf("[*] Scanning: %s\n", module_entry.szExePath);

		size_t module_size = 0;
		BYTE* original_module = load_pe_module(module_entry.szExePath, module_size, false, false);
		if (original_module == NULL) {
			printf("[-] Could not read original module!\n");
			error_modules++;
			continue;
		}
		t_scan_status is_hollowed = SCAN_NOT_MODIFIED;
		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		is_hollowed = is_module_replaced(processHandle, module_entry, original_module, module_size, directory);
		if (is_hollowed == SCAN_MODIFIED) {
			printf("[*] The module is replaced by a different PE!\n");
			hollowed_modules++;
			log_module_info(module_entry);
		}
		else {
			is_hooked = is_module_hooked(processHandle, module_entry, original_module, module_size, directory);
			if (is_hooked == SCAN_MODIFIED) {
				printf("[*] The module is hooked!\n");
				hooked_modules++;
				log_module_info(module_entry);
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			printf("[-] ERROR occured while checking the module\n");
			error_modules++;
		}
		VirtualFree(original_module, module_size, MEM_FREE);

	} while (Module32Next(hProcessSnapShot, &module_entry));

	//close the handles
	CloseHandle(processHandle);
	CloseHandle(hProcessSnapShot);
	printf("[*] Scanned modules: %d\n", modules);
	printf("[*] Total hooked:  %d\n", hooked_modules);
	printf("[*] Total hollowed:  %d\n", hollowed_modules);
	if (error_modules) {
		printf("[!] Reading errors:  %d\n", error_modules);
	}
	printf("---\n");
	return hooked_modules + hollowed_modules;
}

int main(int argc, char *argv[])
{
	char *version = "0.0.7.4 alpha";
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
		printf("Found modules: %d saved to the file: %s\n", num, filename);
	}
	system("pause");
	return 0;
}

