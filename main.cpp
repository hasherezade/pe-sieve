// Enumerates all the hooked modules in the process with a given PID
// saves the list in the log with the given format:
// <module_start>,<module_end>,<module_name>
// CC-BY: hasherezade
// WARNING: this is alpha version!

#include <stdio.h>

#include "peloader\util.h"
#include "peloader\pe_hdrs_helper.h"
#include "peloader\pe_raw_to_virtual.h"
#include "peloader\relocate.h"

#include <Windows.h>
#include <TlHelp32.h>

void log_info(FILE *f, MODULEENTRY32 &module_entry)
{
	BYTE* mod_end = module_entry.modBaseAddr + module_entry.modBaseSize;
	fprintf(f, "%p,%p,%s\n", module_entry.modBaseAddr, mod_end, module_entry.szModule);
	fflush(f);
}

BYTE* get_module_code(BYTE *start_addr, size_t mod_size, HANDLE processHandle, size_t &code_size)
{
	const size_t header_size = 0x400;
	BYTE header_buffer[header_size] = { 0 };
	DWORD read_size = 0;
	ReadProcessMemory(processHandle, start_addr, header_buffer, header_size, &read_size);

	if (read_size != header_size) {
		return NULL;
	}
	PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(header_buffer, header_size, 0);
	BYTE *module_code = new BYTE[section_hdr->SizeOfRawData];
	if (module_code == NULL) {
		return NULL;
	}

	ReadProcessMemory(processHandle, start_addr + section_hdr->VirtualAddress, module_code, section_hdr->SizeOfRawData, &read_size);
	if (read_size != section_hdr->SizeOfRawData) {
		return NULL;
	}
	code_size = read_size;
	return module_code;
}

bool clear_iat(PIMAGE_SECTION_HEADER section_hdr, BYTE* original_module, BYTE* loaded_code)
{
	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
	IMAGE_DATA_DIRECTORY* iat_dir = get_pe_directory(original_module, 12); //GET_IAT
	if (!iat_dir) {
		return false;
	}
	DWORD iat_rva = iat_dir->VirtualAddress;
	DWORD iat_size = iat_dir->Size;
	DWORD iat_end = iat_rva + iat_size;

	if (
		(iat_rva >= section_hdr->VirtualAddress && (iat_rva < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
		|| (iat_end >= section_hdr->VirtualAddress && (iat_end < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
	)
	{
		printf("IAT is in Code section!\n");
		DWORD offset = iat_rva - section_hdr->VirtualAddress;
		memset(orig_code + offset, 0, iat_size);
		memset(loaded_code + offset, 0, iat_size);
	}
	return true;
}

bool dump_module(HANDLE processHandle, BYTE *start_addr, size_t mod_size)
{
	BYTE* buffer = (BYTE*) VirtualAlloc(NULL, mod_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD read_size = 0;
	ReadProcessMemory(processHandle, start_addr, buffer, mod_size, &read_size);
	if (read_size == 0) {
		VirtualFree(buffer, mod_size, MEM_FREE);
		buffer = NULL;
		return false;
	}
	char mod_name[MAX_PATH] = { 0 };
	sprintf(mod_name, "%llX.bin", (ULONGLONG)start_addr);
	FILE *f1 = fopen(mod_name, "wb");
	if (f1) {
		fwrite(buffer, 1, mod_size, f1);
		fclose(f1);
		printf("Module dumped to: %s\n", mod_name);
	}
	VirtualFree(buffer, mod_size, MEM_FREE);
	buffer = NULL;
	return true;
}

size_t enum_modules_in_process(DWORD process_id, FILE *f)
{
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	MODULEENTRY32 module_entry = { 0 };
	module_entry.dwSize = sizeof(module_entry);

	if (!Module32First(hProcessSnapShot, &module_entry)) {
      return 0;
	}
	size_t modules = 1;

	HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
	if (processHandle == NULL)  {
		printf("Could not open process for reading!\n");
		return 0;
	}
	size_t hooked_modules = 0;
    while (Module32Next(hProcessSnapShot, &module_entry)) {
		
		modules++;
		if (processHandle == NULL) continue;

		size_t read_size = 0;
		BYTE *loaded_code = get_module_code(module_entry.modBaseAddr, module_entry.modBaseSize, processHandle, read_size);
		if (loaded_code == NULL) continue;

		printf("Module: %s\n", module_entry.szExePath);
		size_t module_size = 0;
		BYTE* original_module = load_pe_module(module_entry.szExePath, module_size);
		if (original_module == NULL) {
			printf("Could not read original module!\n");
			continue;
		}
		ULONGLONG original_base = get_module_base(original_module);
		printf("original base: %llX\n", original_base);

		ULONGLONG new_base = (ULONGLONG) module_entry.modBaseAddr;
		printf("mapped base:   %llX\n", new_base);

		if (!apply_relocations(new_base, original_base, original_module, module_size)) {
			printf("reloc failed!\n");
		}

		PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(original_module, module_size, 0);
		BYTE *orig_code = original_module + section_hdr->VirtualAddress;
		
		clear_iat(section_hdr, original_module, loaded_code);
		
		size_t smaller_size = section_hdr->SizeOfRawData > read_size ? read_size : section_hdr->SizeOfRawData;
		printf("Code RVA: %x to %x\n", section_hdr->VirtualAddress, section_hdr->SizeOfRawData);
		
		int res = memcmp(loaded_code, orig_code, smaller_size);

		if (res != 0) {
			printf("[!] %s is hooked!\n\n", module_entry.szExePath);
			hooked_modules++;
			log_info(f, module_entry);
			//
			if (!dump_module(processHandle, module_entry.modBaseAddr, module_entry.modBaseSize)) {
				printf("Failed dumping module!\n");
			}
			//---
			char mod_name[MAX_PATH] = { 0 };

			sprintf(mod_name, "%llX_hooked_code.bin", (ULONGLONG)module_entry.modBaseAddr);
			FILE *f1 = fopen(mod_name, "wb");
			if (f1) {
				printf("dumped\n");
				fwrite(loaded_code, 1, read_size, f1);
				fclose(f1);
				f1 = NULL;
			}
			sprintf(mod_name, "%llX_original_code.bin", (ULONGLONG)module_entry.modBaseAddr);
			f1 = fopen(mod_name, "wb");
			if (f1) {
				fwrite(orig_code, 1, section_hdr->SizeOfRawData, f1);
				fclose(f1);
				f1 = NULL;
			}
			//---
			//
		} else {
			printf("[*] %s is NOT hooked!\n\n", module_entry.szExePath);
		}
		VirtualFree(original_module, module_size, MEM_FREE);
		delete []loaded_code;
		}
	if (processHandle) {
		CloseHandle(processHandle);
	}
	// Close the handle
	CloseHandle(hProcessSnapShot);
	printf("[*] Total modules: %d\n", modules);
	printf("[*] Total hooked:  %d\n", hooked_modules);
	return hooked_modules;
}

int main(int argc, char *argv[])
{
	DWORD pid = GetCurrentProcessId();
	if (argc >= 2) {
		pid = atoi(argv[1]);
		printf("PID: %d\n", pid);
	}
	
	char filename[MAX_PATH] = { 0 };
	sprintf(filename,"PID_%d_modules.txt", pid);
	FILE *f = fopen(filename, "w");
	if (!f) {
		printf("[ERROR] Cannot open file!\n");
		system("pause");
		return -1;
	}
	
	int num = enum_modules_in_process(pid, f);
	fclose(f);
	printf("Found modules: %d saved to the file: %s\n", num, filename);
	system("pause");
	return 0;
}

