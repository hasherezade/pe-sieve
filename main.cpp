// Enumerates all the hooked modules in the process with a given PID
// saves the list in the log with the given format:
// <module_start>,<module_end>,<module_name>
// CC-BY: hasherezade
// WARNING: this is alpha version!

#include <stdio.h>

#include "peloader\util.h"
#include "peloader\pe_hdrs_helper.h"
#include "peloader\pe_raw_to_virtual.h"
#include "peloader\pe_virtual_to_raw.h"
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
		delete []module_code;
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

bool dump_module(const char *out_path, const HANDLE processHandle, BYTE *start_addr, size_t mod_size)
{
	BYTE* buffer = (BYTE*) VirtualAlloc(NULL, mod_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD read_size = 0;

	if (!ReadProcessMemory(processHandle, start_addr, buffer, mod_size, &read_size)) {
		printf("[-] Failed reading module. Error: %d\n", GetLastError());
		VirtualFree(buffer, mod_size, MEM_FREE);
		buffer = NULL;
		return false;
	}
	BYTE* dump_data = buffer;
	size_t dump_size = mod_size;

	size_t out_size = 0;
	BYTE* unmapped_module = pe_virtual_to_raw(buffer, mod_size, (ULONGLONG)start_addr, out_size);
	if (unmapped_module != NULL) {
		dump_data = unmapped_module;
		dump_size = out_size;
	}
	FILE *f1 = fopen(out_path, "wb");
	if (f1) {
		fwrite(dump_data, 1, dump_size, f1);
		fclose(f1);
		printf("Module dumped to: %s\n", out_path);
	}
	VirtualFree(buffer, mod_size, MEM_FREE);
	buffer = NULL;
	if (unmapped_module) {
		VirtualFree(unmapped_module, mod_size, MEM_FREE);
	}
	return true;
}

bool dump_to_file(const char *file_name, BYTE* data, size_t data_size)
{
	FILE *f1 = fopen(file_name, "wb");
	if (!f1) {
		return false;
	}
	fwrite(data, 1, data_size, f1);
	fclose(f1);
	return true;
}

size_t report_patches(const char* file_name, DWORD rva, BYTE *orig_code, BYTE *patched_code, size_t code_size)
{
	const char delimiter = ';';
	FILE *f1 = fopen(file_name, "wb");
	size_t patches_count = 0;

	bool patch_flag = false;
	for (size_t i = 0; i < code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			patch_flag = false;
			continue;
		}
		if (patch_flag == false) {
			patch_flag = true;
			if (f1) {
				fprintf(f1, "%8.8X%cpatch_%d\n", rva + i, delimiter, patches_count);
			} else {
				printf("%8.8X\n", rva + i);
			}
			patches_count++;
		}
	}
	if (f1) fclose(f1);
	return patches_count;
}

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

size_t enum_modules_in_process(DWORD process_id, FILE *f)
{
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (!hProcessSnapShot) {
		return 0;
	}

	HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
	if (processHandle == NULL)  {
		printf("[-] Could not open the process for reading!\n");
		return 0;
	}

	//make a directory to store the dumps:
	char directory[MAX_PATH] = { 0 };
	bool is_dir = make_dump_dir(process_id, directory);

	size_t hooked_modules = 0;
	size_t modules = 1;

	MODULEENTRY32 module_entry = { 0 };
	module_entry.dwSize = sizeof(module_entry);

	printf("---\n");
	//check all modules in the process, including the main module:
	if (!Module32First(hProcessSnapShot, &module_entry)) {
		CloseHandle(processHandle);
		return 0;
	}
	do {		
		modules++;
		if (processHandle == NULL) continue;

		//get the code section from the module:
		size_t read_size = 0;
		BYTE *loaded_code = get_module_code(module_entry.modBaseAddr, module_entry.modBaseSize, processHandle, read_size);
		if (loaded_code == NULL) continue;

		//load the same module, but from the disk:
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

		//check if the code of the loaded module is same as the code of the module on the disk:
		int res = memcmp(loaded_code, orig_code, smaller_size);
		char mod_name[MAX_PATH] = { 0 };

		if (res != 0) {
			printf("[!] %s is hooked!\n", module_entry.szExePath);
			hooked_modules++;
			log_info(f, module_entry);
			//
			sprintf(mod_name, "%s\\%llX.dll", directory, (ULONGLONG)module_entry.modBaseAddr);
			if (!dump_module(mod_name, processHandle, module_entry.modBaseAddr, module_entry.modBaseSize)) {
				printf("Failed dumping module!\n");
			}
			//---
			sprintf(mod_name, "%s\\%llX.dll.tag", directory, (ULONGLONG)module_entry.modBaseAddr);
			size_t patches_count = report_patches(mod_name, section_hdr->VirtualAddress, orig_code, loaded_code, smaller_size);
			if (patches_count) {
				printf("Total patches: %d\n", patches_count);
			}
			//---
		} else {
			printf("[*] %s is NOT hooked!\n", module_entry.szExePath);
		}
		VirtualFree(original_module, module_size, MEM_FREE);
		delete []loaded_code;

	} while (Module32Next(hProcessSnapShot, &module_entry));

	//close the handles
	CloseHandle(processHandle);
	CloseHandle(hProcessSnapShot);
	printf("[*] Total modules: %d\n", modules);
	printf("[*] Total hooked:  %d\n", hooked_modules);
	printf("---\n");
	return hooked_modules;
}

int main(int argc, char *argv[])
{
	char *version = "0.0.2 alpha";
	if (argc < 2) {
		printf("[hook_finder v%s]\n", version);
		printf("A small tool allowing to detect and examine inline hooks\n---\n");
		printf("Args: <PID>\n");
		printf("PID: (decimal) PID of the target application\n");
		printf("---\n");
		system("pause");
		return -1;
	}

	DWORD pid = atoi(argv[1]);
	printf("PID: %d\n", pid);
	
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

