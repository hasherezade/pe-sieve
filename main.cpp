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
#include <stdlib.h>

#define HEADER_SIZE 0x800

void log_info(FILE *f, MODULEENTRY32 &module_entry)
{
	BYTE* mod_end = module_entry.modBaseAddr + module_entry.modBaseSize;
	fprintf(f, "%p,%p,%s\n", module_entry.modBaseAddr, mod_end, module_entry.szModule);
	fflush(f);
}

bool read_module_header(HANDLE processHandle, BYTE *start_addr, size_t mod_size, OUT BYTE* buffer, const size_t buffer_size)
{
	DWORD read_size = 0;
	ReadProcessMemory(processHandle, start_addr, buffer, buffer_size, &read_size);
	if (get_nt_hrds(buffer) == NULL) {
		printf("[-] Cannot get the module header!\n");
		return false;
	}
	if (read_size < get_hdrs_size(buffer)) {
		return false;
	}
	return true;
}

BYTE* get_module_section(HANDLE processHandle, BYTE *start_addr, size_t mod_size, const size_t section_num, OUT size_t &section_size)
{
	BYTE header_buffer[HEADER_SIZE] = { 0 };
	DWORD read_size = 0;

	if (!read_module_header(processHandle, start_addr, mod_size, header_buffer, HEADER_SIZE)) {
		return NULL;
	}
	PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(header_buffer, HEADER_SIZE, section_num);
	if (section_hdr == NULL || section_hdr->SizeOfRawData == 0) {
		return NULL;
	}
	BYTE *module_code = (BYTE*) calloc(section_hdr->SizeOfRawData, sizeof(BYTE));
	if (module_code == NULL) {
		return NULL;
	}
	ReadProcessMemory(processHandle, start_addr + section_hdr->VirtualAddress, module_code, section_hdr->SizeOfRawData, &read_size);
	if (read_size != section_hdr->SizeOfRawData) {
		free(module_code);
		return NULL;
	}
	section_size = read_size;
	return module_code;
}

void free_module_section(BYTE *section_buffer)
{
	free(section_buffer);
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

size_t read_pe_from_memory(const HANDLE processHandle, BYTE *start_addr, const size_t mod_size, OUT BYTE* buffer)
{
	DWORD read_size = 0;
	if (ReadProcessMemory(processHandle, start_addr, buffer, mod_size, &read_size)) {
		return read_size;
	}
	printf("[!] Warning: failed to read full module at once: %d\n", GetLastError());
	printf("[*] Trying to read the module section by section...\n");
	BYTE hdr_buffer[HEADER_SIZE] = { 0 };
	if (!read_module_header(processHandle, start_addr, mod_size, hdr_buffer, HEADER_SIZE)) {
		printf("[-] Failed to read the module header\n");
		return 0;
	}
	//if not possible to read full module at once, try to read it section by section:
	size_t sections_count = get_sections_count(hdr_buffer, HEADER_SIZE);
	for (size_t i = 0; i < sections_count; i++) {
		DWORD read_sec_size = 0;
		PIMAGE_SECTION_HEADER hdr = get_section_hdr(hdr_buffer, HEADER_SIZE, i);
		if (!hdr) {
			printf("[-] Failed to read the header of section: %d\n", i);
			break;
		}
		const DWORD sec_va = hdr->VirtualAddress;
		const DWORD sec_size = hdr->SizeOfRawData;
		if (!ReadProcessMemory(processHandle, start_addr + sec_va, buffer + sec_va, sec_size, &read_sec_size)) {
			printf("[-] Failed to read the module section: %d\n", i);
		}
		read_size = sec_va + read_sec_size;
	}
	return read_size;
}

bool dump_module(const char *out_path, const HANDLE processHandle, BYTE *start_addr, size_t mod_size)
{
	BYTE* buffer = (BYTE*) VirtualAlloc(NULL, mod_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD read_size = 0;

	if ((read_size = read_pe_from_memory(processHandle, start_addr, mod_size, buffer)) == 0) {
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

int is_module_replaced(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory)
{
	BYTE hdr_buffer1[HEADER_SIZE] = { 0 };
	if (!read_module_header(processHandle, module_entry.modBaseAddr, module_entry.modBaseSize, hdr_buffer1, HEADER_SIZE)) {
		printf("[-] Failed to read the module header\n");
		return -1;
	}
	size_t hdrs_size = get_hdrs_size(hdr_buffer1);
	if (hdrs_size > HEADER_SIZE) hdrs_size = HEADER_SIZE;

	BYTE hdr_buffer2[HEADER_SIZE] = { 0 };
	memcpy(hdr_buffer2, original_module, hdrs_size);

	update_image_base(hdr_buffer1, 0);
	update_image_base(hdr_buffer2, 0);
	if (memcmp(hdr_buffer1, hdr_buffer2, hdrs_size) != 0) {
		char mod_name[MAX_PATH] = { 0 };
		sprintf(mod_name, "%s\\%llX.dll", directory, (ULONGLONG)module_entry.modBaseAddr);
		if (!dump_module(mod_name, processHandle, module_entry.modBaseAddr, module_entry.modBaseSize)) {
			printf("Failed dumping module!\n");
		}
		return 1; // modified
	}
	return 0; //not modified
}

int is_module_hooked(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory)
{
	//get the code section from the module:
	size_t read_size = 0;
	BYTE *loaded_code = get_module_section(processHandle, module_entry.modBaseAddr, module_entry.modBaseSize, 0, read_size);
	if (loaded_code == NULL) return -1;

	ULONGLONG original_base = get_image_base(original_module);
	ULONGLONG new_base = (ULONGLONG) module_entry.modBaseAddr;
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
	if (res != 0) {
		char mod_name[MAX_PATH] = { 0 };
		sprintf(mod_name, "%s\\%llX.dll.tag", directory, (ULONGLONG)module_entry.modBaseAddr);
		size_t patches_count = report_patches(mod_name, section_hdr->VirtualAddress, orig_code, loaded_code, smaller_size);
		if (patches_count) {
			printf("Total patches: %d\n", patches_count);
		}
		sprintf(mod_name, "%s\\%llX.dll", directory, (ULONGLONG)module_entry.modBaseAddr);
		if (!dump_module(mod_name, processHandle, module_entry.modBaseAddr, module_entry.modBaseSize)) {
			printf("Failed dumping module!\n");
		}
	}
	free_module_section(loaded_code);
	loaded_code = NULL;

	if (res != 0) {
		return 1; // modified
	}
	return 0; //not modified
}

size_t enum_modules_in_process(DWORD process_id, FILE *f)
{
	HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (!hProcessSnapShot) {
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
	size_t modules = 1;

	MODULEENTRY32 module_entry = { 0 };
	module_entry.dwSize = sizeof(module_entry);

	printf("---\n");
	char mod_name[MAX_PATH] = { 0 };

	//check all modules in the process, including the main module:
	if (!Module32First(hProcessSnapShot, &module_entry)) {
		CloseHandle(processHandle);
		return 0;
	}
	do {		
		modules++;
		if (processHandle == NULL) continue;

		//load the same module, but from the disk:
		printf("Module: %s\n", module_entry.szExePath);
		sprintf(mod_name, "%s\\%llX.dll.tag", directory, (ULONGLONG)module_entry.modBaseAddr);

		size_t module_size = 0;
		BYTE* original_module = load_pe_module(module_entry.szExePath, module_size);
		if (original_module == NULL) {
			printf("Could not read original module!\n");
			continue;
		}
		int is_hollowed = 0;
		int is_hooked = 0;
		is_hollowed = is_module_replaced(processHandle, module_entry, original_module, module_size, directory);
		if (is_hollowed == 1) {
			printf("[!] Module has been replaced by a different PE!\n");
			hollowed_modules++;
		}
		else {
			is_hooked = is_module_hooked(processHandle, module_entry, original_module, module_size, directory);
			if (is_hooked == 1) {
				printf("[!] %s is hooked!\n", module_entry.szExePath);
				hooked_modules++;
				log_info(f, module_entry);
			}
		}
		if (is_hollowed == -1 || is_hooked == -1) {
			printf("[!] ERROR occured while checking the module\n");
		}
		VirtualFree(original_module, module_size, MEM_FREE);

	} while (Module32Next(hProcessSnapShot, &module_entry));

	//close the handles
	CloseHandle(processHandle);
	CloseHandle(hProcessSnapShot);
	printf("[*] Total modules: %d\n", modules);
	printf("[*] Total hooked:  %d\n", hooked_modules);
	printf("[*] Total hollowed:  %d\n", hollowed_modules);
	printf("---\n");
	return hooked_modules;
}

int main(int argc, char *argv[])
{
	char *version = "0.0.5 alpha";
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

