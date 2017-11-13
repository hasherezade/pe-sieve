#include "remote_pe_reader.h"

bool read_module_header(HANDLE processHandle, BYTE *start_addr, size_t mod_size, OUT BYTE* buffer, const size_t buffer_size)
{
	SIZE_T read_size = 0;
	const SIZE_T step_size = 0x100;
	SIZE_T to_read_size = buffer_size;

	memset(buffer, 0, buffer_size);
	while (to_read_size >= step_size) {
		BOOL is_ok = ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size);
		if (!is_ok) {
			//try to read less
			to_read_size -= step_size;
			continue;
		}
		if (get_nt_hrds(buffer) == NULL) {
			printf("[-] Cannot get the module header!\n");
			return false;
		}
		if (read_size < get_hdrs_size(buffer)) {
			printf("[-] Read size: %#x is smaller that the headers size: %#x\n", read_size, get_hdrs_size(buffer));
			return false;
		}
		//reading succeeded and the header passed the checks:
		return true;
	}
	return false;
}

BYTE* get_module_section(HANDLE processHandle, BYTE *start_addr, size_t mod_size, const size_t section_num, OUT size_t &section_size)
{
	BYTE header_buffer[MAX_HEADER_SIZE] = { 0 };
	SIZE_T read_size = 0;

	if (!read_module_header(processHandle, start_addr, mod_size, header_buffer, MAX_HEADER_SIZE)) {
		return NULL;
	}
	PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(header_buffer, MAX_HEADER_SIZE, section_num);
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

size_t read_pe_from_memory(const HANDLE processHandle, BYTE *start_addr, const size_t mod_size, OUT BYTE* buffer)
{
	SIZE_T read_size = 0;
	if (ReadProcessMemory(processHandle, start_addr, buffer, mod_size, &read_size)) {
		return read_size;
	}
	printf("[!] Warning: failed to read full module at once: %d\n", GetLastError());
	printf("[*] Trying to read the module section by section...\n");
	BYTE hdr_buffer[MAX_HEADER_SIZE] = { 0 };
	if (!read_module_header(processHandle, start_addr, mod_size, hdr_buffer, MAX_HEADER_SIZE)) {
		printf("[-] Failed to read the module header\n");
		return 0;
	}
	//if not possible to read full module at once, try to read it section by section:
	size_t sections_count = get_sections_count(hdr_buffer, MAX_HEADER_SIZE);
	for (size_t i = 0; i < sections_count; i++) {
		SIZE_T read_sec_size = 0;
		PIMAGE_SECTION_HEADER hdr = get_section_hdr(hdr_buffer, MAX_HEADER_SIZE, i);
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