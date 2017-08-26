#include "remote_pe_reader.h"

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
