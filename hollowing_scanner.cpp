#include "hollowing_scanner.h"
#include "peconv.h"

t_scan_status is_module_replaced(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory)
{
	BYTE hdr_buffer1[MAX_HEADER_SIZE] = { 0 };
	if (!read_remote_pe_header(processHandle, module_entry.modBaseAddr, module_entry.modBaseSize, hdr_buffer1, MAX_HEADER_SIZE)) {
		printf("[-] Failed to read the module header\n");
		return SCAN_ERROR;
	}
	size_t hdrs_size = get_hdrs_size(hdr_buffer1);
	if (hdrs_size > MAX_HEADER_SIZE) hdrs_size = MAX_HEADER_SIZE;

	BYTE hdr_buffer2[MAX_HEADER_SIZE] = { 0 };
	memcpy(hdr_buffer2, original_module, hdrs_size);

	update_image_base(hdr_buffer1, 0);
	update_image_base(hdr_buffer2, 0);
	if (memcmp(hdr_buffer1, hdr_buffer2, hdrs_size) != 0) {
		char mod_name[MAX_PATH] = { 0 };

		if (is_module_dll(hdr_buffer1)) {
			sprintf(mod_name, "%s\\%llX.dll", directory, (ULONGLONG)module_entry.modBaseAddr);
		} else {
			sprintf(mod_name, "%s\\%llX.exe", directory, (ULONGLONG)module_entry.modBaseAddr);
		}
		
		if (!dump_remote_pe(mod_name, processHandle, module_entry.modBaseAddr, module_entry.modBaseSize, true)) {
			printf("Failed dumping module!\n");
		}
		return SCAN_MODIFIED; // modified
	}
	return SCAN_NOT_MODIFIED; //not modified
}