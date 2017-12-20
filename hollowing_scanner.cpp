#include "hollowing_scanner.h"
#include "peconv.h"

using namespace peconv;

t_scan_status HollowingScanner::scanRemote(PBYTE modBaseAddr, PBYTE original_module, size_t module_size)
{
	BYTE hdr_buffer1[MAX_HEADER_SIZE] = { 0 };
	if (!read_remote_pe_header(processHandle, modBaseAddr, hdr_buffer1, MAX_HEADER_SIZE)) {
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
		std::string mod_name = make_module_path((ULONGLONG)modBaseAddr, directory);
		
		if (!dump_remote_pe(mod_name.c_str(), processHandle, modBaseAddr, true)) {
			printf("Failed dumping module!\n");
		}
		return SCAN_MODIFIED; // modified
	}
	return SCAN_NOT_MODIFIED; //not modified
}
