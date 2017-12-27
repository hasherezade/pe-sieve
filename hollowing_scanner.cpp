#include "hollowing_scanner.h"
#include "peconv.h"

t_scan_status HollowingScanner::scanRemote(PBYTE modBaseAddr, PBYTE original_module, size_t module_size)
{
	BYTE hdr_buffer1[peconv::MAX_HEADER_SIZE] = { 0 };
	if (!peconv::read_remote_pe_header(processHandle, modBaseAddr, hdr_buffer1, peconv::MAX_HEADER_SIZE)) {
		std::cerr << "[-] Failed to read the module header" << std::endl;
		return SCAN_ERROR;
	}
	size_t hdrs_size = peconv::get_hdrs_size(hdr_buffer1);
	if (hdrs_size > peconv::MAX_HEADER_SIZE) {
		hdrs_size = peconv::MAX_HEADER_SIZE;
	}
	BYTE hdr_buffer2[peconv::MAX_HEADER_SIZE] = { 0 };
	memcpy(hdr_buffer2, original_module, hdrs_size);
	
	//normalize before comparing:
	peconv::update_image_base(hdr_buffer1, 0);
	peconv::update_image_base(hdr_buffer2, 0);

	zero_unused_fields(hdr_buffer1, hdrs_size);
	zero_unused_fields(hdr_buffer2, hdrs_size);

	//compare:
	if (memcmp(hdr_buffer1, hdr_buffer2, hdrs_size) != 0) {
		return SCAN_MODIFIED;
	}
	return SCAN_NOT_MODIFIED;
}

bool HollowingScanner::zero_unused_fields(PBYTE hdr_buffer, size_t hdrs_size)
{
	size_t section_num = peconv::get_sections_count(hdr_buffer, hdrs_size);
	bool is_modified = false;

	for (size_t i = 0; i < section_num; i++) {
		PIMAGE_SECTION_HEADER sec_hdr = peconv::get_section_hdr(hdr_buffer, hdrs_size, i);
		if (sec_hdr->SizeOfRawData == 0) {
			sec_hdr->PointerToRawData = 0;
			is_modified = true;
		}
	}
	return is_modified;
}

