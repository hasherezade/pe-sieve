#include "mempage_scanner.h"

t_scan_status check_unlisted_module(BYTE hdrs[peconv::MAX_HEADER_SIZE])
{
	t_scan_status status = SCAN_NOT_MODIFIED;
	//check details of the unlisted module...
	size_t sections_num = peconv::get_sections_count(hdrs, peconv::MAX_HEADER_SIZE);
	for (size_t i = 0; i < sections_num; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(hdrs, peconv::MAX_HEADER_SIZE, i);
		if (section_hdr == nullptr) continue;
		if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			status = SCAN_MODIFIED; //if at least one executable section has been found in the PE, it may be suspicious
		}
	}
	return status;
}

MemPageScanReport* MemPageScanner::scanRemote(MemPageData &memPage)
{
	// skip pages that are not not executable
	if (!(memPage.protection & MEMPROTECT_X)) {
		return nullptr;
	}
	// WRITE + EXECUTE -> suspicious
	bool is_wx = (memPage.protection & MEMPROTECT_X) && (memPage.protection & MEMPROTECT_W);

	if (!is_wx && memPage.is_listed_module) {
		//it was already scanned, probably not interesting
		return nullptr;
	}

	BYTE hdrs[peconv::MAX_HEADER_SIZE] = { 0 };
	if (!peconv::read_remote_pe_header(this->processHandle,(BYTE*) memPage.start_va, hdrs, peconv::MAX_HEADER_SIZE)) {
		// this is not a PE file
		return nullptr;
	}

	t_scan_status status = SCAN_NOT_MODIFIED;
	if (is_wx) status = SCAN_MODIFIED; 
	// it is a PE file, and it was not on the list of modules...
	if (!memPage.is_listed_module) {
		status = check_unlisted_module(hdrs);
	}

	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)memPage.start_va, status);
	my_report->is_rwx = is_wx;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
