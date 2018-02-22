#include "mempage_scanner.h"

bool has_executable_section(BYTE hdrs[peconv::MAX_HEADER_SIZE])
{
	bool has_exec = false;
	t_scan_status status = SCAN_NOT_MODIFIED;
	//check details of the unlisted module...
	size_t sections_num = peconv::get_sections_count(hdrs, peconv::MAX_HEADER_SIZE);
	for (size_t i = 0; i < sections_num; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(hdrs, peconv::MAX_HEADER_SIZE, i);
		if (section_hdr == nullptr) continue;
		if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			has_exec = true;
			break;
		}
	}
	return has_exec;
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
	// if it is W+X always mark it as suspicious
	t_scan_status status = is_wx ? SCAN_MODIFIED : SCAN_NOT_MODIFIED;

	// otherwise, check othe features of the PE file:
	if (status != SCAN_MODIFIED) {
		//is it unlisted PE module with at leas one executable section?
		if (!memPage.is_listed_module && has_executable_section(hdrs)) {
			status = SCAN_MODIFIED;
		}
	}

	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)memPage.start_va, status);
	my_report->is_rwx = is_wx;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
