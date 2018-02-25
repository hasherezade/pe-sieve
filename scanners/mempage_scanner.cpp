#include "mempage_scanner.h"

bool MemPageData::fillInfo()
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	SIZE_T out = VirtualQueryEx(this->processHandle, (LPCVOID) start_va, &page_info, sizeof(page_info));
	if (out != 0) {
		initial_protect = page_info.AllocationProtect;
		is_private = (page_info.Type == MEM_PRIVATE);
		protection = page_info.Protect;
		return true;
	}
	if (basic_protection == 0) { // accerss denied
		return false;
	}
	std::cout << "info error: " << std::dec << GetLastError() << "basicp: " << basic_protection << std::endl;
	return false;
}

MemPageScanReport* MemPageScanner::scanRemote(MemPageData &memPage)
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
		return nullptr;
	}
	if (!memPage.is_private) {
		return nullptr;
	}
	if (memPage.protection & PAGE_EXECUTE_WRITECOPY) {
		// they are probably legit
		return nullptr;
	}

	bool only_executable = true; //scan only executable pages
	DWORD depFlags = 0;
	BOOL isPermantent = FALSE;
	if (GetProcessDEPPolicy( this->processHandle, &depFlags, &isPermantent)){
		if (depFlags != PROCESS_DEP_ENABLE) { //DEP is disabled, malware can be injected also in non-executable page
			only_executable = false;
		}
	}
	// is the page executable?
	bool is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE);

	if (only_executable && !is_any_exec) {
		// scanning only executable was enabled
		return nullptr;
	}
	if (!is_any_exec && memPage.is_listed_module) {
		//it was already scanned, probably not interesting
		std::cout << std::hex << memPage.start_va << "Aleady listed" << std::endl;
		return nullptr;
	}
	static BYTE hdrs[peconv::MAX_HEADER_SIZE] = { 0 };
	memset(hdrs, 0, peconv::MAX_HEADER_SIZE);
	if (!peconv::read_remote_pe_header(this->processHandle,(BYTE*) memPage.start_va, hdrs, peconv::MAX_HEADER_SIZE)) {
		// this is not a PE file
		return nullptr;
	}
	std::cout << "[" << std::hex << memPage.start_va << "] " << " initial: " <<  memPage.initial_protect << " current: " << memPage.protection << std::endl;
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)memPage.start_va, SCAN_SUSPICIOUS);
	my_report->is_rwx = (memPage.protection == PAGE_EXECUTE_READWRITE);
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
