#include "mempage_scanner.h"

//template <typename T_MEMORY_BASIC_INFORMATION>
bool fill_page_info(HANDLE hProcess, MemPageData &memPageData)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	SIZE_T out = VirtualQueryEx(hProcess, (LPCVOID) memPageData.start_va, &page_info, sizeof(page_info));
	if (out != 0) {
		memPageData.initial_protect = page_info.AllocationProtect;
		memPageData.is_private = (page_info.Type == MEM_PRIVATE);
		memPageData.protection = page_info.Protect;
		return true;
	}
	if (memPageData.basic_protection == 0) { // accerss denied
		return false;
	}
	std::cout << "info error: " << std::dec << GetLastError() << "basicp: " << memPageData.basic_protection << std::endl;
	return false;
}

bool MemPageData::fillInfo()
{
	is_info_filled = false;
	/*
	BOOL is32b = TRUE;
#ifdef _WIN64
	IsWow64Process(this->processHandle, &is32b);
	if (!is32b) {
		is_info_filled = fill_page_info(this->processHandle, *this);
		return is_info_filled;
	}
#endif*/
	is_info_filled = fill_page_info(this->processHandle, *this);
	return is_info_filled;
}

MemPageScanReport* MemPageScanner::scanRemote(MemPageData &memPage)
{
	if (!memPage.is_info_filled && !memPage.fillInfo()) {
		return nullptr;
	}
	if (!memPage.is_private) {
		return nullptr;
	}
	// is the page executable?
	bool is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE);
	
	if ((memPage.protection & PAGE_EXECUTE_WRITECOPY) 
		|| (memPage.protection == PAGE_READONLY)
		)
	{
		// they are probably legit
		return nullptr;
	}

	if (memPage.is_listed_module) {
		std::cout << std::hex << memPage.start_va << "Aleady listed" << std::endl;
	}
	if (!is_any_exec && memPage.is_listed_module) {
		//it was already scanned, probably not interesting
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
