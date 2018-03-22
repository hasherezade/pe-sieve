#include "mempage_scanner.h"
#include "module_data.h"

#define PE_NOT_FOUND 0

bool MemPageData::fillInfo()
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	SIZE_T out = VirtualQueryEx(this->processHandle, (LPCVOID) start_va, &page_info, sizeof(page_info));
	if (out != sizeof(page_info)) {
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			return false;
		}
#ifdef _DEBUG
		std::cout << "Could not query page: " << std::hex << start_va << " basic protect:" << basic_protection << ". Error: " << GetLastError() << std::endl;
#endif
		return false;
	}
	initial_protect = page_info.AllocationProtect;
	mapping_type = page_info.Type;
	protection = page_info.Protect;
	region_start = (ULONGLONG) page_info.BaseAddress;
	region_end = region_start + page_info.RegionSize;
	return true;
}

bool read_remote_mem(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size)
{
	if (buffer == nullptr) return false;

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
		return true;
	}
	return false;
}

ULONGLONG MemPageScanner::findPeHeader(MemPageData &memPage)
{
	const size_t buffer_size = 2 * peconv::MAX_HEADER_SIZE;
	static BYTE buffer[buffer_size] = { 0 };

	size_t scan_size = size_t(memPage.region_end - memPage.start_va);
	if (scan_size > buffer_size) scan_size = buffer_size;

	if (!read_remote_mem(this->processHandle, (BYTE*) memPage.start_va, buffer, scan_size)) {
		return PE_NOT_FOUND; // could not read the region
	}
	//scan only one page, not the full area
	for (size_t i = 0; i < scan_size && i < peconv::MAX_HEADER_SIZE; i++) {
		if (peconv::get_nt_hrds(buffer+i) != nullptr) {
			return  memPage.start_va + i;
		}
		if (!this->isDeepScan) {
			return PE_NOT_FOUND;
		}
	}
	return PE_NOT_FOUND;
}
MemPageScanReport* MemPageScanner::scanRemote()
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
		return nullptr;
	}
	if (memPage.mapping_type == MEM_IMAGE) {
		//probably legit
		return nullptr;
	}

	bool only_executable = true;

	// is the page executable?
	bool is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.basic_protection & MEMPROTECT_X);

	if (!is_any_exec && memPage.is_listed_module) {
		// probably not interesting
		std::cout << std::hex << memPage.start_va << "Aleady listed" << std::endl;
		return nullptr;
	}
	ULONGLONG pe_header = findPeHeader(memPage);
	if (pe_header == PE_NOT_FOUND) {
		return nullptr; // not a PE file
	}
	RemoteModuleData remoteModule(this->processHandle, (HMODULE)pe_header);
	bool is_executable = remoteModule.hasExecutableSection();

	t_scan_status status = is_executable ? SCAN_SUSPICIOUS : SCAN_NOT_SUSPICIOUS;
	if (!only_executable) {
		// treat every injected PE file as suspicious, even if it does not have any executable sections
		status = SCAN_SUSPICIOUS;
	}

#ifdef _DEBUG
	std::cout << "[" << std::hex << memPage.start_va << "] " << " initial: " <<  memPage.initial_protect << " current: " << memPage.protection << std::endl;
#endif
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)pe_header, status);
	my_report->is_executable = is_executable;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
