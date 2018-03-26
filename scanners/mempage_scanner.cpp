#include "mempage_scanner.h"
#include "module_data.h"
#include "../utils/path_converter.h"

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
		std::cout << "Could not query page: " << std::hex << start_va << ". Error: " << GetLastError() << std::endl;
#endif
		return false;
	}
	initial_protect = page_info.AllocationProtect;
	mapping_type = page_info.Type;
	protection = page_info.Protect;
	alloc_base = (ULONGLONG) page_info.AllocationBase;
	region_start = (ULONGLONG) page_info.BaseAddress;
	region_end = region_start + page_info.RegionSize;
	return true;
}

bool MemPageData::isRealMapping()
{
	if (this->loadedData == nullptr && !fillInfo()) {
#ifdef _DEBUG
		std::cerr << "Not loaded!" << std::endl;
#endif
		return false;
	}
	std::string mapped_filename = RemoteModuleData::getMappedName(this->processHandle, (LPVOID) this->alloc_base);
	if (mapped_filename.length() == 0) {
#ifdef _DEBUG
		std::cerr << "Could not retrieve name" << std::endl;
#endif
		return false;
	}
#ifdef _DEBUG
	std::cout << mapped_filename << std::endl;
#endif
	HANDLE file = CreateFileA(mapped_filename.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		std::cerr << "Could not open file!" << std::endl;
#endif
		return false;
	}
	HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
	if (!mapping) {
#ifdef _DEBUG
		std::cerr << "Could not create mapping!" << std::endl;
#endif
		CloseHandle(file);
		return false;
	}
	BYTE *rawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (rawData == nullptr) {
#ifdef _DEBUG
		std::cerr << "Could not map view of file" << std::endl;
#endif
		CloseHandle(mapping);
		CloseHandle(file);
		return false;
	}

	bool is_same = false;
	size_t r_size = GetFileSize(file, 0);
	size_t smaller_size = this->loadedSize > r_size ? r_size : this->loadedSize;
	if (memcmp(this->loadedData, rawData, smaller_size) == 0) {
		is_same = true;
	}
	UnmapViewOfFile(rawData);
	CloseHandle(mapping);
	CloseHandle(file);
	return is_same;
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

bool MemPageData::loadRemote()
{
	peconv::free_pe_buffer(this->loadedData, this->loadedSize);
	size_t region_size = size_t(this->region_end - this->start_va);
	if (region_size == 0) {
		return false;
	}
	loadedData = peconv::alloc_aligned(region_size, PAGE_READWRITE);
	if (loadedData == nullptr) {
		return false;
	}
	this->loadedSize = region_size;

	if (!read_remote_mem(this->processHandle, (BYTE*) this->start_va, loadedData, loadedSize)) {
		freeRemote();
		return false;
	}
	return true;
}

ULONGLONG MemPageScanner::findPeHeader(MemPageData &memPage)
{
	if (memPage.loadedData == nullptr) {
		if (! memPage.loadRemote()) return PE_NOT_FOUND;
		if (memPage.loadedData == nullptr) return PE_NOT_FOUND;
	}
	size_t scan_size = memPage.loadedSize;
	BYTE* buffer_ptr = memPage.loadedData;

	//scan only one page, not the full area
	for (size_t i = 0; i < scan_size && i < peconv::MAX_HEADER_SIZE; i++) {
		if (peconv::get_nt_hrds(buffer_ptr+i) != nullptr) {
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
		|| (memPage.initial_protect & PAGE_EXECUTE);

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

	if (status == SCAN_SUSPICIOUS && memPage.mapping_type == MEM_MAPPED) {
		if (memPage.isRealMapping()) {
			//this is a legit mapping
			status = SCAN_NOT_SUSPICIOUS;
		}
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
