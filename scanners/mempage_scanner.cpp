#include "mempage_scanner.h"
#include "module_data.h"
#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"

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

	bool is_guarded = (protection & PAGE_GUARD) != 0;

	this->loadedSize = region_size;
	size_t size_read = peconv::read_remote_memory(this->processHandle, (BYTE*)this->start_va, loadedData, loadedSize);
	if ((size_read == 0) && is_guarded) {
#ifdef _DEBUG
		std::cout << "Warning: guarded page, trying to read again..." << std::endl;
#endif
		size_read = peconv::read_remote_memory(this->processHandle, (BYTE*)this->start_va, loadedData, loadedSize);
	}
	if (size_read == 0) {
		freeRemote();
#ifdef _DEBUG
		std::cerr << "Cannot read remote memory!" << std::endl;
#endif
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
		if (peconv::get_nt_hrds(buffer_ptr+i, scan_size-i) != nullptr) {
			return  memPage.start_va + i;
		}
		if (!this->isDeepScan) {
			return PE_NOT_FOUND;
		}
	}
	return PE_NOT_FOUND;
}

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

bool is_valid_section(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact)
{
	PIMAGE_SECTION_HEADER hdr_candidate = (PIMAGE_SECTION_HEADER) hdr_ptr;
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, sizeof(IMAGE_SECTION_HEADER))) {
		// probably buffer finished
		return false;
	}
	if (hdr_candidate->PointerToRelocations != 0
		|| hdr_candidate->NumberOfRelocations != 0
		|| hdr_candidate->PointerToLinenumbers != 0)
	{
		//values that should be NULL are not
		return false;
	}
	if (charact != 0 && (hdr_candidate->Characteristics & charact) == 0) {
		// required characteristics not found
		std::cout << "The section " << hdr_candidate->Name << " NOT  valid, charact:" << std::hex << hdr_candidate->Characteristics << std::endl;
		return false;
	}
	std::cout << "The section " << hdr_candidate->Name << " is valid!" << std::endl;
	return true;
}

size_t count_section_hdrs(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	size_t counter = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		curr_sec++;
		counter++;
	} while (true);

	return counter;
}

//calculate image size basing on the sizes of sections
DWORD calc_image_size(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	DWORD max_addr = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		DWORD sec_max = curr_sec->VirtualAddress + curr_sec->Misc.VirtualSize;
		max_addr = (sec_max > max_addr) ? sec_max : max_addr;
		curr_sec++;
	} while (true);

	return max_addr;
}

IMAGE_SECTION_HEADER* get_first_section(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	IMAGE_SECTION_HEADER* prev_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*) prev_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		hdr_ptr = prev_sec;
		prev_sec--;
	} while (true);

	return hdr_ptr;
}

IMAGE_SECTION_HEADER* MemPageScanner::findSectionsHdr(MemPageData &memPage)
{
	if (memPage.loadedData == nullptr) {
		if (!memPage.loadRemote()) return nullptr;
		if (memPage.loadedData == nullptr) return nullptr;
	}
	size_t scan_size = memPage.loadedSize;
	BYTE* buffer_ptr = memPage.loadedData;
	
	//find sections table
	char sec_name[] = ".text";
	BYTE *hdr_ptr = find_pattern(memPage.loadedData, memPage.loadedSize, (BYTE*)sec_name, strlen(sec_name));
	if (!hdr_ptr) {
		return nullptr;
	}
	DWORD charact = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	if (!is_valid_section(memPage.loadedData, memPage.loadedSize, hdr_ptr, charact)) {
		return nullptr;
	}
	// is it really the first section?
	IMAGE_SECTION_HEADER *first_sec = get_first_section(memPage.loadedData, memPage.loadedSize, (IMAGE_SECTION_HEADER*) hdr_ptr);
	return (IMAGE_SECTION_HEADER*)first_sec;
}

MemPageScanReport* MemPageScanner::scanShellcode(MemPageData &memPageData)
{
	if (memPage.loadedData == nullptr) {
		return nullptr;
	}

	BYTE prolog32_pattern[] = { 0x55, 0x8b, 0xEC };
	BYTE prolog64_pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20 };

	size_t prolog32_size = sizeof(prolog32_pattern);
	size_t prolog64_size = sizeof(prolog64_pattern);
	bool is32bit = false;

	BYTE* buffer = memPageData.loadedData;

	bool pattern_found = false;
	for (size_t i = 0; (i + prolog64_size) < memPageData.loadedSize; i++) {
		if (memcmp(buffer + i, prolog32_pattern, prolog32_size) == 0) {
			pattern_found = true;
			is32bit = true;
#ifdef _DEBUG
			std::cout << std::hex << memPage.region_start << ": contains 32bit shellcode"  << std::endl;
#endif
			break;
		}
		if (memcmp(buffer + i, prolog64_pattern, prolog64_size) == 0) {
			pattern_found = true;
#ifdef _DEBUG
			std::cout << std::hex << memPage.region_start << " : contains 64bit shellcode" << std::hex << memPage.region_start << std::endl;
#endif
			break;
		}
	}
	if (pattern_found == false) {
		return nullptr;
	}

	bool is_damaged_pe = false;
	// it may still contain a damaged PE header...
	ULONGLONG sec_hdr_va = 0;
	size_t sec_count = 0;
	DWORD calculated_img_size = 0;
	IMAGE_SECTION_HEADER* sec_hdr = findSectionsHdr(memPage);
	if (sec_hdr) {
		std::cout << "The detected shellcode is probably a corrupt PE" << std::endl;
		is_damaged_pe = true;
		sec_count = count_section_hdrs(memPage.loadedData, memPage.loadedSize, sec_hdr);
		calculated_img_size = calc_image_size(memPage.loadedData, memPage.loadedSize, sec_hdr);
		sec_hdr_va = ((ULONGLONG)sec_hdr - (ULONGLONG)memPage.loadedData) + memPage.region_start;
	}

	ULONGLONG region_start = memPage.region_start;
	// check a mempage before the current one:
	if (memPage.region_start > memPage.alloc_base) {
		MemPageData prevMemPage(this->processHandle, memPage.alloc_base);
		sec_hdr = findSectionsHdr(prevMemPage);
		if (sec_hdr) {
			std::cout << "The detected shellcode is probably a corrupt PE" << std::endl;
			is_damaged_pe = true;
			region_start = prevMemPage.region_start;
			sec_count = count_section_hdrs(prevMemPage.loadedData, prevMemPage.loadedSize, sec_hdr);
			calculated_img_size = calc_image_size(prevMemPage.loadedData, prevMemPage.loadedSize, sec_hdr);
			sec_hdr_va = ((ULONGLONG)sec_hdr - (ULONGLONG)prevMemPage.loadedData) + prevMemPage.region_start;
		}
	}

	//TODO: differentiate the raport: shellcode vs PE
	const size_t region_size = size_t (memPage.region_end - region_start);
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->is_executable = true;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	my_report->is_shellcode = true;
	if (is_damaged_pe) {
		if (calculated_img_size > region_size) {
			my_report->moduleSize = calculated_img_size;
		}
		my_report->sections_count = sec_count;
		my_report->hdr_candidate = sec_hdr_va;
	}
	return my_report;
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
		// the header is not executable + the module was already listed - > probably not interesting
#ifdef _DEBUG
		std::cout << std::hex << memPage.start_va << " : Aleady listed" << std::endl;
#endif
		return nullptr;
	}
	ULONGLONG pe_header = findPeHeader(memPage);
	if (pe_header == PE_NOT_FOUND) {
		if (!this->detectShellcode) {
			// not a PE file, and we are not interested in checking for shellcode, so just finish it here
			return nullptr;
		}
		if (is_any_exec && (memPage.mapping_type == MEM_PRIVATE ||
			(memPage.mapping_type == MEM_MAPPED && !memPage.isRealMapping())))
		{
#ifdef _DEBUG
			std::cout << std::hex << memPage.start_va << " : Checking for shellcode" << std::endl;
#endif
			return this->scanShellcode(memPage);
		}
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
	std::cout << "[" << std::hex << memPage.start_va << "] Found a PE in the working set. Status: " << status << std::endl;
#endif
	const size_t pe_size = remoteModule.getModuleSize();
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)pe_header, pe_size, status);
	my_report->is_executable = is_executable;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
