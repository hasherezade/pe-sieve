#include "mempage_data.h"
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

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}
