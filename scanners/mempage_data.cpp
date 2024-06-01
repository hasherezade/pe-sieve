#include "mempage_data.h"
#include "module_data.h"
#include "../utils/process_util.h"

using namespace pesieve;

bool pesieve::MemPageData::fillInfo()
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
	is_info_filled = true;
	return true;
}

bool pesieve::MemPageData::loadModuleName()
{
	const HMODULE mod_base = (HMODULE)this->alloc_base;
	std::string module_name = RemoteModuleData::getModuleName(processHandle, mod_base);
	if (module_name.length() == 0) {
#ifdef _DEBUG
		std::cerr << "Could not retrieve the module name. Base: " << std::hex << mod_base << std::endl;
#endif
		return false;
	}
	this->module_name = module_name;
	return true;
}

bool pesieve::MemPageData::loadMappedName()
{
	if (!isInfoFilled() && !fillInfo()) {
		return false;
	}
	std::string mapped_filename = RemoteModuleData::getMappedName(this->processHandle, (HMODULE)this->alloc_base);
	if (mapped_filename.length() == 0) {
#ifdef _DEBUG
		std::cerr << "Could not retrieve the mapped name. Base: " << std::hex << this->alloc_base << std::endl;
#endif
		return false;
	}
	this->mapped_name = mapped_filename;
	return true;
}

bool pesieve::MemPageData::isRealMapping()
{
	if (!loadMappedName()) {
#ifdef _DEBUG
		std::cerr << "Could not retrieve name" << std::endl;
#endif
		return false;
	}
	PVOID old_val = nullptr;
	util::wow64_disable_fs_redirection(&old_val);
	HANDLE file = CreateFileA(this->mapped_name.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	util::wow64_revert_fs_redirection(old_val);
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
		std::cerr << "Could not map view of file: " << this->mapped_name << std::endl;
#endif
		CloseHandle(mapping);
		CloseHandle(file);
		return false;
	}

	bool is_same = false;
	if (this->load()) {
		size_t r_size = GetFileSize(file, 0);
		is_same = this->loadedData.isDataContained(rawData, r_size);
	}
	else {
#ifdef _DEBUG
		std::cerr << "[" << std::hex << start_va << "] Page not loaded!" << std::endl;
#endif
	}
	UnmapViewOfFile(rawData);
	CloseHandle(mapping);
	CloseHandle(file);
	return is_same;
}

bool pesieve::MemPageData::_loadRemote()
{
	_freeRemote();
	size_t region_size = size_t(this->region_end - this->start_va);
	if (stop_va && ( stop_va >= start_va  && stop_va < this->region_end)) {
		region_size = size_t(this->stop_va - this->start_va);
	}
	
	if (region_size == 0) {
		return false;
	}
	if (!loadedData.allocBuffer(region_size)) {
		return false;
	}
	const bool can_force_access = is_process_refl ? true : false;
	const size_t size_read = peconv::read_remote_region(this->processHandle, (BYTE*)this->start_va, loadedData.data, loadedData.getDataSize(), can_force_access);
	if (size_read == 0) {
		_freeRemote();
#ifdef _DEBUG
		std::cerr << "Cannot read remote memory!" << std::endl;
#endif
		return false;
	}
	loadedData.trim();
	return true;
}

