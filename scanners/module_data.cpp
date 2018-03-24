#include "module_data.h"

#include "../utils/util.h"
#include "../utils/path_converter.h"

//---
bool ModuleData::convertPath()
{
	std::string my_path =  convert_to_win32_path(this->szModName);
	if (my_path.length() == 0) {
		return false;
	}
	// store the new path in the buffer:
	memset(this->szModName, 0, MAX_PATH);

	// store the new path in the buffer:
	size_t max_len = my_path.length();
	if (max_len > MAX_PATH) max_len = MAX_PATH;

	memcpy(this->szModName, my_path.c_str(), max_len);
	return true;
}

bool ModuleData::loadOriginal()
{
	is_relocated = false;
	if (!GetModuleFileNameExA(processHandle, this->moduleHandle, szModName, MAX_PATH)) {
		is_module_named = false;
		const char unnamed[] = "unnamed";
		memcpy(szModName, unnamed, sizeof(unnamed));
	}
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (original_module != nullptr) {
		this->is_dot_net = isDotNetManagedCode();
		return true;
	}
	// try to convert path:
	if (!convertPath()) {
		return false;
	}
	std::cout << "[OK] Converted the path: " << szModName << std::endl;
	
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	this->is_dot_net = isDotNetManagedCode();
	return true;
}

bool ModuleData::relocateToBase()
{
	if (!original_module) return false;
	if (is_relocated) return true;

	ULONGLONG original_base = peconv::get_image_base(original_module);
	ULONGLONG new_base = (ULONGLONG) moduleHandle;
	if (peconv::has_relocations(original_module) 
		&& !peconv::relocate_module(original_module, original_size, new_base, original_base))
	{
#ifdef _DEBUG
		std::cerr << "[!] Relocating module failed!" << std::endl;
#endif
		return false;
	}
	return true;
}

bool ModuleData::reloadWow64()
{
	bool is_converted = convert_to_wow64_path(szModName);
	if (!is_converted) return false;

	//reload it and check again...
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}


bool ModuleData::isDotNetManagedCode()
{
	//has a directory entry for .NET header
	IMAGE_DATA_DIRECTORY* dotNetDir = peconv::get_directory_entry(this->original_module, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	if (dotNetDir == nullptr) {
		//does not have .NET directory
		return false;
	}
	
	if (!peconv::get_dotnet_hdr(this->original_module, this->original_size, dotNetDir)){
		return false;
	}
#ifdef _DEBUG
	std::cout << "This is a .NET module" << std::endl;
#endif
	return true;
}

//----
bool RemoteModuleData::init()
{
	this->is_ready = false;
	if (!loadHeader()) {
		return false;
	}
	this->is_ready = true;
	return true;
}

bool RemoteModuleData::loadHeader()
{
	SIZE_T read_size = 0;
	if (!peconv::read_remote_pe_header(this->processHandle, (PBYTE)this->modBaseAddr, this->headerBuffer, peconv::MAX_HEADER_SIZE)) {
		return false;
	}
	return true;
}

ULONGLONG RemoteModuleData::getRemoteSectionVa(const size_t section_num)
{
	if (!this->isInitialized()) return NULL;

	PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(headerBuffer, peconv::MAX_HEADER_SIZE, section_num);
	if ((section_hdr == NULL) || section_hdr->SizeOfRawData == 0) {
		return NULL;
	}
	return (ULONGLONG) modBaseAddr + section_hdr->VirtualAddress;
}

bool RemoteModuleData::isSectionExecutable(size_t section_number)
{
	//for special cases when the section is not set executable in headers, but in reality is executable...
	//get the section header from the module:
	ULONGLONG start_va = getRemoteSectionVa(section_number);
	if (start_va == NULL) {
		return false;
	}
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID) start_va, &page_info, sizeof(page_info));
	if (out != sizeof(page_info)) {
#ifdef _DEBUG
		std::cerr << "Cannot retrieve remote section info" << std::endl;
#endif
		return false;
	}
	DWORD protection = page_info.Protect;
	bool is_any_exec = (protection & PAGE_EXECUTE_READWRITE)|| (protection & PAGE_EXECUTE_READ);
	return is_any_exec;
}

bool RemoteModuleData::hasExecutableSection()
{
	size_t sec_count = peconv::get_sections_count(this->headerBuffer, peconv::MAX_HEADER_SIZE);
	for (size_t i = 0; i < sec_count ; i++) {
		if (isSectionExecutable(i)) {
			return true;
		}
	}
	return false;
}
