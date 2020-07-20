#include "module_data.h"

#include "../utils/format_util.h"
#include "../utils/path_converter.h"
#include "../utils/process_util.h"
#include "../utils/artefacts_util.h"
#include "artefact_scanner.h"

#include <psapi.h>
#pragma comment(lib,"psapi.lib")

using namespace pesieve::util;

//---
bool pesieve::ModuleData::loadModuleName()
{
	std::string my_name = pesieve::RemoteModuleData::getModuleName(processHandle, this->moduleHandle);
	if (my_name.length() == 0 || my_name.length() > MAX_PATH) {
		//invalid length
		return false;
	}
	memcpy(this->szModName, my_name.c_str(), my_name.length());
	return true;
}

bool pesieve::ModuleData::loadOriginal()
{
	//disable FS redirection by default
	if (_loadOriginal(true)) {
		return true;
	}
	//if loading with FS redirection has failed, try without
	return _loadOriginal(false);
}

bool pesieve::ModuleData::_loadOriginal(bool disableFSredir)
{
	if (strlen(this->szModName) == 0) {
		loadModuleName();
	}
	//just in case if something was loaded before...
	peconv::free_pe_buffer(original_module, original_size);

	BOOL isRedirDisabled = FALSE;
	PVOID old_val;
	if (disableFSredir) {
		isRedirDisabled = wow64_disable_fs_redirection(&old_val);
#ifdef _DEBUG
		std::cout << "[+] Loadeding file by disabling FS redirection:" << szModName << "\n";
#endif
	}
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (isRedirDisabled) {
		wow64_revert_fs_redirection(old_val);
	}
	if (!original_module) {
		return false;
	}
	this->is_dot_net = isDotNetManagedCode();
	return true;
}

bool pesieve::ModuleData::relocateToBase(ULONGLONG new_base)
{
	if (!original_module) return false;

	ULONGLONG original_base = peconv::get_image_base(original_module);
	if (original_base == new_base) {
		return true; // already relocated
	}
	if (peconv::has_relocations(original_module) 
		&& !peconv::relocate_module(original_module, original_size, new_base, original_base))
	{
#ifdef _DEBUG
		std::cerr << "[!] Relocating module failed!" << std::endl;
#endif
		return false;
	}
	peconv::update_image_base(original_module, new_base);
	return true;
}

bool pesieve::ModuleData::switchToWow64Path()
{
	BOOL isWow64 = FALSE;
	if (!is_process_wow64(this->processHandle, &isWow64)) {
		//failed to retrieve the info...
		return false;
	}
	if (isWow64) {
		if (pesieve::util::convert_to_wow64_path(szModName)) return true;
	}
	return false;
}

bool pesieve::ModuleData::reloadWow64()
{
	if (!switchToWow64Path()) return false;

	//reload it and check again...
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}

bool pesieve::ModuleData::isDotNetManagedCode()
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

std::string pesieve::RemoteModuleData::getModuleName(HANDLE processHandle, HMODULE modBaseAddr)
{
	char filename[MAX_PATH] = { 0 };
	if (!GetModuleFileNameExA(processHandle, modBaseAddr, filename, MAX_PATH)) {
		return "";
	}
	std::string basic_filename = pesieve::util::convert_to_win32_path(filename);
	std::string expanded = pesieve::util::expand_path(basic_filename);
	if (expanded.length() == 0) {
		return filename;
	}
	return expanded;
}

std::string pesieve::RemoteModuleData::getMappedName(HANDLE processHandle, LPVOID modBaseAddr)
{
	char filename[MAX_PATH] = { 0 };
	if (!GetMappedFileNameA(processHandle, modBaseAddr, filename, MAX_PATH) != 0) {
		return "";
	}
	std::string expanded = pesieve::util::expand_path(filename);
	if (expanded.length() == 0) {
		return filename;
	}
	return expanded;
}

bool pesieve::RemoteModuleData::init()
{
	this->isHdrReady = false;
	if (!loadHeader()) {
		return false;
	}
	this->isHdrReady = true;
	return true;
}

bool pesieve::RemoteModuleData::_loadFullImage(size_t mod_size)
{
	if (this->isFullImageLoaded()) {
		return true;
	}
	this->imgBuffer = peconv::alloc_pe_buffer(mod_size, PAGE_READWRITE);
	this->imgBufferSize = peconv::read_remote_pe(this->processHandle, (PBYTE)this->modBaseAddr, mod_size, this->imgBuffer, mod_size);
	if (this->imgBufferSize == mod_size) {
		return true;
	}
	this->freeFullImage();
	return false;
}

bool pesieve::RemoteModuleData::loadFullImage()
{
	if (this->isFullImageLoaded()) {
		return true;
	}
	size_t mod_size = this->getHdrImageSize();
	if (_loadFullImage(mod_size)) {
		return true;
	}
	//try again with calculated size:
	mod_size = calcImgSize();
	return _loadFullImage(mod_size);
}

bool pesieve::RemoteModuleData::loadHeader()
{
	if (!peconv::read_remote_pe_header(this->processHandle, (PBYTE)this->modBaseAddr, this->headerBuffer, peconv::MAX_HEADER_SIZE)) {
		return false;
	}
	return true;
}

ULONGLONG pesieve::RemoteModuleData::getRemoteSectionVa(const size_t section_num)
{
	if (!this->isInitialized()) return NULL;

	PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(headerBuffer, peconv::MAX_HEADER_SIZE, section_num);
	if ((section_hdr == NULL) || section_hdr->SizeOfRawData == 0) {
		return NULL;
	}
	return (ULONGLONG) modBaseAddr + section_hdr->VirtualAddress;
}

bool pesieve::RemoteModuleData::isSectionEntry(const size_t section_number)
{
	if (!this->isInitialized()) {
		return false;
	}
	const DWORD ep_va = peconv::get_entry_point_rva(this->headerBuffer);
	if (ep_va == 0) {
		return false;
	}
	PIMAGE_SECTION_HEADER sec_hdr = peconv::get_section_hdr(this->headerBuffer, peconv::MAX_HEADER_SIZE, section_number);
	if (!sec_hdr) {
		return false;
	}
	if (ep_va >= sec_hdr->VirtualAddress && ep_va < sec_hdr->Misc.VirtualSize) {
		return true;
	}
	return false;
}

bool pesieve::RemoteModuleData::isSectionExecutable(const size_t section_number)
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
#ifdef _DEBUG
	std::cout << std::hex << "Sec: " << section_number << " VA: " << start_va << " t: " << page_info.Type << " p: " << page_info.Protect << std::endl;
#endif

	if (pesieve::util::is_executable(page_info.Type, page_info.Protect)) {
		//std::cout << std::hex << "p1 Sec: " << section_number << " VA: " << start_va << " t: " << page_info.Type << " p: " << page_info.Protect << std::endl;
		return true;
	}
	return false;
}

bool pesieve::RemoteModuleData::hasExecutableSection()
{
	size_t sec_count = peconv::get_sections_count(this->headerBuffer, peconv::MAX_HEADER_SIZE);
	for (size_t i = 0; i < sec_count ; i++) {
		if (isSectionExecutable(i)) {
			return true;
		}
	}
	return false;
}

//calculate image size basing on the sizes of sections
size_t pesieve::RemoteModuleData::calcImgSize()
{
	if (!isHdrReady) return 0;

	return ArtefactScanner::calcImgSize(this->processHandle, this->modBaseAddr, this->headerBuffer, peconv::MAX_HEADER_SIZE);
}
