#include "hook_scanner.h"

#include <fstream>

#include "peconv.h"

bool PatchList::Patch::reportPatch(std::ofstream &patch_report, const char delimiter)
{
	if (patch_report.is_open()) {
		patch_report << std::hex << startRva;
		patch_report << delimiter;
		patch_report << "patch_" << id;
		patch_report << delimiter;
		patch_report << (endRva - startRva);
		patch_report << std::endl;
	} else {
		std::cout << std::hex << startRva << std::endl;
	}
	return true;
}

//---
size_t PatchList::reportPatches(std::ofstream &patch_report, const char delimiter)
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); itr++) {
		Patch *patch = *itr;
		patch->reportPatch(patch_report, delimiter);
	}
	return patches.size();
}

void PatchList::deletePatches()
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); itr++) {
		Patch *patch = *itr;
		delete patch;
	}
	this->patches.clear();
}

//---

bool HookScanner::clearIAT(PIMAGE_SECTION_HEADER section_hdr, PBYTE original_module, BYTE* loaded_code)
{
	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
	IMAGE_DATA_DIRECTORY* iat_dir = peconv::get_directory_entry(original_module, IMAGE_DIRECTORY_ENTRY_IAT);
	if (!iat_dir) {
		return false;
	}
	DWORD iat_rva = iat_dir->VirtualAddress;
	DWORD iat_size = iat_dir->Size;
	DWORD iat_end = iat_rva + iat_size;

	if (
		(iat_rva >= section_hdr->VirtualAddress && (iat_rva < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
		|| (iat_end >= section_hdr->VirtualAddress && (iat_end < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
	)
	{
#ifdef _DEBUG
		std::cout << "IAT is in Code section!" << std::endl;
#endif
		DWORD offset = iat_rva - section_hdr->VirtualAddress;
		memset(orig_code + offset, 0, iat_size);
		memset(loaded_code + offset, 0, iat_size);
	}
	return true;
}

size_t HookScanner::collectPatches(DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size)
{
	PatchList::Patch *currPatch = nullptr;

	for (DWORD i = 0; i < (DWORD) code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			if (currPatch != nullptr) {
				// close the patch
				currPatch->setEnd(rva + i);
				currPatch = nullptr;
			}
			continue;
		}
		if (currPatch == nullptr) {
			//open a new patch
			currPatch = new PatchList::Patch(this->patchesList.size(), (DWORD) rva + i);
			this->patchesList.insert(currPatch);
		}
	}
	return this->patchesList.size();
}

t_scan_status HookScanner::scanSection(PBYTE modBaseAddr, PBYTE original_module, size_t module_size, size_t section_number)
{
	//get the code section from the module:
	size_t read_size = 0;
	BYTE *loaded_code = peconv::get_remote_pe_section(processHandle, modBaseAddr, section_number, read_size);
	if (loaded_code == nullptr) return SCAN_ERROR;

	PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(original_module, module_size, section_number);
	if (section_hdr == nullptr) return SCAN_ERROR;

	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
	
	//TODO: this should be done on the section's copy...
	clearIAT(section_hdr, original_module, loaded_code);
		
	size_t smaller_size = section_hdr->SizeOfRawData > read_size ? read_size : section_hdr->SizeOfRawData;
#ifdef _DEBUG
	std::cout << "Code RVA: " 
		<< std::hex << section_hdr->VirtualAddress 
		<< " to "
		<< std::hex << section_hdr->SizeOfRawData 
		<< std::endl;
#endif
	//check if the code of the loaded module is same as the code of the module on the disk:
	int res = memcmp(loaded_code, orig_code, smaller_size);
	if (res != 0) {
		size_t patches_count = collectPatches(section_hdr->VirtualAddress, orig_code, loaded_code, smaller_size);
		if (patches_count) {
			std::cout << "Total patches: "  << patches_count << std::endl;
		}
	}
	peconv::free_remote_pe_section(loaded_code);
	loaded_code = NULL;
	if (res != 0) {
		return SCAN_MODIFIED; // modified
	}
	return SCAN_NOT_MODIFIED; //not modified
}

t_scan_status HookScanner::scanRemote(PBYTE modBaseAddr, PBYTE original_module, size_t module_size)
{
	ULONGLONG original_base = peconv::get_image_base(original_module);
	ULONGLONG new_base = (ULONGLONG) modBaseAddr;
	if (peconv::has_relocations(original_module) 
		&& !peconv::relocate_module(original_module, module_size, new_base, original_base))
	{
		std::cerr << "[!] Relocating module failed!" << std::endl;
	}

	t_scan_status last_res = SCAN_NOT_MODIFIED;
	size_t errors = 0;
	size_t modified = 0;
	size_t sec_count = peconv::get_sections_count(original_module, module_size);
	for (size_t i = 0; i < sec_count ; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(original_module, module_size, i);
		if (section_hdr == nullptr) continue;
		if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			last_res = scanSection(modBaseAddr, original_module, module_size, i);
			if (last_res == SCAN_ERROR) errors++;
			else if (last_res == SCAN_MODIFIED) modified++;
		}
	}
	if (modified > 0) return SCAN_MODIFIED; //the highest priority for modified
	if (errors > 0) return SCAN_ERROR;
	return last_res; // last result
}
