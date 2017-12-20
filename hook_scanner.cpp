#include "hook_scanner.h"

#include <fstream>

#include "peconv.h"
using namespace peconv;

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

bool HookScanner::reportPatch(std::ofstream &patch_report, Patch &patch)
{
	if (patch_report.is_open()) {
		patch_report << std::hex << patch.startRva;
		patch_report << HookScanner::delimiter;
		patch_report << "patch_" << patch.id;
		patch_report << HookScanner::delimiter;
		patch_report << (patch.endRva - patch.startRva);
		patch_report << std::endl;
	} else {
		std::cout << std::hex << patch.startRva << std::endl;
	}
	return true;
}

std::vector<HookScanner::Patch*> HookScanner::listPatches(DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size)
{
	std::vector<Patch*> patches_list;
	Patch *currPatch = nullptr;

	for (DWORD i = 0; i < code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			if (currPatch != nullptr) {
				// close the patch
				currPatch->endRva = rva + i;
				currPatch = nullptr;
			}
			continue;
		}
		if (currPatch == nullptr) {
			//open a new patch
			currPatch = new Patch(patches_list.size(), rva + i);
			patches_list.push_back(currPatch);
		}
	}
	return patches_list;
}

size_t HookScanner::reportPatches(const std::string file_name, DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size)
{
	std::vector<Patch*> patches_list = this->listPatches(rva, orig_code, patched_code, code_size);

	std::ofstream patch_report;
	patch_report.open(file_name);
	if (patch_report.is_open() == false) {
		std::cout << "[-] Could not open the file: "<<  file_name << std::endl;
	}
	
	std::vector<Patch*>::iterator itr;
	for (itr = patches_list.begin(); itr != patches_list.end(); itr++) {
		Patch *patch = *itr;
		this->reportPatch(patch_report, *patch);
		delete patch;
	}
	if (patch_report.is_open()) {
		patch_report.close();
	}
	return patches_list.size();
}

t_scan_status HookScanner::scanRemote(PBYTE modBaseAddr, PBYTE original_module, size_t module_size)
{
	//get the code section from the module:
	size_t read_size = 0;
	BYTE *loaded_code = get_remote_pe_section(processHandle, modBaseAddr, 0, read_size);
	if (loaded_code == NULL) return SCAN_ERROR;

	ULONGLONG original_base = get_image_base(original_module);
	ULONGLONG new_base = (ULONGLONG) modBaseAddr;
	if (has_relocations(original_module) && !relocate_module(original_module, module_size, new_base, original_base)) {
		std::cerr << "[!] Relocating module failed!" << std::endl;
	}

	PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(original_module, module_size, 0);
	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
		
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
		std::string mod_name = make_module_path((ULONGLONG)modBaseAddr, directory);
		std::string tagsfile_name = mod_name + ".tag";
		size_t patches_count = reportPatches(tagsfile_name, section_hdr->VirtualAddress, orig_code, loaded_code, smaller_size);
		if (patches_count) {
			std::cout << "Total patches: "  << patches_count << std::endl;
		}
		if (!dump_remote_pe(mod_name.c_str(), processHandle, modBaseAddr, true)) {
			std::cerr << "Failed dumping module!" << std::endl;
		}
	}
	free_remote_pe_section(loaded_code);
	loaded_code = NULL;

	if (res != 0) {
		return SCAN_MODIFIED; // modified
	}
	return SCAN_NOT_MODIFIED; //not modified
}
