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

size_t CodeScanReport::generateTags(std::string reportPath)
{
	if (patchesList.size() == 0) {
		return 0;
	}
	std::ofstream patch_report;
	patch_report.open(reportPath);
	if (patch_report.is_open() == false) {
		return 0;
	}
	size_t patches = patchesList.reportPatches(patch_report, ';');
	if (patch_report.is_open()) {
		patch_report.close();
	}
	return patches;
}

//---

bool HookScanner::clearIAT(ModuleData& modData, PeSection &originalSec, PeSection &remoteSec)
{
	IMAGE_DATA_DIRECTORY* iat_dir = peconv::get_directory_entry(modData.original_module, IMAGE_DIRECTORY_ENTRY_IAT);
	if (!iat_dir) {
		return false;
	}
	DWORD iat_rva = iat_dir->VirtualAddress;
	DWORD iat_size = iat_dir->Size;

	if (originalSec.isContained(iat_rva, iat_size))
	{
#ifdef _DEBUG
		std::cout << "IAT is in Code section!" << std::endl;
#endif
		DWORD offset = iat_rva - originalSec.rva;
		memset(originalSec.loadedSection + offset, 0, iat_size);
		memset(remoteSec.loadedSection + offset, 0, iat_size);
	}
	return true;
}

size_t HookScanner::collectPatches(DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, PatchList &patchesList)
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
			currPatch = new PatchList::Patch(patchesList.size(), (DWORD) rva + i);
			patchesList.insert(currPatch);
		}
	}
	// if there is still unclosed patch, close it now:
	if (currPatch != nullptr) {
		//this happens if the patch lasts till the end of code, so, its end is the end of code
		currPatch->setEnd(rva + (DWORD) code_size);
		currPatch = nullptr;
	}
	return patchesList.size();
}

t_scan_status HookScanner::scanSection(ModuleData& modData, RemoteModuleData &remoteModData, size_t section_number, CodeScanReport& report)
{
	//get the code section from the remote module:
	PeSection remoteSec(remoteModData, section_number);
	if (!remoteSec.isInitialized()) {
		return SCAN_ERROR;
	}

	PeSection originalSec(modData, section_number);
	if (!originalSec.isInitialized()) {
		return SCAN_ERROR;
	}

	clearIAT(modData, originalSec, remoteSec);
		
	size_t smaller_size = originalSec.loadedSize > remoteSec.loadedSize ? remoteSec.loadedSize : originalSec.loadedSize;
#ifdef _DEBUG
	std::cout << "Code RVA: " 
		<< std::hex << section_hdr->VirtualAddress 
		<< " to "
		<< std::hex << section_hdr->SizeOfRawData 
		<< std::endl;
#endif
	//check if the code of the loaded module is same as the code of the module on the disk:
	int res = memcmp(remoteSec.loadedSection, originalSec.loadedSection, smaller_size);
	if (res != 0) {
		size_t patches_count = collectPatches(originalSec.rva, originalSec.loadedSection, remoteSec.loadedSection, smaller_size, report.patchesList);
#ifdef _DEBUG
		if (patches_count) {
			std::cout << "Total patches: "  << patches_count << std::endl;
		}
#endif
	}
	if (res != 0) {
		return SCAN_SUSPICIOUS; // modified
	}
	return SCAN_NOT_SUSPICIOUS; //not modified
}

CodeScanReport* HookScanner::scanRemote(ModuleData& modData, RemoteModuleData &remoteModData)
{
	CodeScanReport *my_report = new CodeScanReport(this->processHandle, modData.moduleHandle);

	ULONGLONG original_base = peconv::get_image_base(modData.original_module);
	ULONGLONG new_base = (ULONGLONG) modData.moduleHandle;
	if (peconv::has_relocations(modData.original_module) 
		&& !peconv::relocate_module(modData.original_module, modData.original_size, new_base, original_base))
	{
		std::cerr << "[!] Relocating module failed!" << std::endl;
	}

	t_scan_status last_res = SCAN_NOT_SUSPICIOUS;
	size_t errors = 0;
	size_t modified = 0;
	size_t sec_count = peconv::get_sections_count(modData.original_module, modData.original_size);
	for (size_t i = 0; i < sec_count ; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modData.original_module, modData.original_size, i);
		if (section_hdr == nullptr) continue;
		if ( (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			||( (i == 0) && remoteModData.isSectionExecutable(i)) ) // for now do it only for the first section
			//TODO: handle sections that have inside Delayed Imports (they give false positives)
		{
			last_res = scanSection(modData, remoteModData, i, *my_report);
			if (last_res == SCAN_ERROR) errors++;
			else if (last_res == SCAN_SUSPICIOUS) modified++;
		}
	}
	if (modified > 0) {
		my_report->status = SCAN_SUSPICIOUS; //the highest priority for modified
	} else if (errors > 0) {
		my_report->status = SCAN_ERROR;
	} else {
		my_report->status = last_res;
	}
	return my_report; // last result
}
