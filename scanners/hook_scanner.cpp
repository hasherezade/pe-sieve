#include "hook_scanner.h"

#include "peconv.h"

#include "patch_analyzer.h"
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

bool HookScanner::clearIAT(PeSection &originalSec, PeSection &remoteSec)
{
	IMAGE_DATA_DIRECTORY* iat_dir = peconv::get_directory_entry(moduleData.original_module, IMAGE_DIRECTORY_ENTRY_IAT);
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

size_t HookScanner::collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, PatchList &patchesList)
{
	PatchAnalyzer analyzer(moduleData, section_rva, patched_code, code_size);
	PatchList::Patch *currPatch = nullptr;

	for (DWORD i = 0; i < (DWORD) code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			if (currPatch != nullptr) {
				// close the patch
				currPatch->setEnd(section_rva + i);
				currPatch = nullptr;
			}
			continue;
		}
		if (currPatch == nullptr) {
			//open a new patch
			currPatch = new PatchList::Patch(patchesList.size(), (DWORD) section_rva + i);
			patchesList.insert(currPatch);
			DWORD parsed_size = (DWORD) analyzer.analyze(*currPatch);
			if (parsed_size > 0) {
				currPatch->setEnd(section_rva + i + parsed_size);
				currPatch = nullptr; // close this patch
				i += (parsed_size - 1); //substract 1 because of i++ executed after continue
				continue;
			}
		}
	}
	// if there is still unclosed patch, close it now:
	if (currPatch != nullptr) {
		//this happens if the patch lasts till the end of code, so, its end is the end of code
		currPatch->setEnd(section_rva + (DWORD) code_size);
		currPatch = nullptr;
	}
	return patchesList.size();
}

t_scan_status HookScanner::scanSection(size_t section_number, CodeScanReport& report)
{
	//get the code section from the remote module:
	PeSection remoteSec(remoteModData, section_number);
	if (!remoteSec.isInitialized()) {
		return SCAN_ERROR;
	}

	PeSection originalSec(moduleData, section_number);
	if (!originalSec.isInitialized()) {
		return SCAN_ERROR;
	}

	clearIAT(originalSec, remoteSec);
		
	size_t smaller_size = originalSec.loadedSize > remoteSec.loadedSize ? remoteSec.loadedSize : originalSec.loadedSize;
#ifdef _DEBUG
	std::cout << "Code RVA: " 
		<< std::hex << originalSec.rva
		<< " to "
		<< std::hex << originalSec.loadedSize
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

CodeScanReport* HookScanner::scanRemote()
{
	CodeScanReport *my_report = new CodeScanReport(this->processHandle, moduleData.moduleHandle);

	moduleData.relocateToBase(); // before scanning, ensure that the original module is relocated to the base where it was loaded

	t_scan_status last_res = SCAN_NOT_SUSPICIOUS;
	size_t errors = 0;
	size_t modified = 0;
	size_t sec_count = peconv::get_sections_count(moduleData.original_module, moduleData.original_size);
	for (size_t i = 0; i < sec_count ; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(moduleData.original_module, moduleData.original_size, i);
		if (section_hdr == nullptr) continue;
		if ( (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			||( (i == 0) && remoteModData.isSectionExecutable(i)) ) // for now do it only for the first section
			//TODO: handle sections that have inside Delayed Imports (they give false positives)
		{
			last_res = scanSection(i, *my_report);
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
