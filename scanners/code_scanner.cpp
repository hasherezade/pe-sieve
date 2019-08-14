#include "code_scanner.h"

#include <peconv.h>

#include "patch_analyzer.h"
#include "../utils/artefacts_util.h"
//---
#include <iostream>

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

bool CodeScanner::clearIAT(PeSection &originalSec, PeSection &remoteSec)
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

bool CodeScanner::clearLoadConfig(PeSection &originalSec, PeSection &remoteSec)
{
	// check if the Guard flag is enabled:
	WORD charact = peconv::get_dll_characteristics(moduleData.original_module);
	if ((charact & 0x4000) == 0) {
		return false; //no guard flag
	}
	BYTE *ldconf_ptr = peconv::get_load_config_ptr(moduleData.original_module, moduleData.original_size);
	if (!ldconf_ptr) return false;

	peconv::t_load_config_ver ver = peconv::get_load_config_version(moduleData.original_module, moduleData.original_size, ldconf_ptr);
	if (ver != peconv::LOAD_CONFIG_W8_VER && ver != peconv::LOAD_CONFIG_W10_VER) {
		return false; // nothing to cleanup
	}
	ULONGLONG cflag_va = 0;
	size_t field_size = 0;
	if (this->moduleData.is64bit()) {
		peconv::IMAGE_LOAD_CONFIG_DIR64_W8* ldc = (peconv::IMAGE_LOAD_CONFIG_DIR64_W8*) ldconf_ptr;
		cflag_va = ldc->GuardCFCheckFunctionPointer;
		field_size = sizeof(ULONGLONG);
	}
	else {
		peconv::IMAGE_LOAD_CONFIG_DIR32_W8* ldc = (peconv::IMAGE_LOAD_CONFIG_DIR32_W8*) ldconf_ptr;
		cflag_va = ldc->GuardCFCheckFunctionPointer;
		field_size = sizeof(DWORD);
	}
	if (cflag_va == 0) return false;

	const ULONGLONG module_base = (ULONG_PTR)moduleData.moduleHandle;
	const ULONGLONG cflag_rva = cflag_va - module_base;
	if (!originalSec.isContained(cflag_rva, field_size)) {
		return false;
	}
	//clear the field:
	size_t sec_offset = size_t(cflag_rva - originalSec.rva);
	memset(originalSec.loadedSection + sec_offset, 0, field_size);
	memset(remoteSec.loadedSection + sec_offset, 0, field_size);
	return true;
}

bool CodeScanner::clearExports(PeSection &originalSec, PeSection &remoteSec)
{
	IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(moduleData.original_module, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if (!dir) {
		return false;
	}
	DWORD iat_rva = dir->VirtualAddress;
	DWORD iat_size = dir->Size;

	if (originalSec.isContained(iat_rva, iat_size))
	{
#ifdef _DEBUG
		std::cout << "Exports are  is in Code section!" << std::endl;
#endif
		DWORD offset = iat_rva - originalSec.rva;
		IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY*) ((ULONGLONG)originalSec.loadedSection + offset);
		if (!peconv::validate_ptr(originalSec.loadedSection, originalSec.loadedSize, exports, sizeof(IMAGE_EXPORT_DIRECTORY))) {
			return false;
		}
		DWORD functions_offset = exports->AddressOfFunctions - originalSec.rva;
		DWORD functions_count = exports->NumberOfFunctions;

		const size_t func_area_size = functions_count * sizeof(DWORD);
		if (!peconv::validate_ptr(originalSec.loadedSection, originalSec.loadedSize, 
			originalSec.loadedSection + functions_offset, 
			func_area_size))
		{
			return false;
		}
		memset(originalSec.loadedSection + functions_offset, 0, func_area_size);
		memset(remoteSec.loadedSection + functions_offset, 0, func_area_size);
	}
	return true;
}

size_t CodeScanner::collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList)
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
			currPatch = new PatchList::Patch(moduleData.moduleHandle, patchesList.size(), (DWORD) section_rva + i);
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

t_scan_status CodeScanner::scanSection(PeSection &originalSec, PeSection &remoteSec, IN OUT CodeScanReport& report)
{
	if (!originalSec.isInitialized() || !remoteSec.isInitialized()) {
		return SCAN_ERROR;
	}
	clearIAT(originalSec, remoteSec);
	clearExports(originalSec, remoteSec);
	clearLoadConfig(originalSec, remoteSec);
	//TODO: handle sections that have inside Delayed Imports (they give false positives)

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
	if (res == 0) {
		return SCAN_NOT_SUSPICIOUS; //not modified
	}

	if (originalSec.rawSize == 0) {
		report.unpackedSections.insert(originalSec.rva);
	}
	else {
		collectPatches(originalSec.rva, originalSec.loadedSection, remoteSec.loadedSection, smaller_size, report.patchesList);
	}
	return SCAN_SUSPICIOUS; // modified

}


CodeScanReport* CodeScanner::scanRemote()
{
	CodeScanReport *my_report = new CodeScanReport(this->processHandle, moduleData.moduleHandle, moduleData.original_size);
	my_report->isDotNetModule = moduleData.isDotNet();
	moduleData.relocateToBase(); // before scanning, ensure that the original module is relocated to the base where it was loaded

	t_scan_status last_res = SCAN_NOT_SUSPICIOUS;
	size_t errors = 0;
	size_t modified = 0;
	size_t sec_count = peconv::get_sections_count(moduleData.original_module, moduleData.original_size);
	for (size_t i = 0; i < sec_count ; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(moduleData.original_module, moduleData.original_size, i);
		if (section_hdr == nullptr) continue;

		if (!(section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !remoteModData.isSectionExecutable(i))
		{
			//not executable, skip it
			continue;
		}

		//get the code section from the remote module:
		PeSection remoteSec(remoteModData, i);
		if (!remoteSec.isInitialized()) {
			continue;
		}
		if ( i == 0 // always scan first section
			|| is_code(remoteSec.loadedSection, remoteSec.loadedSize))
		{
			//std::cout << "Scanning executable section: " << i << std::endl;
			PeSection originalSec(moduleData, i);
			last_res = scanSection(originalSec, remoteSec, *my_report);
			if (last_res == SCAN_ERROR) errors++;
			else if (last_res == SCAN_SUSPICIOUS) modified++;
		}
	}

	//post-process collected patches:
	postProcessScan(*my_report);

	if (modified > 0) {
		my_report->status = SCAN_SUSPICIOUS; //the highest priority for modified
	} else if (errors > 0) {
		my_report->status = SCAN_ERROR;
	} else {
		my_report->status = last_res;
	}
	return my_report; // last result
}

bool CodeScanner::postProcessScan(IN OUT CodeScanReport &report)
{
	// we need only exports from the current module, not the global mapping
	if (report.patchesList.size() == 0) {
		return false;
	}
	peconv::ExportsMapper local_mapper;
	local_mapper.add_to_lookup(moduleData.szModName, (HMODULE) moduleData.original_module, (ULONGLONG) moduleData.moduleHandle);
	report.patchesList.checkForHookedExports(local_mapper);
	return true;
}
