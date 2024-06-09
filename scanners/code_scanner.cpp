#include "code_scanner.h"

#include <peconv.h>

#include "patch_analyzer.h"
#include "../utils/artefacts_util.h"
//---
#include <iostream>

using namespace pesieve;
using namespace pesieve::util;

size_t pesieve::CodeScanReport::generateTags(std::string reportPath)
{
	if (patchesList.size() == 0) {
		return 0;
	}
	std::ofstream patch_report;
	patch_report.open(reportPath);
	if (patch_report.is_open() == false) {
		return 0;
	}
	size_t patches = patchesList.toTAGs(patch_report, ';');
	if (patch_report.is_open()) {
		patch_report.close();
	}
	return patches;
}
//---

bool pesieve::CodeScanner::clearIAT(PeSection &originalSec, PeSection &remoteSec)
{
	// collect IAT fields:
	std::set<DWORD> impThunkRVAs;
	moduleData.loadImportThunks(impThunkRVAs);
	if (impThunkRVAs.size() == 0) {
		return false;
	}

	const size_t thunk_size = moduleData.is64bit() ? sizeof(ULONGLONG) : sizeof(DWORD);
	std::set<DWORD>::iterator itr;
	for (itr = impThunkRVAs.begin(); itr != impThunkRVAs.end(); ++itr) {
		const DWORD iat_field = *itr;
		// clear fields one by one:
		if (originalSec.isContained(iat_field, thunk_size)) {
			const DWORD offset = iat_field - originalSec.rva;
			memset(originalSec.loadedSection + offset, 0, thunk_size);
			memset(remoteSec.loadedSection + offset, 0, thunk_size);
		}
	}
	return true;
}

bool pesieve::CodeScanner::clearLoadConfig(PeSection &originalSec, PeSection &remoteSec)
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

bool pesieve::CodeScanner::clearExports(PeSection &originalSec, PeSection &remoteSec)
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
		std::cout << "Exports are in the Code section!" << std::endl;
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

size_t pesieve::CodeScanner::collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList)
{
	PatchAnalyzer analyzer(moduleData, section_rva, patched_code, code_size);
	PatchList::Patch *currPatch = nullptr;

	for (DWORD i = 0; i < (DWORD) code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			if (currPatch != nullptr) {
				// close the patch
				currPatch->setEnd(section_rva + i);
				analyzer.analyzeOther(*currPatch);
				currPatch = nullptr;
			}
			continue;
		}
		if (currPatch == nullptr) {
			//open a new patch
			currPatch = new(std::nothrow) PatchList::Patch(moduleData.moduleHandle, patchesList.size(), (DWORD) section_rva + i);
			if (!currPatch) continue;
			patchesList.insert(currPatch);
			DWORD parsed_size = (DWORD) analyzer.analyzeHook(*currPatch);
			if (parsed_size > 0) {
				currPatch->setEnd(section_rva + i + parsed_size);
				currPatch = nullptr; // close this patch
				i += (parsed_size - 1); //subtract 1 because of i++ executed after continue
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

namespace pesieve {
	inline BYTE* first_different(const BYTE *buf_ptr, size_t bif_size, const BYTE padding)
	{
		for (size_t i = 0; i < bif_size; i++) {
			if (buf_ptr[i] != padding) {
				return (BYTE*)(buf_ptr + i);
			}
		}
		return nullptr;
	}
};

CodeScanReport::t_section_status pesieve::CodeScanner::scanSection(PeSection &originalSec, PeSection &remoteSec, OUT PatchList &patchesList)
{
	if (!originalSec.isInitialized() || !remoteSec.isInitialized()) {
		return CodeScanReport::SECTION_SCAN_ERR;
	}
	clearIAT(originalSec, remoteSec);
	clearExports(originalSec, remoteSec);
	clearLoadConfig(originalSec, remoteSec);
	//TODO: handle sections that have inside Delayed Imports (they give false positives)

	const size_t smaller_size = originalSec.loadedSize > remoteSec.loadedSize ? remoteSec.loadedSize : originalSec.loadedSize;
#ifdef _DEBUG
	std::cout << "Code RVA: " 
		<< std::hex << originalSec.rva
		<< " to "
		<< std::hex << originalSec.loadedSize
		<< std::endl;
#endif
	//check if the code of the loaded module is same as the code of the module on the disk:
	int res = memcmp(remoteSec.loadedSection, originalSec.loadedSection, smaller_size);

	if ((originalSec.rawSize == 0 || peconv::is_padding(originalSec.loadedSection, smaller_size, 0))
		&& !peconv::is_padding(remoteSec.loadedSection, smaller_size, 0))
	{
		return pesieve::CodeScanReport::SECTION_UNPACKED; // modified
	}

	if (res != 0) {
		collectPatches(originalSec.rva, originalSec.loadedSection, remoteSec.loadedSection, smaller_size, patchesList);
	}

	if (remoteSec.loadedSize > originalSec.loadedSize) {
		
		const size_t diff = remoteSec.loadedSize - originalSec.loadedSize;
		const BYTE *diff_bgn = remoteSec.loadedSection + originalSec.loadedSize;
		
		BYTE *not_padding = first_different(diff_bgn, diff, 0);
		if (not_padding) {
			const DWORD found_offset = MASK_TO_DWORD((ULONG_PTR)not_padding - (ULONG_PTR)remoteSec.loadedSection);
			const DWORD found_rva = remoteSec.rva + found_offset;
			PatchList::Patch* currPatch = new(std::nothrow) PatchList::Patch(moduleData.moduleHandle, patchesList.size(), found_rva);
			if (currPatch) {
				currPatch->setEnd(MASK_TO_DWORD(remoteSec.rva + remoteSec.loadedSize));
				patchesList.insert(currPatch);
			}
		}
	}
	if (patchesList.size()) {
		return pesieve::CodeScanReport::SECTION_PATCHED; // modified
	}
	if (res == 0) {
		return pesieve::CodeScanReport::SECTION_NOT_MODIFIED; //not modified
	}
	return pesieve::CodeScanReport::SECTION_UNPACKED; // modified
}

size_t pesieve::CodeScanner::collectExecutableSections(RemoteModuleData &_remoteModData, std::map<size_t, PeSection*> &sections, CodeScanReport &my_report)
{
	size_t initial_size = sections.size();
	const size_t sec_count = peconv::get_sections_count(_remoteModData.headerBuffer, _remoteModData.getHeaderSize());
	for (DWORD i = 0; i < sec_count; i++) {
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(_remoteModData.headerBuffer, _remoteModData.getHeaderSize(), i);
		if (section_hdr == nullptr) {
			continue;
		}

		const bool is_entry = _remoteModData.isSectionEntry(i);

		if (!is_entry // entry section may be set as non executable, but it will still be executed
			&& !(section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !_remoteModData.isSectionExecutable(i, this->isScanData, this->isScanInaccessible))
		{
			//not executable, skip it
			continue;
		}

		//get the code section from the remote module:
		PeSection *remoteSec = new(std::nothrow) PeSection(_remoteModData, i);
		if (remoteSec && remoteSec->isInitialized()) {
			if (is_entry // always scan section containing Entry Point
				|| is_code(remoteSec->loadedSection, remoteSec->loadedSize))
			{
				sections[i] = remoteSec;
				continue;
			}
		}
		else {
			// report about failed initialization
			my_report.sectionToResult[i] = CodeScanReport::SECTION_SCAN_ERR;
		}
		// the section was not added to the list, delete it instead:
		delete remoteSec;
	}
	//corner case: PEs without sections
	if (sec_count == 0) {
		PeSection *remoteSec = new(std::nothrow) PeSection(_remoteModData, 0);
		if (remoteSec && remoteSec->isInitialized()) {
			sections[0] = remoteSec;
		}
		else {
			// report about failed initialization
			my_report.sectionToResult[0] = CodeScanReport::SECTION_SCAN_ERR;
			// the section was not added to the list, delete it instead:
			delete remoteSec;
		}
	}
	return sections.size() - initial_size;
}

void pesieve::CodeScanner::freeExecutableSections(std::map<size_t, PeSection*> &sections)
{
	std::map<size_t, PeSection*>::iterator itr;
	for (itr = sections.begin(); itr != sections.end(); ++itr) {
		PeSection *sec = itr->second;
		delete sec;
	}
	sections.clear();
}

t_scan_status pesieve::CodeScanner::scanUsingBase(
	IN ULONGLONG load_base,
	IN std::map<size_t, PeSection*> &remote_code,
	OUT std::map<DWORD, CodeScanReport::t_section_status> &sectionToResult,
	OUT PatchList &patchesList)
{
	t_scan_status last_res = SCAN_NOT_SUSPICIOUS;

	// before scanning, ensure that the original module is relocated to the base where it was loaded
	if (!moduleData.relocateToBase(load_base)) {
		return SCAN_ERROR;
	}

	size_t errors = 0;
	size_t modified = 0;
	std::map<size_t, PeSection*>::iterator itr;

	for (itr = remote_code.begin(); itr != remote_code.end(); ++itr) {
		size_t sec_indx = itr->first;
		PeSection *remoteSec = itr->second;

		PeSection originalSec(moduleData, sec_indx);

		CodeScanReport::t_section_status sec_status = scanSection(originalSec, *remoteSec, patchesList);
		sectionToResult[originalSec.rva] = sec_status; //save the status for the section

		if (sec_status == pesieve::CodeScanReport::SECTION_SCAN_ERR) errors++;
		else if (sec_status != pesieve::CodeScanReport::SECTION_NOT_MODIFIED) {
			modified++;
		}
	}

	if (modified > 0) {
		last_res = SCAN_SUSPICIOUS; //the highest priority for modified
	}
	else if (errors > 0) {
		last_res = SCAN_ERROR;
	}
	return last_res;
}

pesieve::CodeScanReport* pesieve::CodeScanner::scanRemote()
{
	if (!moduleData.isInitialized()) {
		std::cerr << "[-] Module not initialized" << std::endl;
		return nullptr;
	}
	if (!remoteModData.isInitialized()) {
		std::cerr << "[-] Failed to read the module header" << std::endl;
		return nullptr;
	}
	CodeScanReport *my_report = new(std::nothrow) CodeScanReport(moduleData.moduleHandle, remoteModData.getModuleSize());
	if (!my_report) return nullptr; //this should not happen...

	my_report->isDotNetModule = moduleData.isDotNet();
	
	t_scan_status last_res = SCAN_NOT_SUSPICIOUS;
	std::map<size_t, PeSection*> remote_code;

	if (!collectExecutableSections(remoteModData, remote_code, *my_report)) {
		my_report->status = last_res;
		if (my_report->countInaccessibleSections() > 0) {
			my_report->status = SCAN_ERROR;
		}
		return my_report;
	}
	ULONGLONG load_base = (ULONGLONG)moduleData.moduleHandle;
	ULONGLONG hdr_base = remoteModData.getHdrImageBase();

	my_report->relocBase = load_base;
	last_res = scanUsingBase(load_base, remote_code, my_report->sectionToResult, my_report->patchesList);
	
	if (load_base != hdr_base && my_report->patchesList.size() > 0) {
#ifdef _DEBUG
		std::cout << "[WARNING] Load Base: " << std::hex << load_base << " is different than the Hdr Base: " << hdr_base << "\n";
#endif
		PatchList list2;
		std::map<DWORD, CodeScanReport::t_section_status> section_to_result;
		t_scan_status scan_res2 = scanUsingBase(hdr_base, remote_code, section_to_result, list2);
		if (list2.size() < my_report->patchesList.size()) {
			my_report->relocBase = hdr_base;
			my_report->patchesList = list2;
			my_report->sectionToResult = section_to_result;
			last_res = scan_res2;
		}
#ifdef _DEBUG
		std::cout << "Using patches list for the base: " << my_report->relocBase << " list size: " << my_report->patchesList.size() << "\n";
#endif
	}

	this->freeExecutableSections(remote_code);
	//post-process collected patches:
	postProcessScan(*my_report);

	my_report->status = last_res;
	return my_report; // last result
}

bool pesieve::CodeScanner::postProcessScan(IN OUT CodeScanReport &report)
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
