#include "hook_scanner.h"

#include <fstream>

#include "peconv.h"

bool PatchList::Patch::reportPatch(std::ofstream &patch_report, const char delimiter)
{
	if (patch_report.is_open()) {
		patch_report << std::hex << startRva;
		patch_report << delimiter;
		if (this->is_hook) {
			patch_report << "hook_" << id;
			patch_report << "->" << std::hex << hook_target_va;
		} else {
			patch_report << "patch_" << id;
		}
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

ULONGLONG PatchAnalyzer::getJmpDestAddr(ULONGLONG currVA, DWORD instrLen, DWORD lVal)
{
	return (currVA + instrLen) + lVal;
}

bool PatchAnalyzer::parseJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va)
{
	DWORD *lval = (DWORD*)((ULONGLONG) patch_ptr + 1);
	ULONGLONG addr = getJmpDestAddr(patch_va, 5, *lval);
	patch.setHookTarget(addr);
	return true;
}

bool PatchAnalyzer::parseMovJmp(PatchList::Patch &patch, PBYTE patch_ptr, size_t mov_instr_len)
{
	PBYTE jmp_ptr = patch_ptr + mov_instr_len; // next instruction
	DWORD reg_id1 = 0;
	if (jmp_ptr[0] == 0xFF && jmp_ptr[1] >= 0xE0 && jmp_ptr[1] <= 0xEF ) {
		//jmp reg
		reg_id1 = jmp_ptr[1] - 0xE0;
	} else {
#ifdef _DEBUG
		std::cerr << "It is not MOV->JMP" << std::endl;
#endif
		return false;
	}
	DWORD reg_id2 = patch_ptr[0] - 0xB8;;
	if (reg_id1 != reg_id2) {
#ifdef _DEBUG
		std::cerr << "MOV->JMP : reg mismatch" << std::endl;
#endif
		return false;
	}
	ULONGLONG addr = NULL;
	if (mov_instr_len == 5) { //32bit
		DWORD *lval = (DWORD*)((ULONGLONG) patch_ptr + 1);
		addr = *lval;
	} else if (mov_instr_len == 9) { //64bit
		ULONGLONG *lval = (ULONGLONG*)((ULONGLONG) patch_ptr + 1);
		addr = *lval;
	} else {
		return false;
	}
	patch.setHookTarget(addr);
	return true;
}

bool PatchAnalyzer::analyze(PatchList::Patch &patch)
{
	ULONGLONG section_va = moduleData.rvaToVa(sectionRVA);
	ULONGLONG patch_va = moduleData.rvaToVa(patch.startRva);
	size_t patch_offset = patch.startRva - sectionRVA;
	PBYTE patch_ptr = this->patchedCode + patch_offset;

	BYTE op = patch_ptr[0];
	if (op == OP_JMP) {
		return parseJmp(patch, patch_ptr, patch_va);
	}
	bool is64bit = this->moduleData.is64bit();
	size_t mov_instr_len = 5;
	if (is64bit) {
		if (op >= 0x40 && op <= 0x4F) { // mov modifier
			patch_ptr++;
			op = patch_ptr[0];
			mov_instr_len = 9;
		}
	}
	if (op >= 0xB8 && op <= 0xBF) { // is mov
		this->parseMovJmp(patch, patch_ptr, mov_instr_len);
	}
	
	return false;
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
				analyzer.analyze(*currPatch);
				currPatch = nullptr;
			}
			continue;
		}
		if (currPatch == nullptr) {
			//open a new patch
			currPatch = new PatchList::Patch(patchesList.size(), (DWORD) section_rva + i);
			patchesList.insert(currPatch);
		}
	}
	// if there is still unclosed patch, close it now:
	if (currPatch != nullptr) {
		//this happens if the patch lasts till the end of code, so, its end is the end of code
		currPatch->setEnd(section_rva + (DWORD) code_size);
		analyzer.analyze(*currPatch);
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
