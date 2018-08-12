#include "mempage_scanner.h"
#include "module_data.h"
#include "artefact_scanner.h"

#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
#include "../utils/artefacts_util.h"

#define PE_NOT_FOUND 0

bool MemPageScanner::isCode(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return false;
	}
	return is_code(memPageData.getLoadedData(), memPageData.getLoadedSize());
}

MemPageScanReport* MemPageScanner::scanShellcode(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return nullptr;
	}
	//shellcode found! now examin it with more details:
	ArtefactScanner artefactScanner(this->processHandle, memPage);
	MemPageScanReport *my_report = artefactScanner.scanRemote();
	if (my_report) {
#ifdef _DEBUG
		std::cout << "The detected shellcode is probably a corrupt PE" << std::endl;
#endif
		return my_report;
	}
	//just a regular shellcode...

	if (!this->detectShellcode) {
		// not a PE file, and we are not interested in shellcode, so just finish it here
		return nullptr;
	}
	//report about shellcode:
	ULONGLONG region_start = memPage.region_start;
	const size_t region_size = size_t (memPage.region_end - region_start);
	my_report = new MemPageScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->has_pe = false;
	my_report->has_shellcode = true;
	return my_report;
}

MemPageScanReport* MemPageScanner::scanRemote()
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
		return nullptr;
	}

	// is the page executable?
	bool is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE);

	if (!is_any_exec) {
		// probably not interesting
		return nullptr;
	}
	bool is_doppel = false;
	if (memPage.mapping_type == MEM_IMAGE) {
		if (!memPage.hasMappedName()) {
			is_doppel = true;
		} else {
			//probably legit
			return nullptr;
		}
	}
	if (memPage.mapping_type == MEM_MAPPED && memPage.isRealMapping()) {
		//probably legit
		return nullptr;
	}
	MemPageScanReport* my_report = nullptr;
	if (is_any_exec && isCode(memPage)) {
#ifdef _DEBUG
		std::cout << std::hex << memPage.start_va << ": Code pattern found, scanning..." << std::endl;
#endif
		my_report = this->scanShellcode(memPage);
	}
	if (!my_report) {
		return nullptr;
	}
	my_report->is_executable = true;
	my_report->is_listed_module = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	my_report->is_doppel = is_doppel;
	return my_report;
}
