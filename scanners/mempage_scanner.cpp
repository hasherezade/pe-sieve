#include "mempage_scanner.h"
#include "module_data.h"
#include "artefact_scanner.h"

#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"

#define PE_NOT_FOUND 0

ULONGLONG MemPageScanner::findPeHeader(MemPageData &memPage)
{
	if (memPage.loadedData == nullptr) {
		if (! memPage.loadRemote()) return PE_NOT_FOUND;
		if (memPage.loadedData == nullptr) return PE_NOT_FOUND;
	}
	size_t scan_size = memPage.loadedSize;
	BYTE* buffer_ptr = memPage.loadedData;

	//scan only one page, not the full area
	for (size_t i = 0; i < scan_size && i < peconv::MAX_HEADER_SIZE; i++) {
		if (peconv::get_nt_hrds(buffer_ptr+i, scan_size-i) != nullptr) {
			return  memPage.start_va + i;
		}
		if (!this->isDeepScan) {
			return PE_NOT_FOUND;
		}
	}
	return PE_NOT_FOUND;
}

MemPageScanReport* MemPageScanner::scanShellcode(MemPageData &memPageData)
{
	if (memPage.loadedData == nullptr) {
		return nullptr;
	}

	BYTE prolog32_pattern[] = { 0x55, 0x8b, 0xEC };
	BYTE prolog64_pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20 };

	size_t prolog32_size = sizeof(prolog32_pattern);
	size_t prolog64_size = sizeof(prolog64_pattern);
	bool is32bit = false;

	BYTE* buffer = memPageData.loadedData;

	bool pattern_found = false;
	for (size_t i = 0; (i + prolog64_size) < memPageData.loadedSize; i++) {
		if (memcmp(buffer + i, prolog32_pattern, prolog32_size) == 0) {
			pattern_found = true;
			is32bit = true;
#ifdef _DEBUG
			std::cout << std::hex << memPage.region_start << ": contains 32bit shellcode"  << std::endl;
#endif
			break;
		}
		if (memcmp(buffer + i, prolog64_pattern, prolog64_size) == 0) {
			pattern_found = true;
#ifdef _DEBUG
			std::cout << std::hex << memPage.region_start << " : contains 64bit shellcode" << std::hex << memPage.region_start << std::endl;
#endif
			break;
		}
	}
	if (pattern_found == false) {
		return nullptr;
	}
	//shellcode found! now examin it with more details:
	ArtefactScanner artefactScanner(this->processHandle, memPage);
	MemPageScanReport *my_report = artefactScanner.scanRemote();
	if (my_report != nullptr) {
		std::cout << "The detected shellcode is probably a corrupt PE" << std::endl;
		return my_report;
	}
	//just a regular shellcode...
	ULONGLONG region_start = memPage.region_start;

	//TODO: differentiate the raport: shellcode vs PE
	const size_t region_size = size_t (memPage.region_end - region_start);
	my_report = new MemPageScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->is_executable = true;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	my_report->is_shellcode = true;
	return my_report;
}

MemPageScanReport* MemPageScanner::scanRemote()
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
		return nullptr;
	}
	if (memPage.mapping_type == MEM_IMAGE) {
		//probably legit
		return nullptr;
	}
	bool only_executable = true;

	// is the page executable?
	bool is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE);

	if (!is_any_exec && memPage.is_listed_module) {
		// the header is not executable + the module was already listed - > probably not interesting
#ifdef _DEBUG
		std::cout << std::hex << memPage.start_va << " : Aleady listed" << std::endl;
#endif
		return nullptr;
	}
	ULONGLONG pe_header = findPeHeader(memPage);
	if (pe_header == PE_NOT_FOUND) {
		if (!this->detectShellcode) {
			// not a PE file, and we are not interested in checking for shellcode, so just finish it here
			return nullptr;
		}
		if (is_any_exec && (memPage.mapping_type == MEM_PRIVATE ||
			(memPage.mapping_type == MEM_MAPPED && !memPage.isRealMapping())))
		{
#ifdef _DEBUG
			std::cout << std::hex << memPage.start_va << " : Checking for shellcode" << std::endl;
#endif
			return this->scanShellcode(memPage);
		}
		return nullptr; // not a PE file
	}
	RemoteModuleData remoteModule(this->processHandle, (HMODULE)pe_header);
	bool is_executable = remoteModule.hasExecutableSection();

	t_scan_status status = is_executable ? SCAN_SUSPICIOUS : SCAN_NOT_SUSPICIOUS;
	if (!only_executable) {
		// treat every injected PE file as suspicious, even if it does not have any executable sections
		status = SCAN_SUSPICIOUS;
	}

	if (status == SCAN_SUSPICIOUS && memPage.mapping_type == MEM_MAPPED) {
		if (memPage.isRealMapping()) {
			//this is a legit mapping
			status = SCAN_NOT_SUSPICIOUS;
		}
	}
#ifdef _DEBUG
	std::cout << "[" << std::hex << memPage.start_va << "] Found a PE in the working set. Status: " << status << std::endl;
#endif
	const size_t pe_size = remoteModule.getModuleSize();
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)pe_header, pe_size, status);
	my_report->is_executable = is_executable;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	return my_report;
}
