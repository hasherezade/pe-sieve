#include "workingset_scanner.h"
#include "module_data.h"
#include "artefact_scanner.h"
#include "scanner.h"

#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
#include "../utils/artefacts_util.h"

using namespace pesieve;
using namespace pesieve::util;

bool pesieve::WorkingSetScanner::isCode(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return false;
	}
	return is_code(memPageData.getLoadedData(), memPageData.getLoadedSize());
}

bool pesieve::WorkingSetScanner::isExecutable(MemPageData &memPageData)
{
	if (pesieve::util::is_executable(memPage.mapping_type, memPage.protection)) {
		return true;
	}
	if (pesieve::util::is_executable(memPage.mapping_type, memPage.initial_protect)) {
		return true;
	}
	return isPotentiallyExecutable(memPageData, this->args.data);
}

bool pesieve::WorkingSetScanner::isPotentiallyExecutable(MemPageData &memPageData, const t_data_scan_mode &mode)
{
	if (mode == pesieve::PE_DATA_NO_SCAN) {
		return false;
	}

	const bool is_managed = this->processReport.isManagedProcess();

	if (mode == pesieve::PE_DATA_SCAN_NO_DEP 
		&& memPage.is_dep_enabled && !is_managed)
	{
		return false;
	}
	if (mode == pesieve::PE_DATA_SCAN_DOTNET
		&& !is_managed)
	{
		return false;
	}
	bool is_any_exec = false;

	if (memPage.mapping_type == MEM_IMAGE) {
		is_any_exec = (memPage.protection & SECTION_MAP_READ) != 0;

		if (is_any_exec) return true;
	}
	is_any_exec = (memPage.protection & PAGE_READWRITE)
		|| (memPage.protection & PAGE_READONLY);
	return is_any_exec;
}

WorkingSetScanReport* pesieve::WorkingSetScanner::scanExecutableArea(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return nullptr;
	}
	// check for PE artifacts (regardless if it has shellcode patterns):
	if (!isScannedAsModule(memPage)) {
		ArtefactScanner artefactScanner(this->processHandle, memPage, this->processReport);
		WorkingSetScanReport *my_report1 = artefactScanner.scanRemote();
		if (my_report1) {
			//pe artefacts found
			return my_report1;
		}
	}
	if (!this->args.shellcode) {
		// not a PE file, and we are not interested in shellcode, so just finish it here
		return nullptr;
	}
	if (!isCode(memPage)) {
		// shellcode patterns not found
		return nullptr;
	}
	//report about shellcode:
	ULONGLONG region_start = memPage.region_start;
	const size_t region_size = size_t (memPage.region_end - region_start);
	WorkingSetScanReport *my_report = new WorkingSetScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->has_pe = isScannedAsModule(memPage) && this->processReport.hasModule(memPage.region_start);
	my_report->has_shellcode = true;
	return my_report;
}

bool pesieve::WorkingSetScanner::isScannedAsModule(MemPageData &memPage)
{
	if (memPage.mapping_type != MEM_IMAGE) {
		return false;
	}
	if (this->processReport.hasModule((ULONGLONG)memPage.alloc_base)) {
		return true; // it was already scanned as a PE
	}
	return false;
}

bool pesieve::WorkingSetScanner::scanImg()
{
	const bool show_info = (!args.quiet);

	if (!memPage.loadMappedName()) {
		//cannot retrieve the mapped name
		return false;
	}

	const HMODULE module_start = (HMODULE)memPage.alloc_base;
	
	if (show_info) {
		std::cout << "[!] Scanning detached: " << std::hex << module_start << " : " << memPage.mapped_name << std::endl;
	}
	RemoteModuleData remoteModData(this->processHandle, module_start);
	if (!remoteModData.isInitialized()) {
		if (show_info) {
			std::cout << "[-] Could not read the remote PE at: " << std::hex << module_start << std::endl;
		}
		return false;
	}

	//load module from file:
	ModuleData modData(processHandle, module_start, memPage.mapped_name);
	
	const t_scan_status status = ProcessScanner::scanForHollows(processHandle, modData, remoteModData, processReport);
#ifdef _DEBUG
	std::cout << "[*] Scanned for hollows. Status: " << status << std::endl;
#endif
	if (status == SCAN_ERROR) {
		//failed scanning it as a loaded PE module
		return false;
	}
	if (status == SCAN_NOT_SUSPICIOUS) {
		if (modData.isDotNet()) {
#ifdef _DEBUG
			std::cout << "[*] Skipping a .NET module: " << modData.szModName << std::endl;
#endif
			processReport.appendReport(new SkippedModuleReport(processHandle, modData.moduleHandle, modData.original_size, modData.szModName));
			return true;
		}
		if (!args.no_hooks) {
			const t_scan_status hooks_stat = ProcessScanner::scanForHooks(processHandle, modData, remoteModData, processReport);
#ifdef _DEBUG
			std::cout << "[*] Scanned for hooks. Status: " << hooks_stat << std::endl;
#endif
		}
	}
	return true;
}

WorkingSetScanReport* pesieve::WorkingSetScanner::scanRemote()
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
#ifdef _DEBUG
		std::cout << "[!] Could not fill: " << std::hex << memPage.start_va << " to: " << memPage.region_end << "\n";
#endif
		return nullptr;
	}
	// is the page executable?
	const bool is_any_exec = isExecutable(memPage);
	if (!is_any_exec) {
		// probably not interesting
		return nullptr;
	}

	if (memPage.mapping_type == MEM_MAPPED && memPage.isRealMapping()) {
		//probably legit
		return nullptr;
	}

	if (memPage.mapping_type == MEM_IMAGE) {
		memPage.loadModuleName();
		memPage.loadMappedName();
		if (!isScannedAsModule(memPage)) {
			scanImg();
		}
		const size_t region_size = (memPage.region_end) ? (memPage.region_end - memPage.region_start) : 0;
		if (this->processReport.hasModuleContaining(memPage.region_start, region_size)) {
			// the area was already scanned
			return nullptr;
		}
	}
#ifdef _DEBUG
	std::cout << std::hex << memPage.start_va << ": Scanning executable area" << std::endl;
#endif
	WorkingSetScanReport* my_report = this->scanExecutableArea(memPage);
	if (!my_report) {
		return nullptr;
	}
	my_report->is_executable = true;
	my_report->protection = memPage.protection;
	my_report->mapping_type = memPage.mapping_type;
	my_report->mapped_name = memPage.mapped_name;
	return my_report;
}
