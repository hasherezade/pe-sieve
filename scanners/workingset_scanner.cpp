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
	return isPotentiallyExecutable(memPageData, this->args.data);
}

bool pesieve::WorkingSetScanner::isPotentiallyExecutable(MemPageData &memPageData, const t_data_scan_mode &mode)
{
	if (mode == pesieve::PE_DATA_NO_SCAN) {
		return false;
	}

	// check preconditions:
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
	// preconditions are fulfilled, now check the access:
	const bool is_page_readable = pesieve::util::is_readable(memPage.mapping_type, memPage.protection);
	if (mode != pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
		if (is_page_readable) {
			return true;
		}
	}
	if ((mode >= pesieve::PE_DATA_SCAN_INACCESSIBLE) || (mode == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY)) {
		if (this->isReflection && (memPage.protection & PAGE_NOACCESS)) {
			return true;
		}
	}
	return false;
}

WorkingSetScanReport* pesieve::WorkingSetScanner::scanExecutableArea(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return nullptr;
	}
	// check for PE artifacts (regardless if it has shellcode patterns):
	if (!isScannedAsModule(memPage)) {
		ArtefactScanner artefactScanner(this->processHandle, this->isReflection, memPage, this->processReport);
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
	WorkingSetScanReport *my_report = new WorkingSetScanReport((HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
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
	if (!memPage.loadMappedName()) {
		//cannot retrieve the mapped name
		return false;
	}

	const HMODULE module_start = (HMODULE)memPage.alloc_base;

	if (!args.quiet) {
		std::cout << "[!] Scanning detached: " << std::hex << module_start << " : " << memPage.mapped_name << std::endl;
	}
	RemoteModuleData remoteModData(this->processHandle, this->isReflection, module_start);
	if (!remoteModData.isInitialized()) {
		if (!args.quiet) {
			std::cout << "[-] Could not read the remote PE at: " << std::hex << module_start << std::endl;
		}
		return false;
	}

	//load module from file:
	ModuleData modData(processHandle, module_start, memPage.mapped_name, args.use_cache);
	if (!modData.loadOriginal()) {
		if (!args.quiet) {
			std::cerr << "[-] [" << std::hex << modData.moduleHandle << "] Could not read the module file" << std::endl;
		}
		processReport.appendReport(new UnreachableModuleReport(module_start, 0, memPage.mapped_name));
		return false;
	}
	t_scan_status scan_status = ProcessScanner::scanForHollows(processHandle, modData, remoteModData, processReport);
#ifdef _DEBUG
	std::cout << "[*] Scanned for hollows. Status: " << scan_status << std::endl;
#endif
	if (scan_status == SCAN_ERROR) {
		// failed scanning it as a loaded PE module
		return false;
	}
	if (scan_status == SCAN_SUSPICIOUS) {
		// detected as hollowed, no need for further scans
		return true;
	}
	if (!args.no_hooks) {
		const bool scan_data = (this->args.data >= pesieve::PE_DATA_SCAN_ALWAYS && this->args.data != PE_DATA_SCAN_INACCESSIBLE_ONLY)
			|| (!memPage.is_dep_enabled && (this->args.data == pesieve::PE_DATA_SCAN_NO_DEP));
		const bool scan_inaccessible = (this->isReflection && (this->args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE));
		scan_status = ProcessScanner::scanForHooks(processHandle, modData, remoteModData, processReport, scan_data, scan_inaccessible);
#ifdef _DEBUG
		std::cout << "[*] Scanned for hooks. Status: " << scan_status << std::endl;
#endif
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
