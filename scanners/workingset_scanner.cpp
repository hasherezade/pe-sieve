#include "workingset_scanner.h"
#include "module_data.h"
#include "artefact_scanner.h"
#include "scanner.h"

#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
#include "../utils/artefacts_util.h"

bool WorkingSetScanner::isCode(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return false;
	}
	return is_code(memPageData.getLoadedData(), memPageData.getLoadedSize());
}

bool WorkingSetScanner::isExecutable(MemPageData &memPageData)
{
	bool is_any_exec = false;
	if (memPage.mapping_type == MEM_IMAGE)
	{
		is_any_exec = (memPage.protection & SECTION_MAP_EXECUTE)
			|| (memPage.protection & SECTION_MAP_EXECUTE_EXPLICIT)
			|| (memPage.initial_protect & SECTION_MAP_EXECUTE)
			|| (memPage.initial_protect & SECTION_MAP_EXECUTE_EXPLICIT);

		if (is_any_exec) return true;
	}
	is_any_exec = (memPage.initial_protect & PAGE_EXECUTE_READWRITE)
		|| (memPage.initial_protect & PAGE_EXECUTE_READ)
		|| (memPage.initial_protect & PAGE_EXECUTE)
		|| (memPage.initial_protect & PAGE_EXECUTE_WRITECOPY)
		|| (memPage.protection & PAGE_EXECUTE_READWRITE)
		|| (memPage.protection & PAGE_EXECUTE_READ)
		|| (memPage.protection & PAGE_EXECUTE)
		|| (memPage.protection & PAGE_EXECUTE_WRITECOPY);
	if (is_any_exec) return true;

	if (this->args.data) {
		is_any_exec = isPotentiallyExecutable(memPageData);
	}
	return is_any_exec;
}

bool WorkingSetScanner::isPotentiallyExecutable(MemPageData &memPageData)
{
	bool is_any_exec = false;
	if (!memPage.is_dep_enabled) {
		//DEP is disabled, check also pages that are readable
		is_any_exec = (memPage.protection & PAGE_READWRITE)
			|| (memPage.protection & PAGE_READONLY);
	}
	return is_any_exec;
}

WorkingSetScanReport* WorkingSetScanner::scanExecutableArea(MemPageData &memPageData)
{
	if (!memPage.load()) {
		return nullptr;
	}
	//shellcode found! now examin it with more details:
	ArtefactScanner artefactScanner(this->processHandle, memPage);
	WorkingSetScanReport *my_report = artefactScanner.scanRemote();
	if (my_report) {
		//pe artefacts found
		return my_report;
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
	my_report = new WorkingSetScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->has_pe = false;
	my_report->has_shellcode = true;
	return my_report;
}

bool WorkingSetScanner::scanDisconnectedImg()
{
	bool show_info = (!args.quiet);
#ifdef _DEBUG
	show_info = true;
#endif
	const HMODULE module_start = (HMODULE)memPage.alloc_base;

	if (this->processReport->hasModuleContaining((ULONGLONG)module_start)) {
		if (this->processReport->hasModuleContaining(memPage.region_start)) {
#ifdef _DEBUG
			std::cout << "[*] This area was already scanned: " << std::hex << memPage.region_start << std::endl;
#endif
			// already scanned
			return true;
		}
		//it may be a shellcode after the loaded PE
		return false;
	}

	if (!memPage.loadMappedName()) {
		//cannot retrieve the mapped name
		return false;
	}
	
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
	if (status == SCAN_NOT_SUSPICIOUS) {
		if (modData.isDotNet()) {
#ifdef _DEBUG
			std::cout << "[*] Skipping a .NET module: " << modData.szModName << std::endl;
#endif
			if (processReport) {
				processReport->appendReport(new SkippedModuleReport(processHandle, modData.moduleHandle, modData.original_size, modData.szModName));
			}
			return true;
		}
		if (!args.no_hooks) {
			const t_scan_status hooks_stat = ProcessScanner::scanForHooks(processHandle, modData, remoteModData, processReport);
#ifdef _DEBUG
			std::cout << "[*] Scanned for hooks. Status: " << hooks_stat << std::endl;
#endif
		}
		return true;
	}
	return false;
}

WorkingSetScanReport* WorkingSetScanner::scanRemote()
{
	if (!memPage.isInfoFilled() && !memPage.fillInfo()) {
		return nullptr;
	}

	// is the page executable?
	bool is_any_exec = isExecutable(memPage);
	if (!is_any_exec) {
		// probably not interesting
		return nullptr;
	}

	if (memPage.mapping_type == MEM_MAPPED && memPage.isRealMapping()) {
		//probably legit
		return nullptr;
	}

	if (memPage.mapping_type == MEM_IMAGE) {

		const bool is_peb_module = memPage.loadModuleName();
		const bool is_mapped_name = memPage.loadMappedName();

		if (is_peb_module && is_mapped_name) {
			//probably legit
			return nullptr;
		}
		if (!is_peb_module) {
#ifdef _DEBUG
			std::cout << "[!] Detected a disconnected MEM_IMG: " << memPage.region_start << std::endl;
#endif
			if (scanDisconnectedImg()) {
				return nullptr; //scanned as disconnected
			}
			//scanning as disconnected module failed, continue scanning as an implant
#ifdef _DEBUG
			std::cout << "Continue to scan the disconnedted MEM_IMG as normal mem page: " << memPage.region_start << std::endl;
#endif
		}
	}

	WorkingSetScanReport* my_report = nullptr;
	if (is_any_exec) {
#ifdef _DEBUG
		std::cout << std::hex << memPage.start_va << ": Scanning executable area" << std::endl;
#endif
		my_report = this->scanExecutableArea(memPage);
	}
	if (!my_report) {
		return nullptr;
	}
	my_report->is_executable = true;
	my_report->protection = memPage.protection;
	my_report->mapping_type = memPage.mapping_type;
	my_report->mapped_name = memPage.mapped_name;
	return my_report;
}
