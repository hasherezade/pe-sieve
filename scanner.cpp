#include "scanner.h"

#include <Psapi.h>
#include <sstream>
#include <fstream>


#include "util.h"

#include "hollowing_scanner.h"
#include "hook_scanner.h"

t_scan_status ProcessScanner::get_scan_status(ModuleScanReport *report)
{
	if (report == nullptr) {
		return SCAN_ERROR;
	}
	return report->status;
}

size_t ProcessScanner::enum_modules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters)
{
	HANDLE hProcess = this->processHandle;
	if (hProcess == nullptr) return 0;

	DWORD cbNeeded;
	if (!EnumProcessModulesEx(hProcess, hMods, hModsMax, &cbNeeded, filters)) {
		DWORD last_err = GetLastError();
		throw std::exception("[-] Could not enumerate modules in the process", last_err);
		return 0;
	}
	const size_t modules_count = cbNeeded / sizeof(HMODULE);
	return modules_count;
}

size_t  report_patches(PatchList &patchesList, std::string reportPath)
{
	std::ofstream patch_report;
	patch_report.open(reportPath);
	if (patch_report.is_open() == false) {
		std::cout << "[-] Could not open the file: "<<  reportPath << std::endl;
	}
	
	size_t patches = patchesList.reportPatches(patch_report, ';');

	if (patch_report.is_open()) {
		patch_report.close();
	}
	return patches;
}

std::string make_dump_path(ULONGLONG modBaseAddr, std::string fname,  std::string directory)
{
	//const char* fname = get_file_name(szExePath);
	std::stringstream stream;
	if (directory.length() > 0) {
		stream << directory;
		stream << "\\";
	}
	stream << std::hex << modBaseAddr;
	if (fname.length() > 0) {
		stream << ".";
		stream << fname;
	} else {
		stream << ".dll";
	}
	return stream.str();
}

size_t ProcessScanner::dumpAllModified(ProcessScanReport &process_report, std::string directory)
{
	HANDLE hProcess = this->processHandle;
	if (hProcess == nullptr) {
		return 0;
	}

	char szModName[MAX_PATH] = { 0 };
	size_t dumped = 0;

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.module_reports.begin();
		itr != process_report.module_reports.end();
		itr++)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status == SCAN_MODIFIED) {
			memset(szModName, 0, MAX_PATH);
			std::string modulePath = "";
			if (GetModuleFileNameExA(processHandle, mod->module, szModName, MAX_PATH)) {
				modulePath = get_file_name(szModName);
			}
			std::string dumpFileName = make_dump_path((ULONGLONG)mod->module, modulePath, directory);
			if (!peconv::dump_remote_pe(
				dumpFileName.c_str(), //output file
				processHandle, 
				(PBYTE) mod->module, 
				true, //unmap
				exportsMap
				))
			{
				std::cerr << "Failed dumping module!" << std::endl;
				continue;
			}
			dumped++;
			CodeScanReport *code_report = dynamic_cast<CodeScanReport*>(mod);
			if (code_report != nullptr && code_report->patchesList.size() > 0) {
				report_patches(code_report->patchesList, dumpFileName + ".tag");
			}
		}
	}
	return dumped;
}

ProcessScanReport* ProcessScanner::scanRemote()
{
	ProcessScanReport *process_report = new ProcessScanReport(this->args.pid);
	t_report &report = process_report->summary;

	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HMODULE hMods[1024];
	const size_t modules_count = enum_modules(hMods, sizeof(hMods), args.filter);
	if (modules_count == 0) {
		report.errors++;
		return process_report;
	}
	if (args.imp_rec) {
		if (exportsMap) delete exportsMap;
		exportsMap = new peconv::ExportsMapper();
	}
	char szModName[MAX_PATH];

	report.scanned = 0;
	for (size_t i = 0; i < modules_count; i++, report.scanned++) {
		if (processHandle == NULL) break;
		
		bool is_module_named = true;

		if (!GetModuleFileNameExA(processHandle, hMods[report.scanned], szModName, MAX_PATH)) {
			std::cerr << "[!][" << args.pid <<  "] Cannot fetch module name" << std::endl;
			is_module_named = false;
			const char unnamed[] = "unnamed";
			memcpy(szModName, unnamed, sizeof(unnamed));
		}
		if (!args.quiet) {
			std::cout << "[*][" << args.pid <<  "] Scanning: " << szModName << std::endl;
		}
		ULONGLONG modBaseAddr = (ULONGLONG)hMods[i];
		const char* modFileName = get_file_name(szModName);

		//load the same module, but from the disk: 
		size_t module_size = 0;
		BYTE* original_module = nullptr;
		if (is_module_named) {
			original_module = peconv::load_pe_module(szModName, module_size, false, false);
		}
		if (original_module == nullptr) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			//TODO: make a report that finding original module was not possible
			HeadersScanReport *mod_report = new HeadersScanReport(processHandle, hMods[i]);
			mod_report->status = SCAN_MODIFIED;
			process_report->appendReport(mod_report);
			report.suspicious++;
			continue;
		}
		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		t_scan_status is_hollowed = SCAN_NOT_MODIFIED;

		HollowingScanner hollows(processHandle);
		HeadersScanReport *scan_report = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
		is_hollowed = get_scan_status(scan_report);

		if (is_hollowed == SCAN_MODIFIED) {
			if (isWow64) {
				//it can be caused by Wow64 path overwrite, check it...
				bool is_converted = convert_to_wow64_path(szModName);
#ifdef _DEBUG
				std::cout << "Reloading Wow64..." << std::endl;
#endif
				//reload it and check again...
				peconv::free_pe_buffer(original_module, module_size);
				original_module = peconv::load_pe_module(szModName, module_size, false, false);

				delete scan_report; // delete previous report
				scan_report = hollows.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			}

			is_hollowed = get_scan_status(scan_report);
			if (is_hollowed == SCAN_MODIFIED) {
				if (!args.quiet) {
					std::cout << "[*][" << args.pid <<  "] The module is replaced by a different PE!" << std::endl;
				}
				report.replaced++;
			}
		}

		process_report->appendReport(scan_report);

		if (exportsMap != nullptr) {
			exportsMap->add_to_lookup(szModName, (HMODULE) original_module, modBaseAddr);
		}
		//if not hollowed, check for hooks:
		if (is_hollowed == SCAN_NOT_MODIFIED) {
			HookScanner hooks(processHandle);
			CodeScanReport *scan_report = hooks.scanRemote((PBYTE)modBaseAddr, original_module, module_size);
			is_hooked = get_scan_status(scan_report);
			process_report->appendReport(scan_report);

			if (is_hooked == SCAN_MODIFIED) {
				if (!args.quiet) {
					std::cout << "[*][" << args.pid <<  "] The module is hooked!" << std::endl;
				}
				report.hooked++;
			}
		}
		if (is_hollowed == SCAN_ERROR || is_hooked == SCAN_ERROR) {
			std::cerr << "[-][" << args.pid <<  "] ERROR while checking the module: " << szModName << std::endl;
			report.errors++;
		}
		peconv::free_pe_buffer(original_module, module_size);
	}
	return process_report;
}
