#include "scanner.h"

#include <Psapi.h>
#include <sstream>
#include <fstream>

#include "util.h"

#include "hollowing_scanner.h"
#include "hook_scanner.h"

//---
bool ModuleData::loadOriginal()
{
	if (!GetModuleFileNameExA(processHandle, this->moduleHandle, szModName, MAX_PATH)) {
		is_module_named = false;
		const char unnamed[] = "unnamed";
		memcpy(szModName, unnamed, sizeof(unnamed));
	}
	peconv::free_pe_buffer(original_module, original_size);
	std::cout << szModName << std::endl;
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}

bool ModuleData::reloadWow64()
{
	bool is_converted = convert_to_wow64_path(szModName);
	if (!is_converted) return false;

#ifdef _DEBUG
	std::cout << "Reloading Wow64..." << std::endl;
#endif
	//reload it and check again...
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	return true;
}

//---

t_scan_status get_scan_status(ModuleScanReport *report)
{
	if (report == nullptr) {
		return SCAN_ERROR;
	}
	return report->status;
}

size_t ProcessScanner::enumModules(OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters)
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

t_scan_status ProcessScanner::scanForHollows(ModuleData& modData, ProcessScanReport& process_report)
{
	BOOL isWow64 = FALSE;
#ifdef _WIN64
	IsWow64Process(processHandle, &isWow64);
#endif
	HollowingScanner hollows(processHandle);
	HeadersScanReport *scan_report = hollows.scanRemote(modData);
	if (scan_report == nullptr) {
		process_report.summary.errors++;
		return SCAN_ERROR;
	}
	t_scan_status is_hollowed = get_scan_status(scan_report);

	if (is_hollowed == SCAN_MODIFIED && isWow64) {
		if (modData.reloadWow64()) {
			delete scan_report; // delete previous report
			scan_report = hollows.scanRemote(modData);
		}
		is_hollowed = get_scan_status(scan_report);
	}
	process_report.appendReport(scan_report);
	if (is_hollowed == SCAN_ERROR) {
		process_report.summary.errors++;
	}
	if (is_hollowed == SCAN_MODIFIED) {
		process_report.summary.replaced++;
	}
	return is_hollowed;
}

t_scan_status ProcessScanner::scanForHooks(ModuleData& modData, ProcessScanReport& process_report)
{
	HookScanner hooks(processHandle);
	CodeScanReport *scan_report = hooks.scanRemote(modData);
	t_scan_status is_hooked = get_scan_status(scan_report);
	process_report.appendReport(scan_report);
	
	if (is_hooked == SCAN_MODIFIED) {
		process_report.summary.hooked++;
	}
	if (is_hooked == SCAN_ERROR) {
		process_report.summary.errors++;
	}
	return is_hooked;
}

ProcessScanReport* ProcessScanner::scanRemote()
{
	ProcessScanReport *process_report = new ProcessScanReport(this->args.pid);
	t_report &report = process_report->summary;


	HMODULE hMods[1024];
	const size_t modules_count = enumModules(hMods, sizeof(hMods), args.filter);
	if (modules_count == 0) {
		report.errors++;
		return process_report;
	}
	if (args.imp_rec) {
		if (exportsMap) delete exportsMap;
		exportsMap = new peconv::ExportsMapper();
	}

	report.scanned = 0;
	for (size_t i = 0; i < modules_count; i++, report.scanned++) {
		if (processHandle == NULL) break;

		ModuleData modData(processHandle, hMods[i]);
		if (!modData.loadOriginal()) {
			std::cout << "[!][" << args.pid <<  "] Suspicious: could not read the module file!" << std::endl;
			//make a report that finding original module was not possible
			process_report->appendReport(new ModuleScanReport(processHandle, hMods[i], SCAN_MODIFIED));
			report.suspicious++;
			continue;
		}
		
		t_scan_status is_hollowed = scanForHollows(modData, *process_report);
		if (is_hollowed == SCAN_ERROR) {
			continue;
		}
		if (exportsMap != nullptr) {
			exportsMap->add_to_lookup(modData.szModName, (HMODULE) modData.original_module, (ULONGLONG) modData.moduleHandle);
		}

		t_scan_status is_hooked = SCAN_NOT_MODIFIED;
		//if not hollowed, check for hooks:
		if (is_hollowed == SCAN_NOT_MODIFIED) {
			is_hooked = scanForHooks(modData, *process_report);
		}
		
	}
	return process_report;
}
