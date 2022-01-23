#include "iat_scanner.h"

#include <peconv.h>

#include <string>
#include <fstream>
#include <iostream>

using namespace pesieve;

const bool IATScanReport::hooksToJSON(std::stringstream &outs, size_t level)
{
	if (notCovered.count() == 0) {
		return false;
	}
	bool is_first = true;
	OUT_PADDED(outs, level, "\"hooks_list\" : [\n");

	std::map<DWORD, ULONGLONG>::iterator itr;
	for (itr = notCovered.thunkToAddr.begin(); itr != notCovered.thunkToAddr.end(); ++itr) {
		const DWORD thunk_rva = itr->first;
		const ULONGLONG addr = itr->second;
		if (!is_first) {
			outs << ",\n";
		}
		is_first = false;
		OUT_PADDED(outs, level, "{\n");

		OUT_PADDED(outs, (level + 1), "\"thunk_rva\" : ");
		outs << "\"" << std::hex << thunk_rva << "\"" << ",\n";

		std::map<DWORD, peconv::ExportedFunc*>::const_iterator found = storedFunc.thunkToFunc.find(thunk_rva);
		if (found != storedFunc.thunkToFunc.end()) {
			const peconv::ExportedFunc *func = found->second;
			if (func) {
				OUT_PADDED(outs, (level + 1), "\"func_name\" : ");
				outs << "\"" << func->toString() << "\"" << ",\n";
			}
		}
		OUT_PADDED(outs, (level + 1), "\"target_va\" : ");
		outs << "\"" << std::hex << (ULONGLONG)addr << "\"";
		outs << "\n";
		OUT_PADDED(outs, level, "}");
	}
	outs << "\n";
	OUT_PADDED(outs, level, "]");
	return true;
}

std::string IATScanReport::formatTargetName(IN const peconv::ExportsMapper* exportsMap, IN const ModulesInfo& modulesInfo, IN const ULONGLONG module_start, IN ULONGLONG addr)
{
	if (addr == 0) {
		return "(invalid)";
	}
	if (!exportsMap) {
		return "";
	}
	const peconv::ExportedFunc* func = exportsMap->find_export_by_va(addr);
	if (func) {
		return func->toString();
	}
	const ScannedModule* modExp = modulesInfo.findModuleContaining(addr);
	if (!modExp) {
		if (module_start == 0) {
			return "(invalid)";
		}
		return "(unknown)";
	}
	std::stringstream report;
	report << peconv::get_dll_shortname(modExp->getModName());
	report << ".(unknown_func)";
	return report.str();
}

std::string IATScanReport::formatHookedFuncName(IN peconv::ImportsCollection* storedFunc, DWORD thunk_rva)
{
	if (!storedFunc) {
		return "(unknown)";
	}
	std::map<DWORD, peconv::ExportedFunc*>::const_iterator found = storedFunc->thunkToFunc.find(thunk_rva);
	if (found != storedFunc->thunkToFunc.end()) {
		const peconv::ExportedFunc* func = found->second;
		if (!func) {
			return ""; //this should not happen
		}
		return func->toString();
	}
	return "(unknown)";
	
}

bool IATScanReport::saveNotRecovered(IN std::string fileName,
	IN HANDLE hProcess,
	IN peconv::ImportsCollection *storedFunc,
	IN peconv::ImpsNotCovered &notCovered,
	IN const ModulesInfo &modulesInfo,
	IN const peconv::ExportsMapper *exportsMap)
{
	const char delim = ';';
	const char internal_delim = ':';

	if (notCovered.count() == 0) {
		return false;
	}
	std::ofstream report;
	report.open(fileName);
	if (report.is_open() == false) {
		return false;
	}

	std::map<DWORD,ULONGLONG>::iterator itr;
	for (itr = notCovered.thunkToAddr.begin(); itr != notCovered.thunkToAddr.end(); ++itr)
	{
		const DWORD thunk_rva = itr->first;
		const ULONGLONG addr = itr->second;
		report << std::hex << thunk_rva << delim;
		if (storedFunc) {
			report << "[" << formatHookedFuncName(storedFunc, thunk_rva) << "]";
			report << "->";
		}
		const ScannedModule* modExp = modulesInfo.findModuleContaining(addr);
		const ULONGLONG module_start = (modExp) ? modExp->getStart() : peconv::fetch_alloc_base(hProcess, (BYTE*)addr);
		const ULONGLONG offset = addr - module_start;
		report << std::hex << addr;
		report << "["
			<< std::hex << module_start << "+" << offset
			<< internal_delim
			<< formatTargetName(exportsMap, modulesInfo, module_start, addr);
		report << internal_delim;
		if (modExp) {
			report << modExp->isSuspicious();
		}
		else {
			report << true; // module not found, assume suspicious
		}
		report  << "]";
		report << std::endl;
	}
	report.close();
	return true;
}

bool IATScanReport::generateList(IN const std::string &fileName, IN HANDLE hProcess, IN const ModulesInfo &modulesInfo, IN const peconv::ExportsMapper *exportsMap)
{
	return saveNotRecovered(fileName,
		hProcess,
		&storedFunc,
		notCovered,
		modulesInfo,
		exportsMap);
}


template <typename FIELD_T>
FIELD_T get_thunk_at_rva(BYTE *mod_buf, size_t mod_size, DWORD rva)
{
	if (!mod_buf || !mod_size) {
		return 0;
	}
	if (!peconv::validate_ptr(mod_buf, mod_size, (BYTE*)((ULONG_PTR)mod_buf + rva), sizeof(FIELD_T))) {
		return 0;
	}

	FIELD_T* field_ptr = (FIELD_T*)((ULONG_PTR)mod_buf + rva);
	return (*field_ptr);
}

bool pesieve::IATScanner::isValidFuncFilled(ULONGLONG filled_val, const peconv::ExportedFunc& definedFunc, const peconv::ExportedFunc &possibleFunc)
{
	if (!peconv::ExportedFunc::isTheSameFuncName(possibleFunc, definedFunc)) {
		return false;
	}
	if (peconv::ExportedFunc::isTheSameDllName(possibleFunc, definedFunc)) {
		return true;
	}
	ULONGLONG dll_base = this->exportsMap.find_dll_base_by_func_va(filled_val);
	if (!dll_base) {
		return false; //could not find a DLL by this function value
	}
	// check for a common redirection to another system DLL:
	const std::string fullName = exportsMap.get_dll_path(dll_base);
	//std::cout << std::hex << filled_val << " : " << dll_base << " : " << fullName << " : " << definedFunc.toString() << " : " << defined_short  << " vs " << possible_short << "\n";
	if (isInSystemDir(fullName)) {
		return true;
	}
	return false;
}

bool pesieve::IATScanner::scanByOriginalTable(peconv::ImpsNotCovered &not_covered)
{
	if (!remoteModData.isInitialized()) {
		std::cerr << "[-] Failed to initialize remote module header" << std::endl;
		return false;
	}
	if (!moduleData.isInitialized() && !moduleData.loadOriginal()) {
		std::cerr << "[-] Failed to initialize module data: " << moduleData.szModName << std::endl;
		return false;
	}

	// first try to find by the Import Table in the original file:
	peconv::ImportsCollection collection;
	if (!listAllImports(collection)) {
		return false;
	}
	if (collection.size() == 0) {
		return true; //nothing to scan...
	}

	// load full remote for the IAT scan:
	if (!remoteModData.loadFullImage()) {
		std::cerr << "[-] Failed to initialize remote module" << std::endl;
		return false;
	}
	std::map<DWORD, peconv::ExportedFunc*>::iterator itr;
	// get filled thunks from the mapped module (remote):

	for (itr = collection.thunkToFunc.begin(); itr != collection.thunkToFunc.end(); ++itr) {
		DWORD thunk_rva = itr->first;

		//std::cout << "Thunk: " << std::hex << *itr << "\n";
		ULONGLONG filled_val = 0;
		if (moduleData.is64bit()) {
			filled_val = get_thunk_at_rva<ULONGLONG>(remoteModData.imgBuffer, remoteModData.imgBufferSize, thunk_rva);
		}
		else {
			filled_val = get_thunk_at_rva<DWORD>(remoteModData.imgBuffer, remoteModData.imgBufferSize, thunk_rva);
		}
		peconv::ExportedFunc* defined_func = itr->second;
		if (!defined_func) {
			// cannot retrieve the origial import
			continue;
		}

		const std::set<peconv::ExportedFunc>* possibleExports = exportsMap.find_exports_by_va(filled_val);
		// no export at this thunk:
		if (!possibleExports || possibleExports->size() == 0) {

			//filter out .NET: mscoree._CorExeMain
			const std::string dShortName = peconv::get_dll_shortname(defined_func->libName);
			if (dShortName == "mscoree" 
				&& (defined_func->funcName == "_CorExeMain" || defined_func->funcName == "_CorDllMain") )
			{
				continue; //this is normal, skip it
			}

			not_covered.insert(thunk_rva, filled_val);
#ifdef _DEBUG
			std::cout << "Function not covered: " << std::hex << thunk_rva << " [" << dShortName << "] func: [" << defined_func->funcName << "] val: " << std::hex << filled_val << "\n";
#endif
			continue;
		}

		// check if the defined import matches the possible ones:
		bool is_covered = false;
		std::set<peconv::ExportedFunc>::const_iterator cItr;
		for (cItr = possibleExports->begin(); cItr != possibleExports->end(); ++cItr) {
			const peconv::ExportedFunc possibleFunc = *cItr;
			if (isValidFuncFilled(filled_val, *defined_func, possibleFunc)){
				is_covered = true;
				break;
			}
		}

		if (!is_covered) {
			not_covered.insert(thunk_rva, filled_val);
#ifdef _DEBUG
			std::cout << "Mismatch at RVA: " << std::hex << thunk_rva << " " << defined_func->libName<< " func: " << defined_func->toString() << "\n";

			for (cItr = possibleExports->begin(); cItr != possibleExports->end(); ++cItr) {
				const peconv::ExportedFunc possibleFunc = *cItr;
				std::cout << "\t proposed: " << possibleFunc.libName << " : " << possibleFunc.toString() << "\n";
			}
#endif
		}
	}
	return true;
}

IATScanReport* pesieve::IATScanner::scanRemote()
{
	if (!remoteModData.isInitialized()) {
		std::cerr << "[-] Failed to initialize remote module header" << std::endl;
		return nullptr;
	}

	peconv::ImpsNotCovered not_covered;
	t_scan_status status = SCAN_NOT_SUSPICIOUS;

	if (!scanByOriginalTable(not_covered)) {
		// IAT scan failed:
		status = SCAN_ERROR;
	}

	if (not_covered.count() > 0) {
#ifdef _DEBUG
		std::cout << "[*] IAT: " << moduleData.szModName << " hooked: " << not_covered.count() << "\n";
#endif
		status = SCAN_SUSPICIOUS;
	}
	
	IATScanReport *report = new(std::nothrow) IATScanReport(remoteModData.modBaseAddr, remoteModData.getModuleSize(), moduleData.szModName);
	if (!report) {
		return nullptr;
	}

	if (not_covered.count()) {
		listAllImports(report->storedFunc);
	}
	if (this->hooksFilter != PE_IATS_UNFILTERED) {
		filterResults(not_covered, *report);
	}
	else {
		report->notCovered = not_covered;
	}
	report->status = status;
	if (report->countHooked() == 0) {
		report->status = SCAN_NOT_SUSPICIOUS;
	}
	return report;
}
///-------

void pesieve::IATScanner::initExcludedPaths()
{
	char sysWow64Path[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\SysWoW64", sysWow64Path, MAX_PATH);
	this->m_sysWow64Path_str = sysWow64Path;
	std::transform(m_sysWow64Path_str.begin(), m_sysWow64Path_str.end(), m_sysWow64Path_str.begin(), tolower);

	char system32Path[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32", system32Path, MAX_PATH);
	this->m_system32Path_str = system32Path;
	std::transform(m_system32Path_str.begin(), m_system32Path_str.end(), m_system32Path_str.begin(), tolower);
}

bool pesieve::IATScanner::isInSystemDir(const std::string &moduleName)
{
	std::string dirName = peconv::get_directory_name(moduleName);
	std::transform(dirName.begin(), dirName.end(), dirName.begin(), tolower);

	if (dirName == m_system32Path_str || dirName == m_sysWow64Path_str) {
		return true;
	}
	return false;
}

bool pesieve::IATScanner::filterResults(peconv::ImpsNotCovered &notCovered, IATScanReport &report)
{
	std::map<DWORD, ULONGLONG>::iterator itr;
	for (itr = notCovered.thunkToAddr.begin(); itr != notCovered.thunkToAddr.end(); ++itr)
	{
		const DWORD thunk = itr->first;
		const ULONGLONG addr = itr->second;

		ScannedModule *modExp = modulesInfo.findModuleContaining(addr);
		ULONGLONG module_start = (modExp) ? modExp->getStart() : peconv::fetch_alloc_base(this->processHandle, (BYTE*)addr);
		if (module_start == 0) {
			// invalid address of the hook
			report.notCovered.insert(thunk, addr);
			continue;
		}
		if (this->hooksFilter == PE_IATS_CLEAN_SYS_FILTERED) {
			// insert hooks leading to suspicious modules:
			if (modExp && modExp->isSuspicious()) {
				report.notCovered.insert(thunk, addr);
				continue;
			}
		}
		// filter out hooks leading to system DLLs
		std::string moduleName = this->exportsMap.get_dll_path(module_start);
		if (isInSystemDir(moduleName)) {
#ifdef _DEBUG
			std::cout << "Skipped: " << moduleName << "\n";
#endif
			continue;
		}
		// insert hooks leading to non-system modules:
		report.notCovered.insert(thunk, addr);
	}
	return true;
}

bool pesieve::IATScanner::listAllImports(peconv::ImportsCollection &_storedFunc)
{
	return moduleData.loadImportsList(_storedFunc);
}

