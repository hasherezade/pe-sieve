#include "hook_targets_resolver.h"

#include "scan_report.h"
#include "code_scanner.h"

using namespace pesieve;

bool pesieve::HookTargetResolver::resolveTarget(PatchList::Patch* currPatch)
{
	if (!currPatch) return false;
	ULONGLONG searchedAddr = currPatch->getHookTargetVA();
	if (searchedAddr == 0) return false;
#ifdef _DEBUG
	std::cout << "Searching hook address: " << std::hex << searchedAddr << std::endl;
#endif
	std::map<ULONGLONG, ScannedModuleInfo>::iterator itr1;
	std::map<ULONGLONG, ScannedModuleInfo>::iterator lastEl = modulesMap.lower_bound(searchedAddr);
	for (itr1 = modulesMap.begin(); itr1 != lastEl; ++itr1) {
		ScannedModuleInfo &modInfo = itr1->second;
		ULONGLONG begin = modInfo.moduleAddr;
		ULONGLONG end = modInfo.moduleSize + begin;
#ifdef _DEBUG
		std::cout << "Searching hook in module: " << std::hex << begin << std::endl;
#endif
		if (searchedAddr >= begin && searchedAddr < end) {
#ifdef _DEBUG
			std::cout << "[+] Address found in module: " << std::hex << modInfo.moduleAddr << std::endl;
#endif
			currPatch->setHookTargetInfo(modInfo.moduleAddr, modInfo.isSuspicious, modInfo.moduleName);
			return true;
		}
	}
	return false;
}

size_t pesieve::HookTargetResolver::resolveAllHooks(const std::set<ModuleScanReport*> &code_reports)
{
	size_t resolved = 0;
	std::set<ModuleScanReport*>::iterator cItr;
	for (cItr = code_reports.begin(); cItr != code_reports.end(); ++cItr) {
		ModuleScanReport* modrep = *cItr;
		CodeScanReport *coderep = dynamic_cast<CodeScanReport*>(modrep);
		if (!coderep) continue;

		std::vector<PatchList::Patch*>::iterator patchItr;
		for (patchItr = coderep->patchesList.patches.begin();
			patchItr != coderep->patchesList.patches.end();
			++patchItr)
		{
			PatchList::Patch* currPatch = *patchItr;
			if (resolveTarget(currPatch)) {
				resolved++;
			}
		}
	}
	return resolved;
}

size_t pesieve::HookTargetResolver::mapScannedModules(ProcessScanReport& process_report, HANDLE hProcess)
{
	std::vector<ModuleScanReport*>::iterator modItr;
	for (modItr = process_report.moduleReports.begin(); modItr != process_report.moduleReports.end(); ++modItr) {
		ModuleScanReport* scanReport = *modItr;
		ScannedModuleInfo modInfo = { 0 };
		modInfo.moduleAddr = (ULONGLONG)scanReport->module;
		modInfo.moduleSize = scanReport->moduleSize;
		modInfo.isSuspicious = (scanReport->status) == SCAN_SUSPICIOUS ? true : false;

		std::map<ULONGLONG, ScannedModuleInfo>::iterator foundItr = modulesMap.find(modInfo.moduleAddr);
		if (foundItr != modulesMap.end()) {
			ScannedModuleInfo &info = foundItr->second;
			if (info.isSuspicious && !modInfo.isSuspicious) {
				continue; //already have this module listed as suspicious
			}
		}
		if (hProcess) {
			char moduleName[MAX_PATH] = { 0 };
			if (GetModuleBaseNameA(hProcess, (HMODULE)modInfo.moduleAddr, moduleName, sizeof(moduleName))) {
				modInfo.moduleName = moduleName;
			}
		}
		modulesMap[modInfo.moduleAddr] = modInfo;
	}
	return modulesMap.size();
}
