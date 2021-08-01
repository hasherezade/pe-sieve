#include "hook_targets_resolver.h"
#include "scanned_modules.h"

#include "scan_report.h"
#include "code_scanner.h"

using namespace pesieve;

bool pesieve::HookTargetResolver::resolveTarget(PatchList::Patch* currPatch)
{
	if (!currPatch) return false;

	const ULONGLONG searchedAddr = currPatch->getHookTargetVA();
	const ScannedModule* foundMod = mInfo.findModuleContaining(searchedAddr);
	if (!foundMod) return false;

	currPatch->setHookTargetInfo(foundMod->getStart(), foundMod->isSuspicious(), foundMod->getModName());
	return true;
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

size_t pesieve::HookTargetResolver::mapScannedModules(ProcessScanReport& process_report)
{
	std::vector<ModuleScanReport*>::iterator modItr;
	for (modItr = process_report.moduleReports.begin(); modItr != process_report.moduleReports.end(); ++modItr) {
		ModuleScanReport* scanReport = *modItr;
		mInfo.appendToModulesList(scanReport);
	}
	return mInfo.count();
}
