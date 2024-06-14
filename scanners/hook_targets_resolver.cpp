#include "hook_targets_resolver.h"
#include "scanned_modules.h"

#include "scan_report.h"
#include "code_scanner.h"
#include "../utils/process_symbols.h"

using namespace pesieve;

bool pesieve::HookTargetResolver::resolveTarget(PatchList::Patch* currPatch)
{
	if (!currPatch) return false;
	
	const bool useSymbols = true;
	const ULONGLONG searchedAddr = currPatch->getHookTargetVA();
	const ScannedModule* foundMod = processReport.getModuleContaining(searchedAddr);
	if (!foundMod) return false;

	if (useSymbols && hProcess) {
		CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 Displacement = { 0 };

		if (SymFromAddr(hProcess, searchedAddr, &Displacement, pSymbol)) {
			std::cout << std::dec << "[" << GetProcessId(hProcess) << "]" << std::hex << searchedAddr << " Sym: " << pSymbol->ModBase << " : " << pSymbol->Name << " disp: " << Displacement
				<< " Flags: " << pSymbol->Flags << " Tag: " << pSymbol->Tag << std::endl;
			if (pSymbol->Flags == SYMFLAG_CLR_TOKEN) std::cout << "CLR token!\n";
			std::stringstream ss;
			ss << foundMod->getModName() + "." << pSymbol->Name << "+" << std::hex << Displacement;
			currPatch->setHookTargetInfo(foundMod->getStart(), foundMod->isSuspicious(), ss.str());
			return true;
		}
		else {
			std::cerr << "Finding symbols failed!\n";
		}
	}
	if (processReport.exportsMap) {
		const peconv::ExportedFunc* expFunc = processReport.exportsMap->find_export_by_va(searchedAddr);
		if (expFunc) {
			const std::string targetName = foundMod->getModName() + "." + expFunc->nameToString();
			currPatch->setHookTargetInfo(foundMod->getStart(), foundMod->isSuspicious(), targetName);
			return true;
		}
	}
	currPatch->setHookTargetInfo(foundMod->getStart(), foundMod->isSuspicious(), foundMod->getModName());
	return true;
}

size_t pesieve::HookTargetResolver::resolveAllHooks(IN OUT std::set<ModuleScanReport*> &code_reports)
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
