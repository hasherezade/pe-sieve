#include "patch_list.h"

#include <iostream>

bool PatchList::Patch::reportPatch(std::ofstream &patch_report, const char delimiter)
{
	if (patch_report.is_open()) {
		patch_report << std::hex << startRva;
		patch_report << delimiter;
		if (this->is_hook) {
			patch_report << "hook_" << id;
			patch_report << "->" << std::hex << hook_target_va;
		} else {
			patch_report << "patch_" << id;
		}
		patch_report << delimiter;
		patch_report << (endRva - startRva);
		patch_report << delimiter;
		patch_report << hooked_func;
		patch_report << std::endl;
	} else {
		std::cout << std::hex << startRva << std::endl;
	}
	return true;
}

bool PatchList::Patch::resolveHookedExport(peconv::ExportsMapper &expMap)
{
	ULONGLONG patch_va = (ULONGLONG) this->moduleBase + this->startRva;
	const peconv::ExportedFunc *func = expMap.find_export_by_va(patch_va);
	if (func == nullptr) {
		return false; // not found
	}
	this->hooked_func = func->toString();
	return true;
}

size_t PatchList::reportPatches(std::ofstream &patch_report, const char delimiter)
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); itr++) {
		Patch *patch = *itr;
		patch->reportPatch(patch_report, delimiter);
	}
	return patches.size();
}

size_t PatchList::checkForHookedExports(peconv::ExportsMapper &expMap)
{
	size_t hookes_exports = 0;
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); itr++) {
		Patch *patch = *itr;
		if (patch->resolveHookedExport(expMap)) {
			hookes_exports++;
		}
	}
	return hookes_exports;
}

void PatchList::deletePatches()
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); itr++) {
		Patch *patch = *itr;
		delete patch;
	}
	this->patches.clear();
}

