#include "patch_list.h"

#include <iostream>
#include <sstream>

std::string  pesieve::PatchList::Patch::getFormattedName()
{
	std::stringstream stream;

	if (this->hooked_func.length() > 0) {
		stream << hooked_func;
	} else {
		if (this->isHook) {
			stream << "hook_" << id;
		} else {
			stream << "patch_" << id;
		}
	}
	if (this->isHook) {
		stream << "->" << std::hex << hookTargetVA;
	}
	if (this->hookTargetModule) {
		ULONGLONG diff = hookTargetVA - hookTargetModule;
		stream << "[";
		stream << std::hex << hookTargetModule;
		stream << "+" << diff << ":";
		if (hookTargetModName.length() > 0) {
			stream << hookTargetModName;
		}
		else {
			stream << "(unnamed)";
		}
		stream << ":" << isTargetSuspicious;
		stream << "]";
	}
	return stream.str();
}

bool  pesieve::PatchList::Patch::reportPatch(std::ofstream &patch_report, const char delimiter)
{
	if (patch_report.is_open()) {
		patch_report << std::hex << startRva;
		patch_report << delimiter;
		patch_report << getFormattedName();
		patch_report << delimiter;
		patch_report << (endRva - startRva);

		patch_report << std::endl;
	} else {
		std::cout << std::hex << startRva << std::endl;
	}
	return true;
}

bool  pesieve::PatchList::Patch::resolveHookedExport(peconv::ExportsMapper &expMap)
{
	ULONGLONG patch_va = (ULONGLONG) this->moduleBase + this->startRva;
	const peconv::ExportedFunc *func = expMap.find_export_by_va(patch_va);
	if (func == nullptr) {
		return false; // not found
	}
	this->hooked_func = func->nameToString();
	return true;
}

size_t  pesieve::PatchList::reportPatches(std::ofstream &patch_report, const char delimiter)
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); ++itr) {
		Patch *patch = *itr;
		patch->reportPatch(patch_report, delimiter);
	}
	return patches.size();
}

size_t  pesieve::PatchList::checkForHookedExports(peconv::ExportsMapper &expMap)
{
	size_t hookes_exports = 0;
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); ++itr) {
		Patch *patch = *itr;
		if (patch->resolveHookedExport(expMap)) {
			hookes_exports++;
		}
	}
	return hookes_exports;
}

void  pesieve::PatchList::deletePatches()
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); ++itr) {
		Patch *patch = *itr;
		delete patch;
	}
	this->patches.clear();
}

