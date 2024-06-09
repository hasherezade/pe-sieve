#include "patch_list.h"

#include <iostream>
#include <sstream>

#include "../utils/format_util.h"

std::string  pesieve::PatchList::Patch::getFormattedName()
{
	std::stringstream stream;

	if (this->type == pesieve::PATCH_PADDING) {
		stream << "padding:";
		stream << std::hex << "0x" << (unsigned int)paddingVal;
		return stream.str();
	}
	if (this->type == pesieve::PATCH_BREAKPOINT) {
		stream << "breakpoint";
		return stream.str();
	}
	if (this->hooked_func.length() > 0) {
		stream << hooked_func;
	} else {
		switch (this->type) {
		case pesieve::HOOK_INLINE:
			stream << "hook_"; break;
		case pesieve::HOOK_ADDR_REPLACEMENT:
			stream << "addr_replaced_"; break;
		default:
			stream << "patch_"; break;
		}
		stream << id;
	}
	if (this->type != pesieve::PATCH_UNKNOWN) {
		stream << "->";
		if (this->isDirect) {
			stream << std::hex << hookTargetVA;
		}
		else {
			stream << "via:" << std::hex << hookTargetVA;
		}
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

const bool pesieve::PatchList::Patch::toTAG(std::ofstream &patch_report, const char delimiter)
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

const bool pesieve::PatchList::Patch::toJSON(std::stringstream &outs, size_t level, bool short_info)
{
	OUT_PADDED(outs, level, "{\n");

	OUT_PADDED(outs, (level + 1), "\"rva\" : ");
	outs << "\"" << std::hex << (ULONGLONG)startRva << "\"" << ",\n";

	OUT_PADDED(outs, (level + 1), "\"size\" : ");
	outs << std::dec << (ULONGLONG)(endRva - startRva);

	if (short_info) {
		outs << ",\n";
		OUT_PADDED(outs, (level + 1), "\"info\" : ");
		outs << "\"" << getFormattedName() << "\"";
	}
	else {
		outs << ",\n";
		const bool isHook = (this->type == pesieve::HOOK_INLINE || this->type == pesieve::HOOK_ADDR_REPLACEMENT);
		OUT_PADDED(outs, (level + 1), "\"is_hook\" : ");
		outs << std::dec << isHook;

		if (this->hooked_func.length() > 0) {
			outs << ",\n";
			OUT_PADDED(outs, (level + 1), "\"func_name\" : ");
			outs << "\"" << hooked_func << "\"";
		}
		if (isHook) {
			outs << ",\n";
			OUT_PADDED(outs, (level + 1), "\"hook_target\" : {\n");
			if (hookTargetModName.length() > 0) {
				OUT_PADDED(outs, (level + 2), "\"module_name\" : ");
				outs << "\"" << hookTargetModName << "\"" << ",\n";
			}
			OUT_PADDED(outs, (level + 2), "\"module\" : ");
			outs << "\"" << std::hex << (ULONGLONG)hookTargetModule << "\"" << ",\n";
			OUT_PADDED(outs, (level + 2), "\"rva\" : ");
			outs << "\"" << std::hex << (ULONGLONG)(hookTargetVA - hookTargetModule) << "\"" << ",\n";
			OUT_PADDED(outs, (level + 2), "\"status\" : ");
			outs << std::dec << (ULONGLONG)this->isTargetSuspicious << "\n";
			OUT_PADDED(outs, (level + 1), "}");
		}
	}

	outs << "\n";
	OUT_PADDED(outs, level, "}");
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

const size_t pesieve::PatchList::toTAGs(std::ofstream &patch_report, const char delimiter)
{
	std::vector<Patch*>::iterator itr;
	for (itr = patches.begin(); itr != patches.end(); ++itr) {
		Patch *patch = *itr;
		patch->toTAG(patch_report, delimiter);
	}
	return patches.size();
}

const bool pesieve::PatchList::toJSON(std::stringstream &outs, size_t level, bool short_info)
{
	if (patches.size() == 0) {
		return false;
	}
	bool is_first = true;
	OUT_PADDED(outs, level, "\"patches_list\" : [\n");
	std::vector<Patch*>::iterator itr;
	size_t id = 0;
	for (itr = patches.begin(); itr != patches.end(); ++itr, ++id) {
		if (!is_first) {
			outs << ",\n";
		}
		Patch *patch = *itr;
		patch->toJSON(outs, level + 1, short_info);
		is_first = false;
	}
	outs << "\n";
	OUT_PADDED(outs, level, "]");
	return true;
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
