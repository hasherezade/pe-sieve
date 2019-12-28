#pragma once
#include <Windows.h>
#include <vector>
#include <fstream>

#include "module_scanner.h"
#include "pe_section.h"
#include "patch_list.h"

class CodeScanReport : public ModuleScanReport
{
public:
	CodeScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize) {}

	const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		ModuleScanReport::toJSON(outs, level);
		outs << ",\n";
		if (patchesList.size() > 0) {
			OUT_PADDED(outs, level, "\"patches\" : ");
			outs << std::dec << patchesList.size();
			if (unpackedSections.size() > 0) {
				outs << ",\n";
			}
		}
		if (unpackedSections.size() > 0) {
			OUT_PADDED(outs, level, "\"unpacked_code_sections\" : ");
			outs << std::dec << unpackedSections.size();
		}
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"code_scan\" : {\n");
		fieldsToJSON(outs, level + 1);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}
	
	size_t generateTags(std::string reportPath);

	std::set<DWORD> unpackedSections;
	PatchList patchesList;
};

class CodeScanner : public ModuleScanner {
public:

	CodeScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
		: ModuleScanner(hProc, moduleData, remoteModData) { }

	virtual CodeScanReport* scanRemote();

private:
	size_t collectExecutableSections(RemoteModuleData &remoteModData, std::map<size_t, PeSection*> &sections);

	void freeExecutableSections(std::map<size_t, PeSection*> &sections);

	bool postProcessScan(IN OUT CodeScanReport &report);
	
	t_scan_status scanUsingBase(IN ULONGLONG load_base, IN std::map<size_t, PeSection*> &remote_code, OUT PatchList &patchesList);
	t_scan_status scanSection(PeSection &originalSec, PeSection &remoteSec, OUT PatchList &patchesList);

	bool clearIAT(PeSection &originalSec, PeSection &remoteSec);

	bool clearExports(PeSection &originalSec, PeSection &remoteSec);

	bool clearLoadConfig(PeSection &originalSec, PeSection &remoteSec);

	size_t collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList);
};

