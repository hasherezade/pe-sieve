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
	CodeScanReport(HANDLE processHandle, HMODULE _module)
		: ModuleScanReport(processHandle, _module) {}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"code_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"patches\" : "; 
		outs << std::dec << patchesList.size();
		outs << "\n}";
		return true;
	}
	
	size_t generateTags(std::string reportPath);

	PatchList patchesList;
};

class HookScanner : public ModuleScanner {
public:

	HookScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
		: ModuleScanner(hProc, moduleData, remoteModData) { }

	virtual CodeScanReport* scanRemote();

private:
	t_scan_status scanSection(size_t section_number, IN CodeScanReport &report);

	bool clearIAT(PeSection &originalSec, PeSection &remoteSec);

	size_t collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList);
};
