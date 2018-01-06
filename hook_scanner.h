#pragma once
#include <Windows.h>
#include <vector>

#include "scanner.h"

class PatchList {
public:
	class Patch
	{
	public:
		Patch(size_t patch_id, DWORD start_rva)
			: id(patch_id), startRva(start_rva), endRva(start_rva)
		{
		}

		void setEnd(DWORD end_rva)
		{
			endRva = end_rva;
		}

		bool reportPatch(std::ofstream &patch_report, const char delimiter);

	protected:
		size_t id;
		DWORD startRva;
		DWORD endRva;

	friend class PatchList;
	};

	//constructor:
	PatchList() {}

	//destructor:
	virtual ~PatchList() {
		deletePatches();
	}

	void insert(Patch *p)
	{
		patches.push_back(p);
	}

	size_t size()
	{
		return patches.size();
	}

	size_t reportPatches(std::ofstream &patch_report, const char delimiter);

	void deletePatches();

// variables:
	std::vector<Patch*> patches;
};

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

	PatchList patchesList;
};

class HookScanner : public ModuleScanner {
public:

	HookScanner(HANDLE hProc)
		: ModuleScanner(hProc) { }

	virtual CodeScanReport* scanRemote(ModuleData &moduleData);

private:
	t_scan_status scanSection(PBYTE modBaseAddr, PBYTE original_module, size_t module_size, size_t section_number, IN CodeScanReport &report);

	bool clearIAT(PIMAGE_SECTION_HEADER section_hdr, PBYTE original_module, PBYTE loaded_code);

	size_t collectPatches(DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList);
};
