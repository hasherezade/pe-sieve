#pragma once
#include <Windows.h>
#include <vector>
#include <fstream>

#include "module_scanner.h"
#include "pe_section.h"

class PatchList {
public:
	class Patch
	{
	public:
		Patch(size_t patch_id, DWORD start_rva)
			: id(patch_id), startRva(start_rva), endRva(start_rva),
			is_hook(false), hook_target_va(NULL)
		{
		}

		void setEnd(DWORD end_rva)
		{
			endRva = end_rva;
		}
		
		void setHookTarget(ULONGLONG target_va)
		{
			hook_target_va = target_va;
			is_hook = true;
		}

		bool reportPatch(std::ofstream &patch_report, const char delimiter);

	protected:
		size_t id;
		DWORD startRva;
		DWORD endRva;

		bool is_hook;
		ULONGLONG hook_target_va;


	friend class PatchList;
	friend class PatchAnalyzer;
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

class PatchAnalyzer
{
public:
	typedef enum {
		OP_JMP = 0xE9,
		OP_CALL_DWORD = 0xE8,
		OP_PUSH_DWORD = 0x68
	} t_hook_opcode;

	PatchAnalyzer(ModuleData &_moduleData,DWORD _sectionRVA, PBYTE patched_code, size_t code_size)
		: moduleData(_moduleData), sectionRVA(_sectionRVA), patchedCode(patched_code), codeSize(code_size)
	{
		isModule64bit = moduleData.is64bit();
	}

	size_t analyze(PatchList::Patch &patch);

protected:
	size_t parseJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
	size_t parseMovJmp(PatchList::Patch &patch, PBYTE patch_ptr,bool is_long);
	size_t parsePushRet(PatchList::Patch &patch, PBYTE patch_ptr);

	ULONGLONG PatchAnalyzer::getJmpDestAddr(ULONGLONG currVA, DWORD instrLen, DWORD lVal);
	bool is64Modifier(BYTE op);
	bool isLongModifier(BYTE op);

	bool isModule64bit;

	ModuleData &moduleData;
	DWORD sectionRVA;
	PBYTE patchedCode;
	size_t codeSize;
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
