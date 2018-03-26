#pragma once

#include <Windows.h>
#include <vector>
#include <fstream>

#include "peconv.h"

class PatchList {
public:
	class Patch
	{
	public:
		Patch(HMODULE module_base, size_t patch_id, DWORD start_rva)
			: moduleBase(module_base), id(patch_id), startRva(start_rva), endRva(start_rva),
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
		bool resolveHookedExport(peconv::ExportsMapper &expMap);

		size_t id;
		DWORD startRva;
		DWORD endRva;
		HMODULE moduleBase;

		bool is_hook;
		ULONGLONG hook_target_va;
		std::string hooked_func;

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
	
	//checks what are the names of the functions that have been hooked
	size_t checkForHookedExports(peconv::ExportsMapper &expMap);

	void deletePatches();

// variables:
	std::vector<Patch*> patches;
};
