#pragma once

#include <Windows.h>
#include <vector>
#include <fstream>

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
