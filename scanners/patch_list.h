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
			isHook(false), hookTargetVA(0), hookTargetModule(0), isTargetSuspicious(false)
		{
		}

		void setEnd(DWORD end_rva)
		{
			endRva = end_rva;
		}
		
		void setHookTarget(ULONGLONG target_va)
		{
			hookTargetVA = target_va;
			isHook = true;
		}

		ULONGLONG getHookTargetVA()
		{
			return hookTargetVA;
		}

		bool setHookTargetInfo(ULONGLONG targetModuleBase, bool isSuspiocious, std::string targetModuleName)
		{
			if (!isHook || targetModuleBase == 0 || targetModuleBase > this->hookTargetVA) {
				return false;
			}
			this->hookTargetModule = targetModuleBase;
			this->isTargetSuspicious = isSuspiocious;
			this->hookTargetModName = targetModuleName;
			return true;
		}

		bool reportPatch(std::ofstream &patch_report, const char delimiter);

	protected:
		bool resolveHookedExport(peconv::ExportsMapper &expMap);

		std::string getFormattedName();

		size_t id;
		DWORD startRva;
		DWORD endRva;
		HMODULE moduleBase;

		bool isHook;
		ULONGLONG hookTargetVA;
		std::string hooked_func;

		ULONGLONG hookTargetModule;
		bool isTargetSuspicious;
		std::string hookTargetModName;

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
