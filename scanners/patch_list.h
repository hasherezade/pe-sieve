#pragma once

#include <windows.h>
#include <vector>
#include <fstream>

#include <peconv.h>

namespace pesieve {

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

			Patch(const Patch& other)
			{
				id = other.id;
				startRva = other.startRva;
				endRva = other.endRva;
				moduleBase = other.moduleBase;

				isHook = other.isHook;
				hookTargetVA = other.hookTargetVA;
				hooked_func = other.hooked_func;

				hookTargetModule = other.hookTargetModule;
				isTargetSuspicious = other.isTargetSuspicious;
				hookTargetModName = other.hookTargetModName;
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

		PatchList & operator=(const PatchList &other)
		{
			deletePatches();
			std::vector<Patch*>::const_iterator itr;
			for (itr = other.patches.begin(); itr != other.patches.end(); itr++) {
				Patch* next = *itr;
				Patch* nextCopy = new Patch(*next);
				patches.push_back(nextCopy);
			}
			return *this;
		}

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

}; //namespace pesieve

