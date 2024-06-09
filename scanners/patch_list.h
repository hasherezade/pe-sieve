#pragma once

#include <windows.h>
#include <vector>
#include <fstream>

#include <peconv.h>

namespace pesieve {

	typedef enum {
		PATCH_UNKNOWN,
		HOOK_INLINE,
		HOOK_ADDR_REPLACEMENT,
		PATCH_PADDING,
		PATCH_BREAKPOINT,
		COUNT_PATCH_TYPES
	} t_patch_type;

	class PatchList {
	public:
		class Patch
		{
		public:
			Patch(HMODULE module_base, size_t patch_id, DWORD start_rva)
				: moduleBase(module_base), id(patch_id), startRva(start_rva), endRva(start_rva),
				type(pesieve::PATCH_UNKNOWN),
				isDirect(true), 
				hookTargetVA(0), hookTargetModule(0), isTargetSuspicious(false),
				paddingVal(0)
			{
			}

			Patch(const Patch& other)
			{
				id = other.id;
				startRva = other.startRva;
				endRva = other.endRva;
				moduleBase = other.moduleBase;

				isDirect = other.isDirect;
				type = other.type;
				hookTargetVA = other.hookTargetVA;
				hooked_func = other.hooked_func;

				hookTargetModule = other.hookTargetModule;
				isTargetSuspicious = other.isTargetSuspicious;
				hookTargetModName = other.hookTargetModName;
				paddingVal = other.paddingVal;
			}

			void setEnd(DWORD end_rva)
			{
				endRva = end_rva;
			}

			void setHookTarget(ULONGLONG target_va, bool is_direct = true, t_patch_type hook_type = pesieve::HOOK_INLINE)
			{
				hookTargetVA = target_va;
				isDirect = is_direct;
				this->type = hook_type;
			}

			ULONGLONG getHookTargetVA()
			{
				return hookTargetVA;
			}

			bool setHookTargetInfo(ULONGLONG targetModuleBase, bool isSuspiocious, std::string targetModuleName)
			{
				if (type == pesieve::PATCH_UNKNOWN || targetModuleBase == 0 || targetModuleBase > this->hookTargetVA) {
					return false;
				}
				this->hookTargetModule = targetModuleBase;
				this->isTargetSuspicious = isSuspiocious;
				this->hookTargetModName = targetModuleName;
				return true;
			}

			const bool toTAG(std::ofstream &patch_report, const char delimiter);
			const bool toJSON(std::stringstream &outs, size_t level, bool short_info);

		protected:
			bool resolveHookedExport(peconv::ExportsMapper &expMap);

			std::string getFormattedName();

			size_t id;
			DWORD startRva;
			DWORD endRva;
			HMODULE moduleBase;

			t_patch_type type;
			bool isDirect;
			ULONGLONG hookTargetVA;
			BYTE paddingVal;
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
			for (itr = other.patches.begin(); itr != other.patches.end(); ++itr) {
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

		const size_t toTAGs(std::ofstream &patch_report, const char delimiter);

		const bool toJSON(std::stringstream &outs, size_t level, bool short_info);

		//checks what are the names of the functions that have been hooked
		size_t checkForHookedExports(peconv::ExportsMapper &expMap);

		void deletePatches();

		// variables:
		std::vector<Patch*> patches;
	};

}; //namespace pesieve

