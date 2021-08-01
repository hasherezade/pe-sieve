#pragma once

#include "scan_report.h"
#include "code_scanner.h"

namespace pesieve {

	struct ScannedModuleInfo {
		ULONGLONG moduleAddr;
		size_t moduleSize;
		bool isSuspicious;
		std::string moduleName;
	};

	class HookTargetResolver
	{
	public:
		HookTargetResolver(ProcessScanReport& process_report, HANDLE processHandle)
			: mInfo(processHandle)
		{
			mapScannedModules(process_report);
		}

		size_t resolveAllHooks(const std::set<ModuleScanReport*> &code_reports);
		bool resolveTarget(PatchList::Patch* currPatch);

	protected:
		size_t mapScannedModules(ProcessScanReport& process_report);
		ModulesInfo mInfo;
	};

}; //namespace pesieve


