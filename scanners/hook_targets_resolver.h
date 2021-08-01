#pragma once

#include "scan_report.h"
#include "code_scanner.h"

namespace pesieve {

	class HookTargetResolver
	{
	public:
		HookTargetResolver(ProcessScanReport& process_report)
			: mInfo(process_report.getPid()), processReport(process_report)
		{
			mapScannedModules(process_report);
		}

		size_t resolveAllHooks(const std::set<ModuleScanReport*> &code_reports);
		bool resolveTarget(PatchList::Patch* currPatch);

	protected:
		size_t mapScannedModules(ProcessScanReport& process_report);
		ModulesInfo mInfo;
		ProcessScanReport& processReport;
	};

}; //namespace pesieve


