#pragma once

#include "scan_report.h"
#include "code_scanner.h"

namespace pesieve {

	class HookTargetResolver
	{
	public:
		HookTargetResolver(ProcessScanReport& process_report)
			: processReport(process_report)
		{
		}

		size_t resolveAllHooks(const std::set<ModuleScanReport*> &code_reports);
		bool resolveTarget(PatchList::Patch* currPatch);

	protected:
		ProcessScanReport& processReport;
	};

}; //namespace pesieve


