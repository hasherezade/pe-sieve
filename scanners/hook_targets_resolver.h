#pragma once

#include "scan_report.h"
#include "code_scanner.h"

namespace pesieve {

	//!  Process the list of collected patches (preprocessed by PatchAnalyzer), and for those of them that were detected as hooks, it resolves information to which modules do they lead to.
	class HookTargetResolver
	{
	public:
		HookTargetResolver(IN ProcessScanReport& process_report)
			: processReport(process_report)
		{
		}

		size_t resolveAllHooks(const std::set<ModuleScanReport*> &code_reports);
		bool resolveTarget(PatchList::Patch* currPatch);

	protected:
		ProcessScanReport& processReport;
	};

}; //namespace pesieve


