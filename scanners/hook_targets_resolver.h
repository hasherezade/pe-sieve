#pragma once

#include "scan_report.h"
#include "code_scanner.h"

namespace pesieve {

	//!  Processes the list of the collected patches (preprocessed by PatchAnalyzer), and for those of them that were detected as hooks, it resolves information about to which modules do they lead to.
	class HookTargetResolver
	{
	public:
		HookTargetResolver(IN ProcessScanReport& process_report)
			: processReport(process_report)
		{
		}

		//!  Resolves all the hooks collected within the given set of reports
		size_t resolveAllHooks(IN OUT std::set<ModuleScanReport*> &code_reports);

		//!  Resolves the information about the target of the provided hook, and fills it back into the object.
		bool resolveTarget(IN OUT PatchList::Patch* currPatch);

	protected:
		ProcessScanReport& processReport;
	};

}; //namespace pesieve


