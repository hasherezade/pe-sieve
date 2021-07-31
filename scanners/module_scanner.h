#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>

#include <peconv.h>
#include "module_scan_report.h"
#include "module_data.h"

#include "../utils/format_util.h"
#include "process_feature_scanner.h"

namespace pesieve {

	//!  A base class for all the scanners operating on module data.
	class ModuleScanner : public ProcessFeatureScanner {
	public:
		ModuleScanner(HANDLE _procHndl, ModuleData &_moduleData, RemoteModuleData &_remoteModData)
			: ProcessFeatureScanner(_procHndl),
			moduleData(_moduleData), remoteModData(_remoteModData)
		{
		}

		virtual ~ModuleScanner() {}

		virtual ModuleScanReport* scanRemote() = 0;

	protected:
		ModuleData &moduleData;
		RemoteModuleData &remoteModData;
	};

}; //namespace pesieve
