#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>

#include <peconv.h>
#include "module_scan_report.h"
#include "module_data.h"

#include "../utils/format_util.h"

namespace pesieve {

	class ModuleScanner {
	public:
		ModuleScanner(HANDLE _procHndl, ModuleData &_moduleData, RemoteModuleData &_remoteModData)
			: processHandle(_procHndl), moduleData(_moduleData), remoteModData(_remoteModData)
		{
		}
		virtual ~ModuleScanner() {}

		virtual ModuleScanReport* scanRemote() = 0;

	protected:
		HANDLE processHandle;
		ModuleData &moduleData;
		RemoteModuleData &remoteModData;
	};

}; //namespace pesieve
