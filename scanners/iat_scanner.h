#pragma once

#include <windows.h>

#include "module_scanner.h"
#include "scanned_modules.h"

namespace pesieve {

	class IATScanReport : public ModuleScanReport
	{
	public:

		static bool saveNotRecovered(IN std::string fileName,
			IN HANDLE hProcess,
			IN const std::map<ULONGLONG, peconv::ExportedFunc> *storedFunc,
			IN peconv::ImpsNotCovered &notCovered,
			IN const ProcessModules &modulesInfo,
			IN const peconv::ExportsMapper *exportsMap);

		IATScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(processHandle, _module, _moduleSize, SCAN_SUSPICIOUS)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			OUT_PADDED(outs, level, "\"iat_scan\" : ");
			outs << "{\n";
			ModuleScanReport::toJSON(outs, level + 1);
			outs << ",\n";
			OUT_PADDED(outs, level + 1, "\"hooks\" : ");
			outs << std::dec << countHooked();
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		bool generateList(IN const std::string &fileName, IN HANDLE hProcess, IN const ProcessModules &modulesInfo, IN const peconv::ExportsMapper *exportsMap);

		size_t countHooked() { return notCovered.count(); }

		std::map<ULONGLONG, peconv::ExportedFunc> storedFunc;
		peconv::ImpsNotCovered notCovered;

	};

	//---

	class IATScanner : public ModuleScanner {
	public:

		IATScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData, const peconv::ExportsMapper &_exportsMap, IN const ProcessModules &_modulesInfo, bool _filterSystemHooks)
			: ModuleScanner(hProc, moduleData, remoteModData),
			exportsMap(_exportsMap), modulesInfo(_modulesInfo),
			filterSystemHooks(_filterSystemHooks)
		{
		}

		virtual IATScanReport* scanRemote();

	private:
		bool hasImportTable(RemoteModuleData &remoteModData);
		bool filterResults(peconv::ImpsNotCovered &not_covered, IATScanReport &report);
		void listAllImports(std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc);

		const peconv::ExportsMapper &exportsMap;
		const ProcessModules &modulesInfo;

		bool filterSystemHooks;
	};

}; //namespace pesieve

