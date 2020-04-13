#pragma once

#include <Windows.h>

#include "module_scanner.h"
#include "scanned_modules.h"

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
		hookedCount = 0;
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"iat_scan\" : ");
		outs << "{\n";
		ModuleScanReport::toJSON(outs, level + 1);
		outs << ",\n";
		OUT_PADDED(outs, level + 1, "\"hooks\" : ");
		outs << std::dec << hookedCount;
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}
	
	bool generateList(IN const std::string &fileName, IN HANDLE hProcess, IN const ProcessModules &modulesInfo, IN const peconv::ExportsMapper *exportsMap);

	std::map<ULONGLONG, peconv::ExportedFunc> storedFunc;
	peconv::ImpsNotCovered notCovered;
	size_t hookedCount;
};

//---

class IATScanner : public ModuleScanner {
public:

	IATScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData, const peconv::ExportsMapper &_exportsMap)
		: ModuleScanner(hProc, moduleData, remoteModData), exportsMap(_exportsMap) { }

	virtual IATScanReport* scanRemote();

private:
	bool filterResults(peconv::ImpsNotCovered &not_covered, IATScanReport &report);
	void listAllImports(std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc);

	const peconv::ExportsMapper &exportsMap;
};

