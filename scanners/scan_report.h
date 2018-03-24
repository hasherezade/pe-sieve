#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pe_sieve_types.h"
#include "peconv.h"
#include "module_scan_report.h"

class ProcessScanReport
{
public:
	ProcessScanReport(DWORD pid)
	{
		memset(&summary,0,sizeof(summary));
		summary.pid = pid;
		exportsMap = nullptr;
	}

	~ProcessScanReport()
	{
		deleteModuleReports();
		if (exportsMap) {
			delete exportsMap;
		}
	}

	void appendReport(ModuleScanReport *report)
	{
		if (report == nullptr) return;
		module_reports.push_back(report);
		scanned_modules.insert(report->module);
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			summary.suspicious++;
		}
		if (ModuleScanReport::get_scan_status(report) == SCAN_ERROR) {
			summary.errors++;
		}
	}

	bool hasModule(HMODULE page_addr)
	{
		if (scanned_modules.find(page_addr) != scanned_modules.end()) {
			return true; // already scanned this module
		}
		return false; // not scanned yet
	}

	t_report summary;
	std::vector<ModuleScanReport*> module_reports; //TODO: make it protected
	peconv::ExportsMapper *exportsMap;
	std::set<HMODULE> scanned_modules;

	std::string mainImagePath;

protected:
	void deleteModuleReports()
	{
		std::vector<ModuleScanReport*>::iterator itr = module_reports.begin();
		for (; itr != module_reports.end(); itr++) {
			ModuleScanReport* module = *itr;
			delete module;
		}
		module_reports.clear();
	}
};
