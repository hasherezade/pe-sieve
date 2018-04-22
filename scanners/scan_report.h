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
	typedef enum {
		REPORT_MAPPING_SCAN,
		REPORT_HEADERS_SCAN,
		REPORT_CODE_SCAN,
		REPORT_MEMPAGE_SCAN,
		REPORT_UNREACHABLE_SCAN,
		REPORT_SKIPPED_SCAN,
		REPORT_TYPES_COUNT
	} report_type_t;

	ProcessScanReport(DWORD _pid)
		: pid(_pid), exportsMap(nullptr), errorsCount(0)
	{
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
		appendToType(report);
	}

	void appendToType(ModuleScanReport *report);

	bool hasModule(HMODULE page_addr)
	{
		if (scanned_modules.find(page_addr) != scanned_modules.end()) {
			return true; // already scanned this module
		}
		return false; // not scanned yet
	}

	t_report generateSummary() const;

	std::string mainImagePath;
	std::vector<ModuleScanReport*> module_reports; //TODO: make it protected
	peconv::ExportsMapper *exportsMap;

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

	size_t countSuspiciousPerType(report_type_t type) const;

	DWORD pid;
	size_t errorsCount;

	std::set<HMODULE> scanned_modules;
	std::set<ModuleScanReport*> reports_by_type[REPORT_TYPES_COUNT];

	friend class ProcessScanner;
};
