#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pe_sieve_types.h"
#include "peconv.h"
#include "module_scan_report.h"
#include "scanned_modules.h"

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
		: pid(_pid), exportsMap(nullptr), errorsCount(0), modulesInfo(pid)
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
		if (report->moduleSize > 0) {
			modulesInfo.appendModule(new LoadedModule(report->pid, (ULONGLONG)report->module, report->moduleSize));
		}
		if (ModuleScanReport::get_scan_status(report) == SCAN_ERROR) {
			this->errorsCount++;
		}
		appendToType(report);
	}

	void appendToType(ModuleScanReport *report);

	bool hasModuleContaining(ULONGLONG page_addr)
	{
		if (modulesInfo.getModuleContaining(page_addr) == nullptr) {
			return false;
		}
		return true;
	}

	bool hasModule(ULONGLONG page_addr)
	{
		if (modulesInfo.getModuleAt(page_addr) == nullptr) {
			return false;
		}
		return true;
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

	ProcessModules modulesInfo;
	std::set<ModuleScanReport*> reports_by_type[REPORT_TYPES_COUNT];

	friend class ProcessScanner;
};
