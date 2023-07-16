#pragma once

#include <windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <peconv.h>
#include "pe_sieve_types.h"
#include "module_scan_report.h"
#include "scanned_modules.h"

namespace pesieve {

	//! The report aggregating the results of the performed scan
	class ProcessScanReport
	{
	public:
		typedef enum {
			REPORT_MAPPING_SCAN,
			REPORT_HEADERS_SCAN,
			REPORT_CODE_SCAN,
			REPORT_MEMPAGE_SCAN,
			REPORT_ARTEFACT_SCAN,
			REPORT_UNREACHABLE_SCAN,
			REPORT_SKIPPED_SCAN,
			REPORT_IAT_SCAN,
			REPORT_THREADS_SCAN,
			REPORT_TYPES_COUNT
		} t_report_type;

		typedef enum {
			REPORT_ERRORS = 1,
			REPORT_NOT_SUSPICIOUS = 2,
			REPORT_SUSPICIOUS = 4,
			REPORT_SUSPICIOUS_AND_ERRORS = REPORT_ERRORS | REPORT_SUSPICIOUS,
			REPORT_ALL = REPORT_ERRORS | REPORT_NOT_SUSPICIOUS | REPORT_SUSPICIOUS
		} t_report_filter;

		static t_report_type getReportType(ModuleScanReport *report);

		ProcessScanReport(DWORD _pid, bool _is64bit, bool _isReflection, t_params* _usedParams)
			: pid(_pid), exportsMap(nullptr), errorsCount(0), modulesInfo(pid), isManaged(false), is64bit(_is64bit), 
			isReflection(_isReflection), usedParams(_usedParams)
		{
		}

		~ProcessScanReport()
		{
			deleteModuleReports();
			delete exportsMap;
		}

		void appendReport(ModuleScanReport *report)
		{
			if (report == nullptr) return;
			moduleReports.push_back(report);
			if (ModuleScanReport::get_scan_status(report) == SCAN_ERROR) {
				this->errorsCount++;
			}
			appendToType(report);
			// if the scan was successful, append the module to the scanned modules:
			if (ModuleScanReport::get_scan_status(report) != SCAN_ERROR) {
				modulesInfo.appendToModulesList(report);
			}
		}

		size_t getScannedSize(ULONGLONG address) const
		{
			return modulesInfo.getScannedSize(address);
		}

		bool hasModule(ULONGLONG page_addr)
		{
			if (!modulesInfo.getModuleAt(page_addr)) {
				return false;
			}
			return true;
		}

		bool hasModuleContaining(ULONGLONG page_addr, size_t size)
		{
			if (!modulesInfo.findModuleContaining(page_addr, size)) {
				return false;
			}
			return true;
		}

		bool isModuleReplaced(HMODULE module_base);

		ScannedModule* getModuleContaining(ULONGLONG field_addr, size_t field_size = 0) const
		{
			return modulesInfo.findModuleContaining(field_addr, field_size);
		}

		const virtual bool toJSON(std::stringstream &stream, size_t level, const t_report_filter &filter, const pesieve::t_json_level &jdetails) const;

		pesieve::t_report generateSummary() const;
		DWORD getPid() { return pid; }
		bool isManagedProcess() { return this->isManaged; }

		std::string mainImagePath;
		std::vector<ModuleScanReport*> moduleReports; //TODO: make it protected
		peconv::ExportsMapper *exportsMap;

	protected:
		std::string listModules(size_t level, const ProcessScanReport::t_report_filter &filter, const t_json_level &jdetails) const;

		void deleteModuleReports()
		{
			std::vector<ModuleScanReport*>::iterator itr = moduleReports.begin();
			for (; itr != moduleReports.end(); ++itr) {
				ModuleScanReport* module = *itr;
				delete module;
			}
			moduleReports.clear();
		}
	
		void appendToType(ModuleScanReport *report);
		size_t countResultsPerType(const t_report_type type, const t_scan_status result) const;

		size_t countSuspiciousPerType(const t_report_type type) const
		{
			return countResultsPerType(type, SCAN_SUSPICIOUS);
		}

		size_t countHdrsReplaced() const;
		bool hasAnyShownType(const ProcessScanReport::t_report_filter &filter);

		DWORD pid;
		bool is64bit;
		bool isManaged;
		bool isReflection;
		t_params* usedParams;
		size_t errorsCount;

		ModulesInfo modulesInfo;
		std::set<ModuleScanReport*> reportsByType[REPORT_TYPES_COUNT];

		friend class ProcessScanner;
		friend class ResultsDumper;
	};

}; //namespace pesieve
