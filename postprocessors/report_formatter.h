#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "../pe_sieve_report.h"

namespace pesieve {

	std::string scan_report_to_string(const ProcessScanReport &report);
	std::string scan_report_to_json(const ProcessScanReport& process_report,t_results_filter filter, const pesieve::t_json_level& jdetails, size_t start_level=0);
	std::string dump_report_to_json(const ProcessDumpReport& process_report, const pesieve::t_json_level& jdetails, size_t start_level=0);

	std::string err_report_to_json(const ErrorReport& err_report, t_results_filter filter, size_t start_level = 0);
	std::string report_to_json(const ReportEx& report, const t_report_type rtype, t_results_filter filter, const pesieve::t_json_level& jdetails, size_t start_level=0);

}; // namespace pesieve

