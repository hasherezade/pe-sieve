#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "../scanners/scan_report.h"
#include "../postprocessors/dump_report.h"

namespace pesieve {

	std::string scan_report_to_string(const ProcessScanReport &report);
	std::string scan_report_to_json(const ProcessScanReport &process_report, ProcessScanReport::t_report_filter filter, const pesieve::t_json_level &jdetails);

}; // namespace pesieve

