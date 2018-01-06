#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "scan_report.h"

typedef enum report_filter {
	REPORT_ERRORS = 1,
	REPORT_NOT_MODIFIED = 2,
	REPORT_MODIFIED = 4,
	REPORT_ALL = REPORT_ERRORS | REPORT_NOT_MODIFIED | REPORT_MODIFIED
} t_report_filter;

std::string report_to_string(const ProcessScanReport &report);

std::string report_to_json(const ProcessScanReport &report, t_report_filter filter);
