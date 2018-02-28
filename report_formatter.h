#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"

typedef enum report_filter {
	REPORT_ERRORS = 1,
	REPORT_NOT_SUSPICIOUS = 2,
	REPORT_SUSPICIOUS = 4,
	REPORT_SUSPICIOUS_AND_ERRORS = REPORT_ERRORS | REPORT_SUSPICIOUS,
	REPORT_ALL = REPORT_ERRORS | REPORT_NOT_SUSPICIOUS | REPORT_SUSPICIOUS
} t_report_filter;

std::string report_to_string(const ProcessScanReport &report);

std::string report_to_json(const ProcessScanReport &report, t_report_filter filter);
