#pragma once

#include <windows.h>
#include <iostream>
#include <stdexcept>

#include <pe_sieve_version.h>
#include <pe_sieve_types.h>
#include "scanners/scan_report.h"
#include "postprocessors/dump_report.h"
#include "postprocessors/report_formatter.h"

namespace pesieve {

	class ReportEx {
	public:
		ReportEx() :
			scan_report(nullptr), dump_report(nullptr)
		{
		}

		~ReportEx()
		{
			delete scan_report;
			delete dump_report;
		}

		ProcessScanReport* scan_report;
		ProcessDumpReport* dump_report;
	};

	std::string info();

	ReportEx* scan_and_dump(IN const pesieve::t_params args);
};
