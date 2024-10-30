/**
* @file
* @brief   The final report produced by PE-sieve.
*/

#pragma once

#include <windows.h>
#include <iostream>

#include "scanners/scan_report.h"
#include "postprocessors/dump_report.h"

namespace pesieve {

	class ErrorReport
	{
	public:
		ErrorReport(DWORD _pid, const std::string &_message)
			: pid(_pid), message(_message)
		{
		}

		const DWORD pid;
		const std::string message;
	};

	//! The final report about the actions performed on the process: scanning and dumping
	class ReportEx {
	public:
		ReportEx() :
			scan_report(nullptr), dump_report(nullptr), error_report(nullptr)
		{
		}

		~ReportEx()
		{
			delete scan_report;
			delete dump_report;
			delete error_report;
		}

		ProcessScanReport* scan_report; ///< the report aggregating the results of the performed scans
		ProcessDumpReport* dump_report; ///< the report aggregating the results of the performed dumps
		ErrorReport* error_report; ///< the report detailing on possible errors that prevented the scan
	};

};
