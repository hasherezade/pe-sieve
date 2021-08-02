/**
* @file
* @brief   The root of the PE-sieve scanner.
*/

#pragma once

#include <windows.h>
#include <iostream>
#include <stdexcept>

#include <pe_sieve_version.h>
#include <pe_sieve_types.h>
#include <pe_sieve_return_codes.h>

#include "scanners/scan_report.h"
#include "postprocessors/dump_report.h"
#include "postprocessors/report_formatter.h"

namespace pesieve {

	//! The final report about the actions performed on the process: scanning and dumping
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

		ProcessScanReport* scan_report; ///< the report aggregating the results of the performed scans
		ProcessDumpReport* dump_report; ///< the report aggregating the results of the performed dumps
	};

	//! The string with the basic information about the scanner.
	std::string info();

	//! The main action performed by PE-sieve: scanning the process and dumping the detected material.
	/**
	\param args : the configuration of the scan (defined as t_params)
	\return A pointer to the generated report (of type ReportEx)
	*/
	ReportEx* scan_and_dump(IN const pesieve::t_params args);
};
