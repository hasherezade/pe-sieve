/**
* @file
* @brief   The root of the PE-sieve scanner.
*/

#pragma once

#include <windows.h>
#include <iostream>
#include <stdexcept>

#include <pe_sieve_types.h>
#include <pe_sieve_return_codes.h>

#include "pe_sieve_ver_short.h"
#include "pe_sieve_report.h"
#include "postprocessors/report_formatter.h"

namespace pesieve {

	const char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

	//! The string with the basic information about the scanner.
	std::string info();

	//! The main action performed by PE-sieve: scanning the process and dumping the detected material.
	/**
	\param args : the configuration of the scan (defined as t_params)
	\return A pointer to the generated report (of type ReportEx)
	*/
	ReportEx* scan_and_dump(IN const pesieve::t_params args);
};
