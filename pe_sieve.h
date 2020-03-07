#pragma once

#include <windows.h>
#include <iostream>
#include <stdexcept>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"
#include "postprocessors/dump_report.h"
#include "postprocessors/report_formatter.h"

static char PESIEVE_VERSION[] = "0.2.4.1";
static DWORD PESIEVE_VERSION_ID = 0x00020401; // 00 02 04 01
static char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

class PeSieveReport {
public:
	PeSieveReport():
		scan_report(nullptr), dump_report(nullptr)
	{
	}

	~PeSieveReport()
	{
		delete scan_report;
		delete dump_report;
	}

	ProcessScanReport* scan_report;
	ProcessDumpReport* dump_report;
};

std::string info();

PeSieveReport* scan_and_dump(const pesieve::t_params args);

ProcessScanReport* scan_process(const pesieve::t_params args, HANDLE hProcess);
ProcessDumpReport* dump_output(ProcessScanReport &process_report, const pesieve::t_params args, HANDLE hProcess);
