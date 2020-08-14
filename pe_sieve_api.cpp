#include <windows.h>
#include <string>
#include <iostream>

#include "pe_sieve.h"

#define PESIEVE_EXPORTS
#include <pe_sieve_api.h>

#define LIB_NAME "PE-sieve"

PEsieve_report PESIEVE_API_FUNC PESieve_scan(const PEsieve_params args)
{
	const pesieve::ReportEx* report = pesieve::scan_and_dump(args);
	if (report == nullptr) {
		pesieve::t_report nullrep = { 0 };
		nullrep.pid = args.pid;
		nullrep.errors = pesieve::ERROR_SCAN_FAILURE;
		return nullrep;
	}
	pesieve::t_report summary = report->scan_report->generateSummary();
	delete report;
	return summary;
}

void PESIEVE_API_FUNC PESieve_help(void)
{
	std::string my_info = pesieve::info();

	std::cout << my_info;
	MessageBox(NULL, my_info.c_str(), LIB_NAME, MB_ICONINFORMATION);
}

extern const DWORD PESIEVE_API PESieve_version = pesieve::PESIEVE_VERSION_ID;
