/**
* @file
* @brief   The main file of PE-sieve built as an EXE
*/

#include <windows.h>
#include <psapi.h>
#include <sstream>
#include <fstream>

#include "pe_sieve.h"
#include "params.h"

#include "utils/process_privilege.h"
#include "params_info/pe_sieve_params_info.h"
#include "utils/process_reflection.h"
#include "utils/console_color.h"
#include "color_scheme.h"


using namespace pesieve;
using namespace pesieve::util;

void banner(PEsieveParams &uParams)
{
	char logo[] = "\
.______    _______           _______. __   ___________    ____  _______ \n\
|   _  \\  |   ____|         /       ||  | |   ____\\   \\  /   / |   ____|\n\
|  |_)  | |  |__    ______ |   (----`|  | |  |__   \\   \\/   /  |  |__   \n\
|   ___/  |   __|  |______| \\   \\    |  | |   __|   \\      /   |   __|  \n\
|  |      |  |____      .----)   |   |  | |  |____   \\    /    |  |____ \n\
| _|      |_______|     |_______/    |__| |_______|   \\__/     |_______|\n";

	char logo2[] = "\
  _        _______       _______      __   _______     __       _______ \n";
	char logo3[] = "\
________________________________________________________________________\n";
	paramkit::print_in_color(2, logo);
	paramkit::print_in_color(4, logo2);
	paramkit::print_in_color(4, logo3);
	std::cout << "\n";
	std::cout << info();
	std::cout <<  "---\n";
	uParams.info();
}

void print_report(const pesieve::ReportEx& report, const t_params args)
{
	if (!report.scan_report) return;

	std::string report_str;
	if (args.json_output) {
		report_str = scan_report_to_json(*report.scan_report, ProcessScanReport::REPORT_SUSPICIOUS_AND_ERRORS, args.json_lvl);
	} else {
		report_str = scan_report_to_string(*report.scan_report);
	}
	//summary:
	std::cout << report_str;
	if (!args.json_output) {
		std::cout << "---" << std::endl;
	}
}

int main(int argc, char *argv[])
{

	//---
	bool info_req = false;
	t_params args = { 0 };

	PEsieveParams uParams;
	if (argc < 2) {
		banner(uParams);
		system("pause");
		return PESIEVE_INFO;
	}
	if (!uParams.parse(argc, argv) || !uParams.hasRequiredFilled()) {
		return 0;
	}
	uParams.fillStruct(args);
	//---
	if (!args.quiet) {
		std::cout << "PID: " << args.pid << std::endl;
		std::cout << "Output filter: " << translate_out_filter(args.out_filter) << std::endl;
		std::cout << "Dump mode: " << translate_dump_mode(args.dump_mode) << std::endl;
	}
	pesieve::ReportEx* report = pesieve::scan_and_dump(args);
	t_pesieve_res res = PESIEVE_ERROR;
	if (report != nullptr) {
		print_report(*report, args);

		pesieve::t_report summary = report->scan_report->generateSummary();
		if (summary.scanned > 0) {
			res = (summary.suspicious > 0) ? PESIEVE_DETECTED : PESIEVE_NOT_DETECTED;
		}
		delete report;
		report = nullptr;
	}
#ifdef _DEBUG
	system("pause");
#endif
	return res;
}
