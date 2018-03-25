// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <fstream>

#include "utils/process_privilege.h"

#include "utils/util.h"

#include "peconv.h"
#include "pe_sieve.h"

#define PARAM_PID "/pid"
#define PARAM_MODULES_FILTER "/mfilter"
#define PARAM_IMP_REC "/imp"
#define PARAM_OUT_FILTER "/ofilter"
#define PARAM_HELP "/help"
#define PARAM_HELP2  "/?"
#define PARAM_VERSION  "/version"
#define PARAM_QUIET "/quiet"
#define PARAM_JSON "/json"

void print_in_color(int color, std::string text)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	FlushConsoleInputBuffer(hConsole);
	SetConsoleTextAttribute(hConsole, color); // back to default color
	std::cout << text;
	FlushConsoleInputBuffer(hConsole);
	SetConsoleTextAttribute(hConsole, 7); // back to default color
}

void print_help()
{
	const int hdr_color = 14;
	const int param_color = 15;
	print_in_color(hdr_color, "Required: \n");
	print_in_color(param_color, PARAM_PID);
	std::cout << " <target_pid>\n\t: Set the PID of the target process.\n";

	print_in_color(hdr_color, "\nOptional: \n");
	print_in_color(param_color, PARAM_IMP_REC);
	std::cout << "\t: Enable recovering imports. ";
	std::cout << "(Warning: it may slow down the scan)\n";
#ifdef _WIN64
	print_in_color(param_color, PARAM_MODULES_FILTER);
	std::cout << " <*mfilter_id>\n\t: Filter the scanned modules.\n";
	std::cout << "*mfilter_id:\n\t0 - no filter\n\t1 - 32bit\n\t2 - 64bit\n\t3 - all (default)\n";
#endif
	print_in_color(param_color, PARAM_OUT_FILTER);
	std::cout << " <*ofilter_id>\n\t: Filter the dumped output.\n";
	std::cout << "*ofilter_id:\n\t0 - no filter: dump everything (default)\n\t1 - don't dump the modified PEs, but file the report\n\t2 - don't create the output directory at all\n";

	print_in_color(param_color, PARAM_QUIET);
	std::cout << "\t: Print only the summary. Do not log on stdout during the scan.\n";
	print_in_color(param_color, PARAM_JSON);
	std::cout << "\t: Print the JSON report as the summary.\n";

	print_in_color(hdr_color, "\nInfo: \n");
	print_in_color(param_color, PARAM_HELP);
	std::cout << "    : Print this help.\n";
	print_in_color(param_color, PARAM_VERSION);
	std::cout << " : Print version number.\n";
	std::cout << "---" << std::endl;
}

void banner()
{
	const int logo_color = 25;
	char logo[] = "\
.______    _______           _______. __   ___________    ____  _______ \n\
|   _  \\  |   ____|         /       ||  | |   ____\\   \\  /   / |   ____|\n\
|  |_)  | |  |__    ______ |   (----`|  | |  |__   \\   \\/   /  |  |__   \n\
|   ___/  |   __|  |______| \\   \\    |  | |   __|   \\      /   |   __|  \n\
|  |      |  |____      .----)   |   |  | |  |____   \\    /    |  |____ \n\
| _|      |_______|     |_______/    |__| |_______|   \\__/     |_______|\n\
  _        _______       _______      __   _______     __       _______ \n";

	print_in_color(logo_color, logo);
	std::cout << info();
	std::cout <<  "---\n";
	print_help();
}

void print_report(const ProcessScanReport& report, const t_params args)
{
	std::string report_str;
	if (args.json_output) {
		report_str = report_to_json(report, REPORT_SUSPICIOUS_AND_ERRORS);
	} else {
		report_str = report_to_string(report);
	}
	//summary:
	const t_report &summary = report.summary;
	std::cout << report_str;
	if (!args.json_output) {
		std::cout << "---" << std::endl;
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		banner();
		system("pause");
		return 0;
	}
	//---
	bool info_req = false;
	t_params args = { 0 };
	args.modules_filter = LIST_MODULES_ALL;

	//Parse parameters
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], PARAM_HELP) || !strcmp(argv[i], PARAM_HELP2)) {
			print_help();
			info_req = true;
		}
		else if (!strcmp(argv[i], PARAM_IMP_REC)) {
			args.imp_rec = true;
		}
		else if (!strcmp(argv[i], PARAM_OUT_FILTER)) {
			args.out_filter = static_cast<t_output_filter>(atoi(argv[i + 1]));
			i++;
		} 
		else if (!strcmp(argv[i], PARAM_MODULES_FILTER) && i < argc) {
			args.modules_filter = atoi(argv[i + 1]);
			if (args.modules_filter > LIST_MODULES_ALL) {
				args.modules_filter = LIST_MODULES_ALL;
			}
			i++;
		}
		else if (!strcmp(argv[i], PARAM_PID) && i < argc) {
			args.pid = atoi(argv[i + 1]);
			++i;
		}
		else if (!strcmp(argv[i], PARAM_VERSION)) {
			std::cout << VERSION << std::endl;
			info_req = true;
		}
		else if (!strcmp(argv[i], PARAM_QUIET)) {
			args.quiet = true;
		}
		else if (!strcmp(argv[i], PARAM_JSON)) {
			args.json_output = true;
		}
	}
	//if didn't received PID by explicit parameter, try to parse the first param of the app
	if (args.pid == 0) {
		if (info_req) {
#ifdef _DEBUG
			system("pause");
#endif
			return 0; // info requested, pid not given. finish.
		}
		if (argc >= 2) args.pid = atoi(argv[1]);
		if (args.pid == 0) {
			print_help();
			return 0;
		}
	}
	//---
	if (!args.quiet) {
		std::cout << "PID: " << args.pid << std::endl;
		std::cout << "Modules filter: " << args.modules_filter << std::endl;
		std::cout << "Output filter: " << args.out_filter << std::endl;
	}
	ProcessScanReport* report = check_modules_in_process(args);
	if (report != nullptr) {
		print_report(*report, args);
		delete report;
		report = nullptr;
	}
#ifdef _DEBUG
	system("pause");
#endif
	return 0;
}
