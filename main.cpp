// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include <windows.h>
#include <psapi.h>
#include <sstream>
#include <fstream>

#include "pe_sieve.h"

#include "utils/process_privilege.h"
#include "params_info/pe_sieve_params_info.h"
#include "utils/process_reflection.h"
#include "utils/console_color.h"
#include "color_scheme.h"

#define PARAM_SWITCH1 '/'
#define PARAM_SWITCH2 '-'
//scan options:
#define PARAM_PID "pid"
#define PARAM_SHELLCODE "shellc"
#define PARAM_DATA "data"
#define PARAM_IAT "iat"
#define PARAM_MODULES_FILTER "mfilter"
#define PARAM_MODULES_IGNORE "mignore"
#define PARAM_REFLECTION "refl"
#define PARAM_DOTNET_POLICY "dnet"

//dump options:
#define PARAM_IMP_REC "imp"
#define PARAM_DUMP_MODE "dmode"
//output options:
#define PARAM_OUT_FILTER "ofilter"
#define PARAM_QUIET "quiet"
#define PARAM_JSON "json"
#define PARAM_DIR "dir"
#define PARAM_MINIDUMP "minidmp"
//info:
#define PARAM_HELP "help"
#define PARAM_HELP2  "?"
#define PARAM_VERSION "version"
#define PARAM_VERSION2 "ver"

using namespace pesieve;
using namespace pesieve::util;

void print_param_in_color(int color, const std::string &text)
{
	print_in_color(color, PARAM_SWITCH1 + text);
}

bool is_param(const char *str)
{
	if (!str) return false;

	const size_t len = strlen(str);
	if (len < 2) return false;

	if (str[0] == PARAM_SWITCH1 || str[0] == PARAM_SWITCH2) {
		return true;
	}
	return false;
}

size_t copyToCStr(char *buf, size_t buf_max, const std::string &value)
{
	size_t len = value.length() + 1;
	if (len > buf_max) len = buf_max;

	memset(buf, 0, buf_max);
	memcpy(buf, value.c_str(), len);
	buf[len] = '\0';
	return len;
}

//TODO: this will be replaced when params will be refactored to use ParamKit
template<typename PARAM_T>
bool get_int_param(int argc, char *argv[], const char *param, int &param_i,
	const char *param_id, PARAM_T &out_val, const PARAM_T default_set,
	bool &info_req, void(*callback)(int))
{
	if (strcmp(param, param_id) != 0) {
		return false;
	}
	out_val = default_set;
	if ((param_i + 1) < argc && !is_param(argv[param_i + 1])) {
		char* mode_num = argv[param_i + 1];
		if (is_number(mode_num)) {
			out_val = (PARAM_T)get_number(mode_num);
		}
		else {
			if (callback) {
				callback(ERROR_COLOR);
			}
			info_req = true;
		}
		++param_i;
	}
	return true;
}

//TODO: this will be replaced when params will be refactored to use ParamKit
bool get_cstr_param(int argc, char *argv[], const char *param, int &param_i,
	const char *param_id, char* out_buf, const size_t out_buf_max,
	bool &info_req, void(*callback)(int))
{
	if (strcmp(param, param_id) != 0) {
		return false;
	}
	bool fetched = false;
	if ((param_i + 1) < argc && !is_param(argv[param_i + 1])) {
		if (argv[param_i + 1][0] != PARAM_HELP2[0]) {
			copyToCStr(out_buf, out_buf_max, argv[param_i + 1]);
			fetched = true;
		}
		++param_i;
	}
	if (!fetched) {
		callback(ERROR_COLOR);
		info_req = true;
	}
	return true;
}

void print_dnet_param(int param_color)
{
	print_param_in_color(param_color, PARAM_DOTNET_POLICY);
	std::cout << " <*dotnet_policy>\n\t: Set the policy for scanning managed processes (.NET).\n";;
	std::cout << "*dotnet_policy:\n";
	for (size_t i = 0; i < PE_DNET_COUNT; i++) {
		t_dotnet_policy mode = (t_dotnet_policy)(i);
		std::cout << "\t" << mode << " - " << translate_dotnet_policy(mode) << "\n";
	}
}

void print_imprec_param(int param_color)
{
	print_param_in_color(param_color, PARAM_IMP_REC);
	std::cout << " <*imprec_mode>\n\t: Set in which mode the ImportTable should be recovered.\n";;
	std::cout << "*imprec_mode:\n";
	for (size_t i = 0; i < PE_IMPREC_MODES_COUNT; i++) {
		t_imprec_mode mode = (t_imprec_mode)(i);
		std::cout << "\t" << mode << " - " << translate_imprec_mode(mode) << "\n";
	}
}

void print_out_filter_param(int param_color)
{
	print_param_in_color(param_color, PARAM_OUT_FILTER);
	std::cout << " <*ofilter_id>\n\t: Filter the dumped output.\n";
	std::cout << "*ofilter_id:\n";
	for (size_t i = 0; i < OUT_FILTERS_COUNT; i++) {
		t_output_filter mode = (t_output_filter)(i);
		std::cout << "\t" << mode << " - " << translate_out_filter(mode) << "\n";
	}
}

void print_iat_param(int param_color)
{
	print_param_in_color(param_color, PARAM_IAT);
	std::cout << " <*scan_mode>\n\t: Scan for IAT hooks.\n";
	std::cout << "*scan_mode:\n";
	for (size_t i = 0; i < pesieve::PE_IATS_MODES_COUNT; i++) {
		std::cout << "\t" << i << " - " << translate_iat_scan_mode((pesieve::t_iat_scan_mode) i) << "\n";
	}
}

void print_dmode_param(int param_color)
{
	print_param_in_color(param_color, PARAM_DUMP_MODE);
	std::cout << " <*dump_mode>\n\t: Set in which mode the detected PE files should be dumped.\n";
	std::cout << "*dump_mode:\n";
	for (DWORD i = 0; i < peconv::PE_DUMP_MODES_COUNT; i++) {
		peconv::t_pe_dump_mode mode = (peconv::t_pe_dump_mode)(i);
		std::cout << "\t" << mode << " - " << translate_dump_mode(mode) << "\n";
	}
}

void print_shellc_param(int param_color)
{
	print_param_in_color(param_color, PARAM_SHELLCODE);
	std::cout << "\t: Detect shellcode implants. (By default it detects PE only).\n";
}

void print_module_filter_param(int param_color)
{
	print_param_in_color(param_color, PARAM_MODULES_FILTER);
	std::cout << " <*mfilter_id>\n\t: Filter the scanned modules.\n";
	std::cout << "*mfilter_id:\n";
	for (DWORD i = 0; i <= LIST_MODULES_ALL; i++) {
		std::cout << "\t" << i << " - " << translate_modules_filter(i) << "\n";
	}
}

void print_mignore_param(int param_color)
{
	print_param_in_color(param_color, PARAM_MODULES_IGNORE);
	std::cout << " <module_name>\n\t: Do not scan module/s with given name/s (separated by '" << PARAM_LIST_SEPARATOR << "').\n"
		"\t  Example: kernel32.dll" << PARAM_LIST_SEPARATOR << "user32.dll\n";
}

void print_refl_param(int param_color)
{
	if (pesieve::util::can_make_process_reflection()) {
		print_param_in_color(param_color, PARAM_REFLECTION);
		std::cout << "\t: Make a process reflection before scan.\n";
	}
}

void print_data_param(int param_color)
{
	print_param_in_color(param_color, PARAM_DATA);
	std::cout << " <*data_scan_mode>\n\t: Set if non-executable pages should be scanned.\n";
	std::cout << "*data_scan_mode:\n";
	for (DWORD i = 0; i < pesieve::PE_DATA_COUNT; i++) {
		std::cout << "\t" << i << " - " << translate_data_mode((pesieve::t_data_scan_mode) i) << "\n";
	}
}

void print_pid_param(int param_color)
{
	print_param_in_color(param_color, PARAM_PID);
	std::cout << " <target_pid>\n\t: Set the PID of the target process.\n\t(decimal, or hexadecimal with '0x' prefix)\n";
}

void print_json_param(int param_color)
{
	print_param_in_color(param_color, PARAM_JSON);
	std::cout << "\t: Print the JSON report as the summary.\n";
}

void print_quiet_param(int param_color)
{
	print_param_in_color(param_color, PARAM_QUIET);
	std::cout << "\t: Print only the summary. Do not log on stdout during the scan.\n";
}

void print_minidump_param(int param_color)
{
	print_param_in_color(param_color, PARAM_MINIDUMP);
	std::cout << ": Create a minidump of the full suspicious process.\n";
}

void print_output_dir_param(int param_color)
{
	print_param_in_color(param_color, PARAM_DIR);
	std::cout << " <output_dir>\n\t: Set a root directory for the output (default: current directory).\n";
}

void print_help()
{
	const int hdr_color = HEADER_COLOR;
	const int param_color = HILIGHTED_COLOR;
	const int separator_color = SEPARATOR_COLOR;

	print_in_color(hdr_color, "Required: \n");
	print_pid_param(param_color);

	print_in_color(hdr_color, "\nOptional: \n");

	print_in_color(separator_color, "\n---scan options---\n");
	print_iat_param(param_color);
	print_shellc_param(param_color);

	print_data_param(param_color);
#ifdef _WIN64
	print_module_filter_param(param_color);
#endif
	print_mignore_param(param_color);
	print_refl_param(param_color);
	print_dnet_param(param_color);

	print_in_color(separator_color, "\n---dump options---\n");
	print_imprec_param(param_color);
	print_dmode_param(param_color);

	print_in_color(separator_color, "\n---output options---\n");

	print_out_filter_param(param_color);

	print_quiet_param(param_color);
	print_json_param(param_color);

	print_minidump_param(param_color);
	print_output_dir_param(param_color);

	print_in_color(hdr_color, "\nInfo: \n");
	print_param_in_color(param_color, PARAM_HELP);
	std::cout << "    : Print this help.\n";
	print_param_in_color(param_color, PARAM_VERSION);
	std::cout << " : Print version number.\n";
	std::cout << "---" << std::endl;
}

void banner()
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
	print_in_color(2, logo);
	print_in_color(4, logo2);
	print_in_color(4, logo3);
	std::cout << "\n";
	std::cout << info();
	std::cout <<  "---\n";
	print_help();
}

void print_scan_report(const ProcessScanReport& report, const t_params args)
{
	std::string report_str;
	if (args.json_output) {
		report_str = scan_report_to_json(report, ProcessScanReport::REPORT_SUSPICIOUS_AND_ERRORS);
	} else {
		report_str = scan_report_to_string(report);
	}
	//summary:
	std::cout << report_str;
	if (!args.json_output) {
		std::cout << "---" << std::endl;
	}
}

void print_unknown_param(const char *param)
{
	print_in_color(WARNING_COLOR, "Invalid parameter: ");
	std::cout << param << "\n";
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
		if (!is_param(argv[i])) {
			if (i == 1 && is_number(argv[i])) {
				//allow for PID as a first parameter
				continue;
			}
			// if the argument didn't have a param switch, print info but do not exit
			print_unknown_param(argv[i]);
			continue;
		}
		const char *param = &argv[i][1];
		if (!strcmp(param, PARAM_HELP) || !strcmp(param, PARAM_HELP2)) {
			print_help();
			info_req = true;
		}
		else if (get_int_param<DWORD>(argc, argv, param, i,
			PARAM_PID,
			args.pid,
			0,
			info_req,
			print_pid_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_IMP_REC,
			args.imprec_mode,
			pesieve::PE_IMPREC_AUTO,
			info_req,
			print_imprec_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_OUT_FILTER,
			args.out_filter,
			pesieve::OUT_FULL,
			info_req,
			print_out_filter_param))
		{
			continue;
		}
		else if (get_int_param<DWORD>(argc, argv, param, i,
			PARAM_MODULES_FILTER,
			args.modules_filter,
			LIST_MODULES_ALL,
			info_req,
			print_module_filter_param))
		{
			continue;
		}
		else if (get_cstr_param(argc, argv, param, i,
			PARAM_MODULES_IGNORE,
			args.modules_ignored,
			_countof(args.modules_ignored),
			info_req,
			print_mignore_param))
		{
			continue;
		}
		else if (!strcmp(param, PARAM_VERSION) || !strcmp(param, PARAM_VERSION2)) {
			std::cout << PESIEVE_VERSION << "\n";
			info_req = true;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_QUIET,
			args.quiet,
			true,
			info_req,
			print_quiet_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_JSON,
			args.json_output,
			true,
			info_req,
			print_json_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_MINIDUMP,
			args.minidump,
			true,
			info_req,
			print_minidump_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_SHELLCODE,
			args.shellcode,
			true,
			info_req,
			print_shellc_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_REFLECTION,
			args.make_reflection,
			true,
			info_req,
			print_refl_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_IAT,
			args.iat,
			pesieve::PE_IATS_FILTERED,
			info_req,
			print_iat_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_DOTNET_POLICY,
			args.dotnet_policy,
			pesieve::PE_DNET_SKIP_MAPPING,
			info_req,
			print_dnet_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_DATA,
			args.data,
			pesieve::PE_DATA_SCAN_NO_DEP,
			info_req,
			print_data_param))
		{
			continue;
		}
		else if (get_int_param(argc, argv, param, i,
			PARAM_DUMP_MODE,
			args.dump_mode,
			pesieve::PE_DUMP_AUTO,
			info_req,
			print_dmode_param))
		{
			args.dump_mode = normalize_dump_mode(args.dump_mode);
			continue;
		}
		else if (get_cstr_param(argc, argv, param, i,
			PARAM_DIR,
			args.output_dir,
			_countof(args.output_dir),
			info_req,
			print_output_dir_param))
		{
			continue;
		}
		else {
			print_unknown_param(argv[i]);
			print_in_color(HILIGHTED_COLOR, "Available parameters:\n\n");
			print_help();
			return 0;
		}
	}
	// do not start scan if the info was requested:
	if (info_req) {
#ifdef _DEBUG
		system("pause");
#endif
		return 0; // info requested, pid not given. finish.
	}
	// if didn't received PID by explicit parameter, try to parse the first param of the app
	if (args.pid == 0) {
		if (argc >= 2 && is_number(argv[1])) args.pid = get_number(argv[1]);
		if (args.pid == 0) {
			print_help();
			return 0;
		}
	}
	//---
	if (!args.quiet) {
		std::cout << "PID: " << args.pid << std::endl;
		std::cout << "Modules filter: " << translate_modules_filter(args.modules_filter) << std::endl;
		std::cout << "Output filter: " << translate_out_filter(args.out_filter) << std::endl;
		std::cout << "Dump mode: " << translate_dump_mode(args.dump_mode) << std::endl;
	}
	pesieve::ReportEx* report = pesieve::scan_and_dump(args);
	if (report != nullptr) {
		print_scan_report(*report->scan_report, args);
		delete report;
		report = nullptr;
	}
#ifdef _DEBUG
	system("pause");
#endif
	return 0;
}
