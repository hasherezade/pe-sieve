#include "pe_sieve.h"
#include <peconv.h>

#include <windows.h>
#include "scanners/scanner.h"

#include "utils/format_util.h"
#include "utils/process_util.h"
#include "utils/process_privilege.h"
#include "utils/process_minidump.h"
#include "utils/path_converter.h"
#include "postprocessors/results_dumper.h"
#include "utils/process_reflection.h"
#include "utils/console_color.h"
#include "color_scheme.h"

#include "utils/artefacts_util.h"

using namespace pesieve;
using namespace pesieve::util;

pesieve::PatternMatcher g_Matcher;

namespace pesieve {
	void check_access_denied(DWORD processID)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
		if (!hProcess) {
			std::cerr << "-> Access denied. Try to run the scanner as Administrator." << std::endl;
			return;
		}
		process_integrity_t level = get_integrity_level(hProcess);
		switch (level) {
		case INTEGRITY_UNKNOWN:
			std::cerr << "-> Access denied. Could not query the process token." << std::endl;
			break;
		case INTEGRITY_SYSTEM:
			std::cerr << "-> Access denied. Could not access the system process." << std::endl;
			break;
		default:
			break;
		}
		CloseHandle(hProcess);
		hProcess = NULL;
	}

	bool is_scanner_compatible(IN HANDLE hProcess)
	{
		BOOL isCurrWow64 = FALSE;
		is_process_wow64(GetCurrentProcess(), &isCurrWow64);
		
		BOOL isRemoteWow64 = FALSE;
		is_process_wow64(hProcess, &isRemoteWow64);

		if (isCurrWow64 && !isRemoteWow64) {
			return false;
		}
		return true;
	}

	// throws std::runtime_error if opening the process failed
	HANDLE open_process(DWORD processID, bool reflection, bool quiet)
	{
		const DWORD basic_access = SYNCHRONIZE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
		DWORD access = basic_access;
		if (reflection) {
			access |= pesieve::util::reflection_access | PROCESS_VM_OPERATION;
		}

		HANDLE hProcess = OpenProcess(access, FALSE, processID);

		// if failed, try to open with the lower reflection access
		if (!hProcess && access != basic_access && access != pesieve::util::reflection_access1) {
			hProcess = OpenProcess(pesieve::util::reflection_access1, FALSE, processID);
		}

		// if failed, try to open with basic rights
		if (!hProcess && access != basic_access) {
			hProcess = OpenProcess( basic_access, FALSE, processID);
		}

		// check process compatibility
		if (hProcess && !is_scanner_compatible(hProcess) && !quiet) {
			util::print_in_color(WARNING_COLOR, "[!] Scanner mismatch! Try to use the 64bit version of the scanner!\n", true);
		}

		// opening succeeded, return the handle:
		if (hProcess) {
			return hProcess;
		}

		const DWORD last_err = GetLastError();

		if (last_err == ERROR_ACCESS_DENIED) {
			if (!quiet) {
				std::cerr << "[-][" << processID << "] Could not open the process Error: " << last_err << std::endl;
				//print more info:
				check_access_denied(processID);
			}

			SetLastError(ERROR_ACCESS_DENIED);
			throw std::runtime_error("Could not open the process: Access Denied");
			return nullptr;
		}
		if (last_err == ERROR_INVALID_PARAMETER) {
			if (!quiet) {
				std::cerr << "-> Is this process still running?" << std::endl;
			}
			SetLastError(ERROR_INVALID_PARAMETER);
			throw std::runtime_error("Could not open the process: Invalid Parameter");
		}
		return hProcess;
	}

	pesieve::ProcessDumpReport* make_dump(IN HANDLE hProcess, IN bool isRefl, IN const pesieve::t_params &args, IN ProcessScanReport &process_report)
	{
		if (!hProcess) {
			return nullptr;
		}
		if (args.out_filter == OUT_NO_DIR) {
			// dumping disabled
			return nullptr;
		}
		ProcessDumpReport* dumpReport = nullptr;
		ResultsDumper dumper(expand_path(args.output_dir), args.quiet);

		if (dumper.dumpJsonReport(process_report, ProcessScanReport::REPORT_SUSPICIOUS_AND_ERRORS, args.json_lvl) && !args.quiet) {
			std::cout << "[+] Report dumped to: " << dumper.getOutputDir() << std::endl;
		}
		
		if (args.out_filter != OUT_NO_DUMPS) {
			pesieve::t_dump_mode dump_mode = pesieve::PE_DUMP_AUTO;
			if (args.dump_mode < peconv::PE_DUMP_MODES_COUNT) {
				dump_mode = pesieve::t_dump_mode(args.dump_mode);
			}
			size_t dumped_modules = 0;
			dumpReport = dumper.dumpDetectedModules(hProcess, isRefl, process_report, dump_mode, args.imprec_mode);
			if (dumpReport && dumpReport->countDumped()) {
				dumped_modules = dumpReport->countDumped();
			}
			if (!args.quiet && dumped_modules) {
				std::cout << "[+] Dumped modified to: " << dumper.getOutputDir() << std::endl;
			}
		}
		if (args.minidump) {
			pesieve::t_report report = process_report.generateSummary();
			if (report.suspicious > 0) {
				if (!args.quiet) {
					std::cout << "[*] Creating minidump..." << std::endl;
				}
				std::string original_path = process_report.mainImagePath;
				std::string file_name = peconv::get_file_name(original_path);
				std::string dump_file = dumper.makeOutPath(file_name + ".dmp");
				if (make_minidump(process_report.getPid(), dump_file)) {
					if (!dumpReport) {
						dumpReport = new ProcessDumpReport(process_report.getPid());
					}
					dumpReport->minidumpPath = dump_file;
					if (!args.quiet) {
						std::cout << "[+] Minidump saved to: " << dumpReport->minidumpPath << std::endl;
					}
				}
				else if (!args.quiet) {
					std::cout << "[-] Creating minidump failed! " << std::endl;
				}
			}
		}
		if (dumpReport) {
			dumpReport->outputDir = dumper.getOutputDir();
			if (dumper.dumpJsonReport(*dumpReport) && !args.quiet) {
				std::cout << "[+] Report dumped to: " << dumper.getOutputDir() << std::endl;
			}
		}
		return dumpReport;
	}

}; //namespace pesieve


namespace pesieve {

	inline bool is_by_patterns(const t_shellc_mode& shellc_mode)
	{
		switch (shellc_mode) {
		case  SHELLC_PATTERNS:
		case  SHELLC_PATTERNS_OR_STATS:
		case SHELLC_PATTERNS_AND_STATS:
			return true;
		}
		return false;
	}

}; // namespace pesieve

pesieve::ReportEx* pesieve::scan_and_dump(IN const pesieve::t_params args)
{
	ReportEx *report = new(std::nothrow) ReportEx();
	if (!report) {
		// should not happen
		return nullptr;
	}
	HANDLE orig_proc = nullptr; // original process handle
	HANDLE cloned_proc = nullptr; // process reflection handle

	if (!set_debug_privilege()) {
		if (!args.quiet) std::cerr << "[-] Could not set debug privilege" << std::endl;
	}

	if (args.pattern_file.length) {
		size_t loaded = g_Matcher.loadPatternFile(args.pattern_file.buffer);
		if (!args.quiet) {
			if (loaded) std::cout << "[+] Pattern file loaded: " << args.pattern_file.buffer << ", Signs: " << loaded << std::endl;
			else std::cerr << "[-] Failed to load pattern file: " << args.pattern_file.buffer << std::endl;
		}
	}
	if (is_by_patterns(args.shellcode)) {
		g_Matcher.initShellcodePatterns();
	}
	
	try {
		orig_proc = open_process(args.pid, args.make_reflection, args.quiet);
		HANDLE target_proc = orig_proc;

		if (args.make_reflection) {
			cloned_proc = make_process_reflection(orig_proc);
			if (cloned_proc) {
				target_proc = cloned_proc;
			}
			else {
				if (!args.quiet) std::cerr << "[-] Failed to create the process reflection" << std::endl;
			}
		}

		if (!args.quiet) {
			if (cloned_proc) {
				std::cout << "[*] Using process reflection!\n";
			}
			else {
				std::cout << "[*] Using raw process!\n";
				if (args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
					print_in_color(WARNING_COLOR, "[WARNING] Scanning of inaccessible pages is possible only in reflection mode!\n");
				}
			}
		}

		const bool is_reflection = (cloned_proc) ? true : false;
		ProcessScanner scanner(target_proc, is_reflection, args);
		report->scan_report = scanner.scanRemote();

		if (report->scan_report) {
			// dump elements from the process:
			report->dump_report = make_dump(target_proc, is_reflection, args, *report->scan_report);
		}
	}
	catch (std::exception &e) {
		delete report;
		report = nullptr;

		if (!args.quiet) {
			util::print_in_color(ERROR_COLOR, std::string("[ERROR] ") + e.what() + "\n", true);
		}
	}
	if (cloned_proc) {
		release_process_reflection(&cloned_proc);
	}
	CloseHandle(orig_proc);
	return report;
}

std::string pesieve::info()
{
	std::stringstream stream;
	stream << "Version:  " << PESIEVE_VERSION_STR;
#ifdef _WIN64
	stream << " (x64)" << "\n";
#else
	stream << " (x86)" << "\n";
#endif
	stream << "Built on: " << __DATE__ << "\n\n";
	stream << "~ from hasherezade with love ~\n";
	stream << "Scans a given process, recognizes and dumps a variety of in-memory implants:\nreplaced/injected PEs, shellcodes, inline hooks, patches etc.\n";
	stream << "URL: " << PESIEVE_URL << "\n";
	return stream.str();
}
