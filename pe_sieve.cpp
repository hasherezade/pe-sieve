// Scans the process with a given PID
// author: hasherezade (hasherezade@gmail.com)

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

using namespace pesieve;
using namespace pesieve::util;

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

	HANDLE open_process(DWORD processID, bool reflection, bool quiet)
	{
		const DWORD basic_access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
		DWORD access = basic_access;
		if (reflection) {
			access |= pesieve::util::reflection_access;
		}
		HANDLE hProcess = OpenProcess(
			access,
			FALSE, processID
		);
		// success, return the handle:
		if (hProcess) {
			return hProcess;
		}
		if (access != basic_access) {
			// if failed, try to open with basic rights
			hProcess = OpenProcess(
				basic_access,
				FALSE, processID
			);
			// success, return the handle:
			if (hProcess) {
				return hProcess;
			}
		}
		DWORD last_err = GetLastError();
		if (last_err == ERROR_ACCESS_DENIED) {
			if (!quiet) {
				std::cerr << "[-][" << processID << "] Could not open the process Error: " << last_err << std::endl;
				//print more info:
				check_access_denied(processID);
			}

			SetLastError(ERROR_ACCESS_DENIED);
			throw std::runtime_error("Could not open the process");
			return nullptr;
		}
		if (last_err == ERROR_INVALID_PARAMETER) {
			if (!quiet) {
				std::cerr << "-> Is this process still running?" << std::endl;
			}
			SetLastError(ERROR_INVALID_PARAMETER);
			throw std::runtime_error("Could not open the process");
		}
		return hProcess;
	}

	bool is_scanner_compatible(IN HANDLE hProcess, bool quiet)
	{
		BOOL isCurrWow64 = FALSE;
		is_process_wow64(GetCurrentProcess(), &isCurrWow64);
		BOOL isRemoteWow64 = FALSE;
		is_process_wow64(hProcess, &isRemoteWow64);
		if (isCurrWow64 && !isRemoteWow64) {
			if (!quiet) {
				std::cerr << "-> Try to use the 64bit version of the scanner." << std::endl;
			}
			return false;
		}
		return true;
	}
};

pesieve::ProcessDumpReport* pesieve::dump_output(IN ProcessScanReport &process_report, IN const pesieve::t_params args, IN HANDLE hProcess)
{
	if (!hProcess) return nullptr;
	if (args.out_filter == OUT_NO_DIR) {
		return nullptr;
	}

	ProcessDumpReport* dumpReport = nullptr;
	ResultsDumper dumper(expand_path(args.output_dir), args.quiet);

	if (dumper.dumpJsonReport(process_report, ProcessScanReport::REPORT_SUSPICIOUS_AND_ERRORS) && !args.quiet) {
		std::cout << "[+] Report dumped to: " << dumper.getOutputDir() << std::endl;
	}
	size_t dumped_modules = 0;
	if (args.out_filter != OUT_NO_DUMPS) {
		pesieve::t_dump_mode dump_mode = pesieve::PE_DUMP_AUTO;
		if (args.dump_mode < peconv::PE_DUMP_MODES_COUNT) {
			dump_mode = pesieve::t_dump_mode(args.dump_mode);
		}
		dumpReport = dumper.dumpDetectedModules(hProcess, process_report, dump_mode, args.imprec_mode);
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
				if(!args.quiet) {
					std::cout << "[+] Minidump saved to: " << dumpReport->minidumpPath << std::endl;
				}
			}
			else if(!args.quiet){
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

pesieve::ReportEx* pesieve::scan_and_dump(IN const pesieve::t_params args)
{
	if (!set_debug_privilege()) {
		if (!args.quiet) std::cerr << "[-] Could not set debug privilege" << std::endl;
	}
	ReportEx *report = new ReportEx();
	HANDLE hProcess = nullptr;

	try {
		hProcess = open_process(args.pid, args.make_reflection, args.quiet);
		if (!is_scanner_compatible(hProcess, args.quiet)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			throw std::runtime_error("Scanner mismatch. Try to use the 64bit version of the scanner.");
		}
		HANDLE _pHndl = hProcess;
		HANDLE cloned_proc = NULL;
		if (args.make_reflection) {
			cloned_proc = make_process_reflection(hProcess);
			if (cloned_proc) {
				if (!args.quiet) std::cout << "Using process reflection!\n";
				_pHndl = cloned_proc;
			}
		}
		if (!cloned_proc) {
			if (!args.quiet) std::cout << "Using raw process!\n";
		}
		ProcessScanner scanner(_pHndl, args);
		report->scan_report = scanner.scanRemote();
		if (cloned_proc) {
			release_process_reflection(&cloned_proc);
		}
	}
	catch (std::exception &e) {
		if (!args.quiet) {
			std::cerr << "[ERROR] " << e.what() << std::endl;
		}
		return nullptr;

	}
	if (report->scan_report) {
		report->dump_report = dump_output(*report->scan_report, args, hProcess);
	}
	CloseHandle(hProcess);
	return report;
}

pesieve::ProcessScanReport* pesieve::scan_process(IN const t_params args, IN OPTIONAL HANDLE hProcess)
{
	if (!set_debug_privilege()) {
		if (!args.quiet) std::cerr << "[-] Could not set debug privilege" << std::endl;
	}

	bool autoopened = false;
	ProcessScanReport *process_report = nullptr;
	try {
		if (!hProcess) {
			hProcess = open_process(args.pid, args.make_reflection, args.quiet);
			autoopened = true;
		}
		if (!is_scanner_compatible(hProcess, args.quiet)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			throw std::runtime_error("Scanner mismatch. Try to use the 64bit version of the scanner.");
		}
		ProcessScanner scanner(hProcess, args);
		process_report = scanner.scanRemote();

	} catch (std::exception &e) {
		if(!args.quiet) {
			std::cerr << "[ERROR] " << e.what() << std::endl;
		}
		return nullptr;
		
	}
	if (autoopened) {
		CloseHandle(hProcess);
	}
	return process_report;
}

std::string pesieve::info()
{
	std::stringstream stream;
	stream << "Version:  " << PESIEVE_VERSION;
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
