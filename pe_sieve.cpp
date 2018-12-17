// Scans the process with a given PID
// author: hasherezade (hasherezade@gmail.com)

#include "pe_sieve.h"
#include "peconv.h"

#include <Windows.h>
#include "scanners/scanner.h"

#include "utils/util.h"
#include "utils/process_privilege.h"
#include "postprocessors/results_dumper.h"

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
			std::cerr << "-> Access denied. Try to run the scanner as Administrator." << std::endl;
			break;
	}
	CloseHandle(hProcess);
	hProcess = NULL;
}

HANDLE open_process(DWORD processID)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE, processID
	);
	if (hProcess != nullptr) {
		return hProcess;
	}
	DWORD last_err = GetLastError();
	if (last_err == ERROR_ACCESS_DENIED) {
		if (set_debug_privilege(processID)) {
			//try again to open
			hProcess = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE, processID
			);
			if (hProcess != nullptr) {
				return hProcess;
			}
		}
		std::cerr << "[-][" << processID << "] Could not open the process Error: " << last_err << std::endl;
		//print more info:
		check_access_denied(processID);

		SetLastError(ERROR_ACCESS_DENIED);
		throw std::runtime_error("Could not open the process");
		return nullptr;
	}
	if (last_err == ERROR_INVALID_PARAMETER) {
		std::cerr << "-> Is this process still running?" << std::endl;
		SetLastError(ERROR_INVALID_PARAMETER);
		throw std::runtime_error("Could not open the process");
	}
	return hProcess;
}

bool is_scaner_compatibile(HANDLE hProcess)
{
	BOOL isCurrWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isCurrWow64);
	BOOL isRemoteWow64 = FALSE;
	IsWow64Process(hProcess, &isRemoteWow64);
	if (isCurrWow64 && !isRemoteWow64) {
		std::cerr << "-> Try to use the 64bit version of the scanner." << std::endl;
		return false;
	}
	return true;
}

size_t dump_output(ProcessScanReport *process_report, HANDLE hProcess, const t_params args)
{
	if (!process_report || !hProcess) return 0;
	if (args.out_filter == OUT_NO_DIR) {
		return 0;
	}
	ResultsDumper dumper(args.output_dir, args.quiet);

	if (dumper.dumpJsonReport(*process_report, REPORT_SUSPICIOUS_AND_ERRORS)) {
		std::cout << "[+] Report dumped to: " << dumper.dumpDir << std::endl;
	}
	size_t dumped_modules = 0;
	if (args.out_filter != OUT_NO_DUMPS) {
		peconv::t_pe_dump_mode dump_mode = peconv::PE_DUMP_AUTO;
		if (args.dump_mode < peconv::PE_DUMP_MODES_COUNT) {
			dump_mode = peconv::t_pe_dump_mode(args.dump_mode);
		}
		dumped_modules = dumper.dumpAllModified(hProcess, *process_report, dump_mode);
		if (dumped_modules) {
			std::cout << "[+] Dumped modified to: " << dumper.dumpDir << std::endl;
		}
	}
	return dumped_modules;
}

ProcessScanReport* scan_process(const t_params args)
{
	HANDLE hProcess = nullptr;
	ProcessScanReport *process_report = nullptr;
	try {
		hProcess = open_process(args.pid);
		if (!is_scaner_compatibile(hProcess)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			throw std::runtime_error("Scanner mismatch. Try to use the 64bit version of the scanner.");
		}

		ProcessScanner scanner(hProcess, args);
		process_report = scanner.scanRemote();

	} catch (std::exception &e) {
		std::cerr << "[ERROR] " << e.what() << std::endl;
		return nullptr;
		
	}
	dump_output(process_report, hProcess, args);
	CloseHandle(hProcess);
	return process_report;
}

std::string info()
{
	std::stringstream stream;
	stream << "version: " << PESIEVE_VERSION;
#ifdef _WIN64
	stream << " (x64)" << "\n\n";
#else
	stream << " (x86)" << "\n\n";
#endif
	stream << "~ from hasherezade with love ~\n";
	stream << "Scans a given process, recognizes and dumps a variety of in-memory implants:\nreplaced/injected PEs, shellcodes, inline hooks, patches etc.\n";
	stream << "URL: " << PESIEVE_URL << "\n";
	return stream.str();
}

