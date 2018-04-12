// Scans for modified modules within the process of a given PID
// author: hasherezade (hasherezade@gmail.com)

#include "pe_sieve.h"
#include "peconv.h"

#include <Windows.h>
#include "scanners/scanner.h"

#include "utils/util.h"
#include "utils/process_privilege.h"
#include "results_dumper.h"

HANDLE open_process(DWORD processID)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,
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
				PROCESS_QUERY_INFORMATION |PROCESS_VM_READ,
				FALSE, processID
			);
			if (hProcess != nullptr) {
				return hProcess;
			}
		}
		std::cerr << "[-][" << processID << "] Could not open the process Error: " << last_err << std::endl;
		std::cerr << "-> Access denied. Try to run the scanner as Administrator." << std::endl;
		throw std::exception("Could not open the process", ERROR_ACCESS_DENIED);
		return nullptr;
	}
	if (last_err == ERROR_INVALID_PARAMETER) {
		std::cerr << "-> Is this process still running?" << std::endl;
		throw std::exception("Could not open the process", ERROR_INVALID_PARAMETER);
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

ProcessScanReport* check_modules_in_process(const t_params args)
{
	HANDLE hProcess = nullptr;
	ProcessScanReport *process_report = nullptr;
	try {
		hProcess = open_process(args.pid);
		if (!is_scaner_compatibile(hProcess)) {
			throw std::exception("Scanner mismatch. Try to use the 64bit version of the scanner.", ERROR_INVALID_PARAMETER);
		}

		ProcessScanner scanner(hProcess, args);
		process_report = scanner.scanRemote();

	} catch (std::exception &e) {
		std::cerr << "[ERROR] " << e.what() << std::endl;
		return nullptr;
		
	}

	if (process_report != nullptr && !(args.out_filter & OUT_NO_DIR)) {
		ResultsDumper dumper;
		if (!(args.out_filter & OUT_NO_DUMPS)) {
			if (dumper.dumpAllModified(hProcess, *process_report) > 0) {
				std::cout << "[+] Dumped modified to: " << dumper.dumpDir << std::endl;
			}
		}
		if (dumper.dumpJsonReport(*process_report, REPORT_SUSPICIOUS_AND_ERRORS)) {
			std::cout << "[+] Report dumped to: " << dumper.dumpDir << std::endl;
		}
	}
	CloseHandle(hProcess);
	return process_report;
}

std::string info()
{
	std::stringstream stream;
	stream << "version: " << VERSION;
#ifdef _WIN64
	stream << " (x64)" << "\n\n";
#else
	stream << " (x86)" << "\n\n";
#endif
	stream << "~ from hasherezade with love ~\n";
	stream << "Detects inline hooks and other in-memory PE modifications\n";
	stream << "URL: " << URL << "\n";
	return stream.str();
}

