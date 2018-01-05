#include <Windows.h>
#include <string>
#include <iostream>

#include "pe_sieve.h"

#define PESIEVE_EXPORTS
#include "pe_sieve_api.h"

#include "report_formatter.h"

#define LIB_NAME "PE-sieve"

t_report __stdcall PESieve_scan(t_params args)
{
	const ProcessScanReport* report = check_modules_in_process(args);
	if (report == nullptr) {
		t_report nullrep = { 0 };
		nullrep.pid = args.pid;
		nullrep.errors = 1;
		return nullrep;
	}
	t_report summary = report->summary;
	delete report;
	return summary;
}

void __stdcall PESieve_help(void)
{
	std::string my_info = info();

	std::cout << my_info;
	MessageBox(NULL, my_info.c_str(), LIB_NAME, MB_ICONINFORMATION);
}

BOOL WINAPI DllMain (HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

