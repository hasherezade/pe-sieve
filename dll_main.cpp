#include <Windows.h>
#include <string>
#include <iostream>

#include "pe_sieve.h"
#include "dll_main.h"

#define LIB_NAME "PE-sieve"

t_report __stdcall scan(t_params args)
{
	const t_report report = check_modules_in_process(args);
	std::string report_str = report_to_string(report);
	std::cout << report_str;
	return report;
}

void __stdcall help(void)
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

