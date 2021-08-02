/**
* @file
* @brief   The main file of PE-sieve built as a DLL
*/

#include <windows.h>
#include <string>
#include <iostream>

#define PESIEVE_EXPORTS
#include <pe_sieve_api.h>

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

