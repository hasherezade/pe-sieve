#pragma once

#include <windows.h>
#include "pe_sieve_types.h"

#ifdef PESIEVE_EXPORTS
#define PESIEVE_API __declspec(dllexport)
#else
#define PESIEVE_API __declspec(dllimport)
#endif

#ifndef PESIEVE_LIB
extern "C" {
	void PESIEVE_API __stdcall PESieve_help(void);
	DWORD PESIEVE_API __stdcall PESieve_version(void);
	pesieve::t_report PESIEVE_API __stdcall PESieve_scan(pesieve::t_params args);
};
#else
void PESieve_help(void);
DWORD PESieve_version(void);
pesieve::t_report PESieve_scan(pesieve::t_params args);
#endif