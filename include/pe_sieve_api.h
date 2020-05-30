#pragma once

#include <windows.h>
#include "pe_sieve_types.h"

#ifndef PESIEVE_STATIC_LIB
#ifdef PESIEVE_EXPORTS
#define PESIEVE_API __declspec(dllexport) __stdcall
#else
#define PESIEVE_API __declspec(dllimport) __stdcall
#endif
#else
#define PESIEVE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

void PESIEVE_API PESieve_help(void);
DWORD PESIEVE_API PESieve_version(void);

#ifdef __cplusplus
typedef pesieve::t_report PEsieve_report;
typedef pesieve::t_params PEsieve_params;
#else
typedef t_report PEsieve_report;
typedef t_params PEsieve_params;
#endif

PEsieve_report PESIEVE_API PESieve_scan(PEsieve_params args);

#ifdef __cplusplus
};
#endif
