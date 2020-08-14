#pragma once

#include <windows.h>
#include <pe_sieve_types.h>

#ifndef PESIEVE_STATIC_LIB
#ifdef PESIEVE_EXPORTS
#define PESIEVE_API __declspec(dllexport)
#else
#define PESIEVE_API __declspec(dllimport)
#endif
#else
#define PESIEVE_API
#endif

#define PESIEVE_API_FUNC PESIEVE_API __cdecl

#ifdef __cplusplus
extern "C" {
#endif

extern const DWORD PESIEVE_API PESieve_version;

void PESIEVE_API_FUNC PESieve_help(void);

#ifdef __cplusplus
typedef pesieve::t_report PEsieve_report;
typedef pesieve::t_params PEsieve_params;
#else
typedef t_report PEsieve_report;
typedef t_params PEsieve_params;
#endif

PEsieve_report PESIEVE_API_FUNC PESieve_scan(const PEsieve_params args);

#ifdef __cplusplus
};
#endif
