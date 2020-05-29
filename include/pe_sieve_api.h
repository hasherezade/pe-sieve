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
#define report_type pesieve::t_report
#define params_type pesieve::t_params
#else
#define report_type t_report
#define params_type t_params
#endif
report_type PESIEVE_API PESieve_scan(params_type args);
#undef report_type
#undef params_type

#ifdef __cplusplus
};
#endif
