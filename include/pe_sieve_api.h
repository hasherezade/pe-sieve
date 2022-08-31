/**
* @file
* @brief   The API: definitions of the exported elements that are accessible from PE-sieve DLL.
*/

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


//! PE-sieve version in a DWORD form.
extern const DWORD PESIEVE_API PESieve_version;

//! Shows a MessageBox with the informations about PE-sieve.
void PESIEVE_API_FUNC PESieve_help(void);

#ifdef __cplusplus
typedef pesieve::t_report PEsieve_report;
typedef pesieve::t_params PEsieve_params;
#else
typedef t_report PEsieve_report;
typedef t_params PEsieve_params;
#endif

//! Performs a PE-sieve scan with a supplied set of parameters (defined as a structure t_params). Returns a summary of the scan in a variable of type t_report.
PEsieve_report PESIEVE_API_FUNC PESieve_scan(const PEsieve_params args);

//! Performs a PE-sieve scan with a supplied set of parameters (defined as a structure t_params). Returns a summary of the scan in a variable of type t_report.	Allows to supply a buffer that will be filled with full JSON report.
PEsieve_report PESIEVE_API_FUNC PESieve_scan_ex(const PEsieve_params args, char* json_buf, size_t json_buf_size, size_t *buf_needed_size);

#ifdef __cplusplus
};
#endif
