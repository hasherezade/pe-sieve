/**
* @file
* @brief   The types used by PE-sieve API.
*/

#pragma once

#include <windows.h>
#include <pshpack4.h> // ensure 4 byte packing of the structures

#define MAX_MODULE_BUF_LEN 1024
#define PARAM_LIST_SEPARATOR ';'

#ifndef __cplusplus
typedef char bool;
#endif

#ifdef __cplusplus
namespace pesieve {
#endif

	//! the status returned if scanning has failed
	const DWORD ERROR_SCAN_FAILURE = (-1);

	typedef enum {
		OUT_FULL = 0, ///< no filter: dump everything (default)
		OUT_NO_DUMPS, ///< don't dump the modified PEs, but save the report
		OUT_NO_DIR, ///< don't dump any files
		OUT_FILTERS_COUNT
	} t_output_filter;

	typedef enum {
		PE_IMPREC_NONE = 0, ///< do not try to recover imports
		PE_IMPREC_AUTO,     ///< try to autodetect the most suitable mode
		PE_IMPREC_UNERASE,  ///< recover erased parts of the partialy damaged import table
		PE_IMPREC_REBUILD,  ///< build the import table from the scratch, basing on the found IAT(s)
		PE_IMPREC_MODES_COUNT
	} t_imprec_mode;

	typedef enum {
		PE_DUMP_AUTO = 0,   ///< autodetect which dump mode is the most suitable for the given input
		PE_DUMP_VIRTUAL,    ///< dump as it is in the memory (virtual)
		PE_DUMP_UNMAP,      ///< convert to the raw format: using raw sections' headers
		PE_DUMP_REALIGN,    ///< convert to the raw format: by realigning raw sections' headers to be the same as virtual (useful if the PE was unpacked in memory)
		PE_DUMP_MODES_COUNT
	} t_dump_mode;

	typedef enum {
		PE_IATS_NONE = 0,           ///< do not scan IAT
		PE_IATS_CLEAN_SYS_FILTERED, ///< scan IAT, filter hooks if they lead to unpatched system module
		PE_IATS_ALL_SYS_FILTERED,   ///< scan IAT, filter hooks if they lead to any system module
		PE_IATS_UNFILTERED,         ///< scan IAT, unfiltered
		PE_IATS_MODES_COUNT
	} t_iat_scan_mode;

	typedef enum {
		PE_DNET_NONE = 0,           ///< none: treat managed processes same as native
		PE_DNET_SKIP_MAPPING = 1,   ///< skip mapping mismatch (in .NET modules only)
		PE_DNET_SKIP_SHC,           ///< skip shellcodes (in all modules within the managed process)
		PE_DNET_SKIP_HOOKS,         ///< skip hooked modules (in all modules within the managed process)
		PE_DNET_SKIP_ALL,           ///< skip all above indicators (mapping, shellcodes, hooks) in modules within the managed process
		PE_DNET_COUNT
	} t_dotnet_policy;

	typedef enum {
		PE_DATA_NO_SCAN = 0,        ///< do not scan non-executable pages
		PE_DATA_SCAN_DOTNET,        ///< scan data in .NET applications
		PE_DATA_SCAN_NO_DEP,        ///< scan data if no DEP or in .NET applications
		PE_DATA_SCAN_ALWAYS,        ///< scan data unconditionally
		PE_DATA_SCAN_INACCESSIBLE,      ///< scan data unconditionally, and inaccessible pages (if running in reflection mode)
		PE_DATA_SCAN_INACCESSIBLE_ONLY, ///< scan inaccessible pages (if running in reflection mode)
		PE_DATA_COUNT
	} t_data_scan_mode;

	typedef enum {
		JSON_BASIC = 0,     ///< basic
		JSON_DETAILS = 1,   ///< include the basic list patches in the main JSON report
		JSON_DETAILS2,      ///< include the extended list patches in the main JSON report
		JSON_LVL_COUNT
	} t_json_level;

	//!  Input parameters for PE-sieve, defining the configuration.
	typedef struct {
		DWORD pid;                 ///< the PID of the process to be scanned
		t_dotnet_policy dotnet_policy; ///< policy for scanning .NET modules
		t_imprec_mode imprec_mode;  ///< import recovery mode
		bool quiet;                 ///<do not print log on the stdout
		t_output_filter out_filter; ///< level of details of the created output material
		bool no_hooks;           ///< don't scan for hooks
		bool shellcode;         ///< detect shellcode implants
		t_iat_scan_mode iat;    ///< detect IAT hooking
		t_data_scan_mode data;  ///< should scan non-executable pages?
		bool minidump;          ///< make minidump of full process
		t_dump_mode dump_mode;  ///< in which mode the detected PE implants should be dumped
		bool json_output;       ///< display the final summary as the JSON report
		bool make_reflection;   ///< operate on a process reflection rather than on the live process (this allows i.e. to force-read inaccessible pages)
		t_json_level json_lvl;  ///< level of the details of the JSON report
		char output_dir[MAX_PATH + 1];  ///< the root directory where the output should be saved (default: current directory)
		char modules_ignored[MAX_MODULE_BUF_LEN]; ///< a list of modules that will not be scanned, separated by PARAM_LIST_SEPARATOR
	} t_params;

	//!  Final summary about the scanned process.
	typedef struct {
		DWORD pid;              ///< pid of the process that was scanned
		bool is_managed;        ///< is process managed (.NET)
		bool is_64bit;          ///< is process 64 bit
		DWORD scanned;          ///< number of all scanned modules
		DWORD suspicious;       ///< general summary of suspicious
		DWORD replaced;         ///< PE file replaced in memory (probably hollowed)
		DWORD hdr_mod;          ///< PE header is modified (but not replaced)
		DWORD unreachable_file; ///< cannot read the file corresponding to the module in memory
		DWORD patched;          ///< detected modifications in the code
		DWORD iat_hooked;       ///< detected IAT hooks
		DWORD implanted;        ///< all implants: shellcodes + PEs
		DWORD implanted_pe;     ///< the full PE was probably loaded manually
		DWORD implanted_shc;    ///< implanted shellcodes
		DWORD other;            ///< other indicators
		DWORD skipped;          ///< some of the modules must be skipped (i.e. dotNET managed code have different characteristics and this scan does not apply)
		DWORD errors;           ///< the number of elements that could not be scanned because of errors. If errors == ERROR_SCAN_FAILURE, no scan was performed.
	} t_report;

#ifdef __cplusplus
};
#endif

#include <poppack.h> //back to the previous structure packing
