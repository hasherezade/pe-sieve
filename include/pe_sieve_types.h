/**
* @file
* @brief   The types used by PE-sieve API.
*/

#pragma once

#include <windows.h>

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
		SHELLC_NONE = 0,           ///< do not detect shellcode
		SHELLC_PATTERNS,           ///< detect shellcodes by patterns
		SHELLC_STATS,              ///< detect shellcodes by stats
		SHELLC_PATTERNS_OR_STATS, ///< detect shellcodes by patterns or stats (any match)
		SHELLC_PATTERNS_AND_STATS, ///< detect shellcodes by patterns and stats (both match)
		SHELLC_COUNT
	} t_shellc_mode;

	typedef enum {
		OBFUSC_NONE = 0,            ///< do not detect obfuscated contents
		OBFUSC_STRONG_ENC,          ///< detect areas possibly encrypted with strong encryption
		OBFUSC_WEAK_ENC,            ///< detect areas possibly encrypted with weak encryption (lower entropy, possible XOR patterns)
		OBFUSC_ANY,                 ///< detect both: possible strong or weak encryption
		OBFUSC_COUNT
	} t_obfusc_mode;

	typedef enum {
		PE_IMPREC_NONE = 0, ///< do not try to recover imports
		PE_IMPREC_AUTO,     ///< try to autodetect the most suitable mode
		PE_IMPREC_UNERASE,  ///< recover erased parts of the partialy damaged import table
		PE_IMPREC_REBUILD0,  ///< build the import table from the scratch, basing on the found IAT(s): use only terminated blocks (restrictive mode)
		PE_IMPREC_REBUILD1,  ///< build the import table from the scratch, basing on the found IAT(s): use terminated blocks, or blocks with more than 1 thunk
		PE_IMPREC_REBUILD2,  ///< build the import table from the scratch, basing on the found IAT(s): use all found blocks (aggressive mode)
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

	typedef enum {
		REPORT_NONE = 0,     ///< do not output a report
		REPORT_SCANNED,	     ///< output the scan report
		REPORT_DUMPED,	     ///< output the dumps report
		REPORT_ALL           ///< output all available reports
	} t_report_type;

	//!  A wrapper for a dynamically allocated string.
	typedef struct _PARAM_STRING {
		ULONG length;
		char* buffer;
	} PARAM_STRING;

	//!  Input parameters for PE-sieve, defining the configuration.
	typedef struct params {
		DWORD pid;                 ///< the PID of the process to be scanned
		t_dotnet_policy dotnet_policy; ///< policy for scanning .NET modules
		t_imprec_mode imprec_mode;  ///< import recovery mode
		bool quiet;                 ///<do not print log on the stdout
		t_output_filter out_filter; ///< level of details of the created output material
		bool no_hooks;            ///< don't scan for hooks
		t_shellc_mode shellcode;  ///< detect shellcode implants
		t_obfusc_mode obfuscated;        ///< detect encrypted or obfuscated content (possible encrypted shellcodes)
		bool threads;           ///< scan threads
		t_iat_scan_mode iat;    ///< detect IAT hooking
		t_data_scan_mode data;  ///< should scan non-executable pages?
		bool minidump;          ///< make minidump of full process
		t_dump_mode dump_mode;  ///< in which mode the detected PE implants should be dumped
		bool json_output;       ///< display the final summary as the JSON report
		bool make_reflection;   ///< operate on a process reflection rather than on the live process (this allows i.e. to force-read inaccessible pages)
		bool use_cache;      ///< enable cache for the scanned modules
		t_json_level json_lvl;  ///< level of the details of the JSON report
		char output_dir[MAX_PATH + 1];  ///< the root directory where the output should be saved (default: current directory)
		PARAM_STRING modules_ignored; ///< a list of modules that will not be scanned, separated by PARAM_LIST_SEPARATOR
	} t_params;

	//!  Final summary about the scanned process.
	typedef struct report {
		DWORD pid;              ///< pid of the process that was scanned
		bool is_managed;        ///< is process managed (.NET)
		bool is_64bit;          ///< is process 64 bit
		bool is_reflection;     ///< was the scan performed on process reflection
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

