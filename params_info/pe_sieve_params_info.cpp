#include "pe_sieve_params_info.h"

#include <windows.h>
#include <psapi.h>

using namespace pesieve;

std::string pesieve::translate_dump_mode(const DWORD dump_mode)
{
	switch (dump_mode) {
	case pesieve::PE_DUMP_AUTO:
		return "autodetect (default)";
	case pesieve::PE_DUMP_VIRTUAL:
		return "virtual (as it is in the memory, no unmapping)";
	case pesieve::PE_DUMP_UNMAP:
		return "unmapped (converted to raw using sections' raw headers)";
	case pesieve::PE_DUMP_REALIGN:
		return "realigned raw (converted raw format to be the same as virtual)";
	}
	return "undefined";
}

std::string pesieve::translate_out_filter(const pesieve::t_output_filter o_filter)
{
	switch (o_filter) {
	case pesieve::OUT_FULL:
		return "no filter: dump everything (default)";
	case pesieve::OUT_NO_DUMPS:
		return "don't dump the modified PEs, but save the report";
	case pesieve::OUT_NO_DIR:
		return "don't dump any files";
	}
	return "undefined";
}

std::string pesieve::translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode)
{
	switch (imprec_mode) {
	case pesieve::PE_IMPREC_NONE:
		return "none: do not recover imports (default)";
	case pesieve::PE_IMPREC_AUTO:
		return "try to autodetect the most suitable mode";
	case pesieve::PE_IMPREC_UNERASE:
		return "recover erased parts of the partialy damaged ImportTable";
	case pesieve::PE_IMPREC_REBUILD:
		return "build the ImportTable from the scratch, basing on the found IAT(s)";
	}
	return "undefined";
}

std::string pesieve::translate_dotnet_policy(const pesieve::t_dotnet_policy &mode)
{
	switch (mode) {
	case pesieve::PE_DNET_NONE:
		return "none: treat managed processes same as native";
	case pesieve::PE_DNET_SKIP_MAPPING:
		return "skip mapping mismatch (in .NET modules only)";
	case pesieve::PE_DNET_SKIP_SHC:
		return "skip shellcodes (in all modules within the managed process)";
	case pesieve::PE_DNET_SKIP_HOOKS:
		return "skip hooked modules (in all modules within the managed process)";
	case pesieve::PE_DNET_SKIP_ALL:
		return "skip all the above (mapping, shellcodes, hooks)";
	}
	return "undefined";
}

std::string pesieve::translate_modules_filter(DWORD m_filter)
{
	switch (m_filter) {
	case LIST_MODULES_DEFAULT:
		return "no filter (as the scanner)";
	case LIST_MODULES_32BIT:
		return "32bit only";
	case LIST_MODULES_64BIT:
		return "64bit only";
	case LIST_MODULES_ALL:
		return "all accessible (default)";
	}
	return "undefined";
}

std::string pesieve::translate_data_mode(const pesieve::t_data_scan_mode &mode)
{
	switch (mode) {
	case pesieve::PE_DATA_NO_SCAN:
		return "none: do not scan non-executable pages"; 
	case pesieve::PE_DATA_SCAN_DOTNET:
		return ".NET: scan non-executable in .NET applications";
	case pesieve::PE_DATA_SCAN_NO_DEP:
		return "if no DEP: scan non-exec if DEP is disabled (or if is .NET)";
	case pesieve::PE_DNET_SCAN_ALWAYS:
		return "always: scan non-executable pages unconditionally";
	}
	return "undefined";
}

std::string pesieve::translate_iat_scan_mode(const pesieve::t_iat_scan_mode mode)
{
	switch (mode) {
	case pesieve::PE_IATS_NONE:
		return "none: do not scan for IAT Hooks (default)";
	case pesieve::PE_IATS_FILTERED:
		return "filtered: scan for IAT Hooks, filter out system hooks";
	case pesieve::PE_IATS_UNFILTERED:
		return "unfiltered: scan for IAT Hooks, report all";
	}
	return "undefined";
}

pesieve::t_imprec_mode pesieve::normalize_imprec_mode(size_t mode_id)
{
	if (mode_id > pesieve::PE_IMPREC_MODES_COUNT) {
		return pesieve::PE_IMPREC_NONE;
	}
	return (t_imprec_mode)mode_id;
}

pesieve::t_dump_mode pesieve::normalize_dump_mode(size_t mode_id)
{
	if (mode_id > pesieve::PE_DUMP_MODES_COUNT) {
		return pesieve::PE_DUMP_AUTO;
	}
	return (pesieve::t_dump_mode) mode_id;
}

