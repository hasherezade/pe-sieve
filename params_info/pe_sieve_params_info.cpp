#include "pe_sieve_params_info.h"

#include <Windows.h>
#include <Psapi.h>

using namespace pesieve;

std::string translate_dump_mode(const DWORD dump_mode)
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

std::string translate_out_filter(const pesieve::t_output_filter o_filter)
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

std::string translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode)
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

std::string translate_modules_filter(DWORD m_filter)
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

pesieve::t_imprec_mode normalize_imprec_mode(size_t mode_id)
{
	if (mode_id > pesieve::PE_IMPREC_MODES_COUNT) {
		return pesieve::PE_IMPREC_NONE;
	}
	return (t_imprec_mode)mode_id;
}

pesieve::t_dump_mode normalize_dump_mode(size_t mode_id)
{
	if (mode_id > pesieve::PE_DUMP_MODES_COUNT) {
		return pesieve::PE_DUMP_AUTO;
	}
	return (pesieve::t_dump_mode) mode_id;
}

