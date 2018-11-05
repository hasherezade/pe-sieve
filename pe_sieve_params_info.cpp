#include "pe_sieve_params_info.h"

#include <peconv.h>
#include <Windows.h>
#include <Psapi.h>

std::string translate_dump_mode(const DWORD dump_mode)
{
	switch (dump_mode) {
	case peconv::PE_DUMP_AUTO:
		return "autodetect (default)";
	case peconv::PE_DUMP_VIRTUAL:
		return "virtual (as it is in the memory, no unmapping)";
	case peconv::PE_DUMP_UNMAP:
		return "unmapped (converted to raw using sections' raw headers)";
	case peconv::PE_DUMP_REALIGN:
		return "realigned raw (converted raw format to be the same as virtual)";
	}
	return "undefined";
}

std::string translate_out_filter(const t_output_filter o_filter)
{
	switch (o_filter) {
	case OUT_FULL:
		return "no filter: dump everything (default)";
	case OUT_NO_DUMPS:
		return "don't dump the modified PEs, but save the report";
	case OUT_NO_DIR:
		return "don't dump any files";
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
