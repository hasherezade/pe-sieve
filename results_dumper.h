#pragma once

#include <Windows.h>

#include "report_formatter.h"

class ResultsDumper
{
public:
	static bool make_dump_dir(const std::string directory);

	ResultsDumper(std::string _baseDir="")
		: baseDir(_baseDir)
	{
		if (!make_dump_dir(this->baseDir)) {
			this->baseDir = ""; // reset path
		}
	}

	size_t dumpAllModified(HANDLE hProcess, ProcessScanReport &process_report, peconv::t_pe_dump_mode dump_mode);
	bool dumpJsonReport(ProcessScanReport &process_report, t_report_filter filter);
	std::string dumpDir; // dump directory
	std::string baseDir; // base directory

protected:
	/**
	@modBaseAddr : base address where this module was mapped
	@fname : known name of this module
	@defaultExtension : default extension - it will be used if no other extension was detected from the previous name
	*/
	std::string makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, std::string defaultExtension);

	std::string makeDirName(const DWORD process_id);
};
