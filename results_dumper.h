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

	size_t dumpAllModified(HANDLE hProcess, ProcessScanReport &process_report);
	bool dumpJsonReport(ProcessScanReport &process_report, t_report_filter filter);
	std::string dumpDir; // dump directory
	std::string baseDir; // base directory

protected:
	std::string makeDumpPath(ULONGLONG modBaseAddr, std::string fname);
	std::string makeDirName(const DWORD process_id);
};
