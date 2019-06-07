#pragma once

#include <Windows.h>

#include "report_formatter.h"

class ResultsDumper
{
public:
	static bool make_dump_dir(const std::string directory);

	ResultsDumper(std::string _baseDir, bool _quiet)
		: baseDir(_baseDir), quiet(_quiet)
	{
	}

	size_t dumpAllModified(HANDLE hProcess, ProcessScanReport &process_report, const peconv::t_pe_dump_mode dump_mode, const t_pesieve_imprec_mode imprec_mode);
	bool dumpJsonReport(ProcessScanReport &process_report, t_report_filter filter);
	std::string dumpDir; // dump directory
	std::string baseDir; // base directory
	bool quiet;

protected:
	/**
	@modBaseAddr : base address where this module was mapped
	@fname : known name of this module
	@defaultExtension : default extension - it will be used if no other extension was detected from the previous name
	*/
	std::string makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, std::string defaultExtension);

	std::string makeOutPath(std::string fname, std::string defaultExtension="");

	std::string makeDirName(const DWORD process_id);

	void makeAndJoinDirectories(std::stringstream& name_stream);
};
