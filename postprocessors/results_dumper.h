#pragma once

#include <Windows.h>

#include "report_formatter.h"

class ResultsDumper
{
public:

	ResultsDumper(std::string _baseDir, bool _quiet)
		: baseDir(_baseDir), quiet(_quiet)
	{
	}
	
	// dump all modules detected as suspicious during the process scan
	size_t dumpDetectedModules(HANDLE hProcess, ProcessScanReport &process_report, const pesieve::t_dump_mode dump_mode, const pesieve::t_imprec_mode imprec_mode);

	// dump JSON report from the process scan
	bool dumpJsonReport(ProcessScanReport &process_report, t_report_filter filter);

	std::string getOutputDir()
	{
		return this->dumpDir;
	}

protected:

	bool dumpModule(HANDLE processHandle, ModuleScanReport* mod, const peconv::ExportsMapper *exportsMap, const pesieve::t_dump_mode dump_mode, const pesieve::t_imprec_mode imprec_mode);

	/**
	@modBaseAddr : base address where this module was mapped
	@fname : known name of this module
	@defaultExtension : default extension - it will be used if no other extension was detected from the previous name
	*/
	std::string makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, std::string defaultExtension);

	std::string makeOutPath(std::string fname, std::string defaultExtension="");

	std::string makeDirName(const DWORD process_id);

	void makeAndJoinDirectories(std::stringstream& name_stream);

	std::string dumpDir; // dump directory
	std::string baseDir; // base directory
	bool quiet;
};
