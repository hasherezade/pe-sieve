#pragma once

#include <windows.h>

#include "report_formatter.h"
#include "dump_report.h"
#include "pe_buffer.h"

namespace pesieve {

	class ResultsDumper
	{
	public:

		ResultsDumper(std::string _baseDir, bool _quiet)
			: baseDir(_baseDir), quiet(_quiet)
		{
		}

		// dump all modules detected as suspicious during the process scan
		ProcessDumpReport* dumpDetectedModules(HANDLE hProcess, bool isRefl, ProcessScanReport &process_report, const pesieve::t_dump_mode dump_mode, const pesieve::t_imprec_mode imprec_mode);

		// dump JSON report from the process scan
		bool dumpJsonReport(ProcessScanReport &process_report, const ProcessScanReport::t_report_filter &filter, const pesieve::t_json_level &jdetails);

		bool dumpJsonReport(ProcessDumpReport &process_report);

		std::string getOutputDir()
		{
			return this->dumpDir;
		}

		std::string makeOutPath(const std::string &fname, const std::string& defaultExtension = "");

	protected:
		/**
		\param processHandle : handle of the target process (from which the artefacts will be dumped)
		\param isRefl : a flag indicating if this is a process reflection
		\param modulesInfo : list the scanned modules, with their statuses
		\param modReport : ModuleScanReport defining artefacts to be dumped
		\param exportsMap : mapping of all the exported APIs available within the process (for imports reconstruction)
		\param imprec_mode : mode in which imports reconstruction will be attempted
		\param dumpReport : ProcessDumpReport to which reports from the current dump will be appended
		*/
		bool dumpModule(
			IN HANDLE processHandle,
			IN bool isRefl,
			IN const ModulesInfo &modulesInfo,
			IN ModuleScanReport* modReport,
			IN const peconv::ExportsMapper *exportsMap,
			IN const pesieve::t_dump_mode dump_mode,
			IN const pesieve::t_imprec_mode imprec_mode,
			OUT ProcessDumpReport &dumpReport
		);

		/**
		\param modBaseAddr : base address where this module was mapped
		\param fname : known name of this module
		\param defaultExtension : default extension - it will be used if no other extension was detected from the previous name
		*/
		std::string makeModuleDumpPath(ULONGLONG modBaseAddr, const std::string &fname, const std::string &defaultExtension);

		std::string makeDirName(const DWORD process_id);

		void makeAndJoinDirectories(std::stringstream& name_stream);

		bool fillModuleCopy(IN ModuleScanReport* mod, IN OUT PeBuffer& module_buf);

		std::string dumpDir; // dump directory
		std::string baseDir; // base directory
		bool quiet;
	};

}; //namespace pesieve
