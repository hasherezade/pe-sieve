#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <peconv.h>
#include "../utils/util.h"
#include "../utils/path_converter.h"

class ModuleDumpReport
{
public:

	ModuleDumpReport(ULONGLONG module_start)
		: moduleStart(module_start), isDumped(false),
		is_corrupt_pe(false), 
		dump_shellcode(false)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level)
	{
		OUT_PADDED(outs, level, "\"module\" : ");
		outs << "\"" << std::hex << moduleStart << "\"" << ",\n";
		if (dumpFileName.length()) {
			OUT_PADDED(outs, level, "\"dump_file\" : ");
			outs << "\"" << escape_path_separators(dumpFileName) << "\"" << ",\n";
		}
		if (mode_info.length()) {
			OUT_PADDED(outs, level, "\"dump_mode\" : ");
			outs << "\"" << mode_info << "\"" << ",\n";
		}
		OUT_PADDED(outs, level, "\"status\" : ");
		outs << std::dec << this->isDumped;
		return true;
	}

	ULONGLONG moduleStart;
	bool is_corrupt_pe;
	bool dump_shellcode;

	bool isDumped;
	std::string mode_info;
	std::string dumpFileName;
};

class ProcessDumpReport
{
public:

	ProcessDumpReport(DWORD _pid)
		: pid(_pid), successCount(0), errorsCount(0)
	{
	}

	~ProcessDumpReport()
	{
		deleteModuleReports();
	}

	void appendReport(ModuleDumpReport *report)
	{
		if (!report) return;
		if (report->isDumped) {
			this->successCount++;
		}
		else {
			this->errorsCount++;
		}
		module_reports.push_back(report);
	}

	size_t countDumped() const
	{
		return this->successCount;
	}

	DWORD getPid() const { return pid; }

	std::string outputDir;
	std::vector<ModuleDumpReport*> module_reports; //TODO: make it protected
	//peconv::ExportsMapper *exportsMap;

protected:
	void deleteModuleReports()
	{
		std::vector<ModuleDumpReport*>::iterator itr = module_reports.begin();
		for (; itr != module_reports.end(); itr++) {
			ModuleDumpReport* module = *itr;
			delete module;
		}
		module_reports.clear();
	}

	DWORD pid;
	size_t errorsCount;
	size_t successCount;

	friend class ProcessScanner;
};
