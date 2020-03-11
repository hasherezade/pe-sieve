#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <peconv.h>
#include "../utils/path_util.h"
#include "../utils/path_converter.h"

class ModuleDumpReport
{
public:

	ModuleDumpReport(ULONGLONG module_start, size_t module_size)
		: moduleStart(module_start), moduleSize(module_size),
		isDumped(false),
		is_corrupt_pe(false), 
		is_shellcode(false)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level);

	ULONGLONG moduleStart;
	size_t moduleSize;
	bool is_corrupt_pe;
	bool is_shellcode;
	std::string impRecMode;
	bool isDumped;
	std::string mode_info;
	std::string dumpFileName;
	std::string tagsFileName;
	std::string impListFileName;
	std::string notRecoveredFileName;
};

class ProcessDumpReport
{
public:

	ProcessDumpReport(DWORD _pid)
		: pid(_pid)
	{
	}

	~ProcessDumpReport()
	{
		deleteModuleReports();
	}

	void appendReport(ModuleDumpReport *report)
	{
		if (!report) return;
		module_reports.push_back(report);
	}

	size_t countTotal() const
	{
		return module_reports.size();
	}

	bool isFilled() const
	{
		if (countTotal()) return true;
		if (this->minidumpPath.length()) return true;
		return false;
	}

	size_t countDumped() const
	{
		size_t dumped = 0;
		std::vector<ModuleDumpReport*>::const_iterator itr = module_reports.begin();
		for (; itr != module_reports.end(); itr++) {
			ModuleDumpReport* module = *itr;
			if (module->isDumped) {
				dumped++;
			}
		}
		return dumped;
	}

	const virtual bool toJSON(std::stringstream &stream, size_t level);

	DWORD getPid() const { return pid; }

	std::string outputDir;
	std::string minidumpPath;

protected:

	std::string list_dumped_modules(size_t level);

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
	std::vector<ModuleDumpReport*> module_reports;

	friend class ResultsDumper;
};
