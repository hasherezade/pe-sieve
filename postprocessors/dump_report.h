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

	ModuleDumpReport(ULONGLONG module_start, size_t module_size)
		: moduleStart(module_start), moduleSize(module_size), isDumped(false),
		is_corrupt_pe(false), 
		is_shellcode(false), is_imp_rec(false)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level)
	{
		OUT_PADDED(outs, level, "\"module\" : ");
		outs << "\"" << std::hex << moduleStart << "\"" << ",\n";
		OUT_PADDED(outs, level, "\"module_size\" : ");
		outs << "\"" << std::hex << moduleSize << "\"" << ",\n";
		if (dumpFileName.length()) {
			OUT_PADDED(outs, level, "\"dump_file\" : ");
			outs << "\"" << escape_path_separators(dumpFileName) << "\"" << ",\n";
		}
		if (tagsFileName.length()) {
			OUT_PADDED(outs, level, "\"tags_file\" : ");
			outs << "\"" << escape_path_separators(tagsFileName) << "\"" << ",\n";
		}
		if (tagsFileName.length()) {
			OUT_PADDED(outs, level, "\"imports_file\" : ");
			outs << "\"" << escape_path_separators(impListFileName) << "\"" << ",\n";
		}
		if (is_imp_rec) {
			OUT_PADDED(outs, level, "\"is_imp_rec\" : ");
			outs << std::dec << is_imp_rec << ",\n";
		}
		if (mode_info.length()) {
			OUT_PADDED(outs, level, "\"dump_mode\" : ");
			outs << "\"" << mode_info << "\"" << ",\n";
		}
		OUT_PADDED(outs, level, "\"is_shellcode\" : ");
		outs <<  std::dec << is_shellcode  << ",\n";
		if (is_corrupt_pe) {
			OUT_PADDED(outs, level, "\"is_corrupt_pe\" : ");
			outs << std::dec << is_corrupt_pe << ",\n";
		}

		OUT_PADDED(outs, level, "\"status\" : ");
		outs << std::dec << this->isDumped;
		return true;
	}

	ULONGLONG moduleStart;
	size_t moduleSize;
	bool is_corrupt_pe;
	bool is_shellcode;
	bool is_imp_rec;
	bool isDumped;
	std::string mode_info;
	std::string dumpFileName;
	std::string tagsFileName;
	std::string impListFileName;
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

	friend class ResultsDumper;
};
