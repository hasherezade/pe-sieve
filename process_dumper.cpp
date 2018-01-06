#include "process_dumper.h"
#include <Windows.h>
#include <Psapi.h>

#include <fstream>

#include "scanner.h"
#include "util.h"

#include "report_formatter.h"
//---

bool ProcessDumper::make_dump_dir(const std::string directory)
{
	if (CreateDirectoryA(directory.c_str(), NULL) 
		||  GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return true;
	}
	return false;
}

std::string ProcessDumper::makeDumpPath(ULONGLONG modBaseAddr, std::string fname)
{
	if (!make_dump_dir(this->dumpDir)) {
		this->dumpDir = ""; // reset path
	}
	//const char* fname = get_file_name(szExePath);
	std::stringstream stream;
	if (this->dumpDir.length() > 0) {
		stream << this->dumpDir;
		stream << "\\";
	}
	stream << std::hex << modBaseAddr;
	if (fname.length() > 0) {
		stream << ".";
		stream << fname;
	} else {
		stream << ".dll";
	}
	return stream.str();
}

size_t ProcessDumper::dumpAllModified(HANDLE processHandle, ProcessScanReport &process_report)
{
	if (processHandle == nullptr) {
		return 0;
	}

	DWORD pid = GetProcessId(processHandle);
	this->dumpDir = ProcessDumper::makeDirName(pid);

	char szModName[MAX_PATH] = { 0 };
	size_t dumped = 0;

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.module_reports.begin();
		itr != process_report.module_reports.end();
		itr++)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status != SCAN_MODIFIED) {
			continue;
		}
		memset(szModName, 0, MAX_PATH);
		std::string modulePath = "";
		if (GetModuleFileNameExA(processHandle, mod->module, szModName, MAX_PATH)) {
			modulePath = get_file_name(szModName);
		}
		std::string dumpFileName = makeDumpPath((ULONGLONG)mod->module, modulePath);
		if (!peconv::dump_remote_pe(
			dumpFileName.c_str(), //output file
			processHandle, 
			(PBYTE) mod->module, 
			true, //unmap
			process_report.exportsMap
		))
		{
			std::cerr << "Failed dumping module!" << std::endl;
			continue;
		}
		dumped++;
		mod->generateTags(dumpFileName + ".tag");
	}
	return dumped;
}

bool ProcessDumper::dumpJsonReport(ProcessScanReport &process_report)
{
	std::string report_all = report_to_json(process_report, REPORT_ALL);
	std::ofstream json_report;
	json_report.open(dumpDir + "\\report.json");
	if (json_report.is_open() == false) {
		return false;
	}
	json_report << report_all;
	if (json_report.is_open()) {
		json_report.close();
		return true;
	}
	return false;
}

std::string ProcessDumper::makeDirName(const DWORD process_id)
{
	std::stringstream stream;
	if (baseDir.length() > 0) {
		stream << baseDir;
		stream << "\\";
	}
	stream << "process_";
	stream << process_id;
	return stream.str();
}

