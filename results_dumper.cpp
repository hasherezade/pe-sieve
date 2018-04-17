#include "results_dumper.h"
#include <Windows.h>
#include <Psapi.h>

#include <fstream>

#include "utils\util.h"
#include "utils\workingset_enum.h"

//---

bool ResultsDumper::make_dump_dir(const std::string directory)
{
	if (CreateDirectoryA(directory.c_str(), NULL) 
		||  GetLastError() == ERROR_ALREADY_EXISTS)
	{
		return true;
	}
	return false;
}

std::string ResultsDumper::makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, std::string default_extension)
{
	if (!make_dump_dir(this->dumpDir)) {
		this->dumpDir = ""; // reset path
	}
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
		stream << default_extension;
	}
	return stream.str();
}

bool dumpAsShellcode(std::string dumpFileName, HANDLE processHandle, PBYTE moduleBase)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID)moduleBase, &page_info, sizeof(page_info));
	if (out != sizeof(page_info)) {
		if (GetLastError() == ERROR_INVALID_PARAMETER) {
			return false;
		}
		return false;
	}

	size_t offset = moduleBase - (PBYTE)page_info.BaseAddress;
	size_t dump_size = page_info.RegionSize - offset;

	BYTE *buf = peconv::alloc_unaligned(dump_size);
	if (!buf) return false;

	bool is_ok = false;

	if (peconv::read_remote_memory(processHandle, moduleBase, buf, dump_size)) {
		is_ok = peconv::dump_to_file(dumpFileName.c_str(), buf, dump_size);
	}
	
	peconv::free_unaligned(buf);
	buf = nullptr;
	return is_ok;
}

size_t ResultsDumper::dumpAllModified(HANDLE processHandle, ProcessScanReport &process_report)
{
	if (processHandle == nullptr) {
		return 0;
	}

	DWORD pid = GetProcessId(processHandle);
	this->dumpDir = ResultsDumper::makeDirName(pid);

	char szModName[MAX_PATH] = { 0 };
	size_t dumped = 0;

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.module_reports.begin();
		itr != process_report.module_reports.end();
		itr++)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status != SCAN_SUSPICIOUS) {
			continue;
		}
		memset(szModName, 0, MAX_PATH);
		std::string modulePath = "";
		if (GetModuleFileNameExA(processHandle, mod->module, szModName, MAX_PATH)) {
			modulePath = get_file_name(szModName);
		}

		std::string dumpFileName = makeModuleDumpPath((ULONGLONG)mod->module, modulePath, ".dll");

		if (!peconv::dump_remote_pe(
			dumpFileName.c_str(), //output file
			processHandle, 
			(PBYTE) mod->module, 
			true, //unmap
			process_report.exportsMap
		))
		{
			std::string dumpFileName = makeModuleDumpPath((ULONGLONG)mod->module, modulePath, ".shc");
			if (!dumpAsShellcode(dumpFileName, processHandle, (PBYTE)mod->module)) {
				std::cerr << "Failed dumping module!" << std::endl;
			}
			continue;
		}
		dumped++;
		mod->generateTags(dumpFileName + ".tag");
	}
	return dumped;
}

bool has_any_shown_type(t_report summary, t_report_filter filter)
{
	t_scan_status aggregated_status = summary.suspicious > 0 ? SCAN_SUSPICIOUS : SCAN_NOT_SUSPICIOUS;
	if (is_shown_type(aggregated_status, filter)) {
		return true;
	}
	aggregated_status = summary.errors > 0 ? SCAN_ERROR : SCAN_NOT_SUSPICIOUS;
	if (is_shown_type(aggregated_status, filter)) {
		return true;
	}
	return false;
}

bool ResultsDumper::dumpJsonReport(ProcessScanReport &process_report, t_report_filter filter)
{
	t_report summary = process_report.generateSummary();
	if (!has_any_shown_type(summary, filter)) {
		return false;
	}
	std::string report_all = report_to_json(process_report, filter);
	if (report_all.length() == 0) {
		return false; 
	}

	//just in case if the directory was not created before:
	if (!make_dump_dir(this->dumpDir)) {
		this->dumpDir = ""; // reset path
	}
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

std::string ResultsDumper::makeDirName(const DWORD process_id)
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

