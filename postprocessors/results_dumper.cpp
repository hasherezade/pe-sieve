#include "results_dumper.h"
#include <Windows.h>
#include <Psapi.h>

#include <fstream>
#include "../utils/util.h"
#include "../utils/workingset_enum.h"
#include "pe_reconstructor.h"

#define DIR_SEPARATOR "\\"
//---

bool ResultsDumper::make_dump_dir(const std::string directory)
{
	if (directory.length() == 0) {
		return true;
	}
	return create_dir_recursively(directory);
}

void ResultsDumper::makeAndJoinDirectories(std::stringstream& stream)
{
	bool is_created = true;
	if (!make_dump_dir(this->baseDir)) {
		this->baseDir = ""; // reset path
	}
	std::string inner_dir = this->dumpDir;
	if (baseDir.length() > 0) {
		inner_dir = this->baseDir + DIR_SEPARATOR + this->dumpDir;
	}
	if (!make_dump_dir(inner_dir)) {
		this->dumpDir = ""; // reset path
	}
	if (baseDir.length() > 0) {
		stream << baseDir;
		stream << DIR_SEPARATOR;
	}
	if (this->dumpDir.length() > 0) {
		stream << this->dumpDir;
		stream << DIR_SEPARATOR;
	}
}

std::string ResultsDumper::makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, std::string default_extension)
{
	std::stringstream stream;
	makeAndJoinDirectories(stream);
	stream << std::hex << modBaseAddr;
	if (fname.length() > 0) {
		stream << ".";
		stream << fname;
	} else {
		stream << default_extension;
	}
	return stream.str();
}

std::string ResultsDumper::makeOutPath(std::string fname, std::string default_extension)
{
	std::stringstream stream;
	makeAndJoinDirectories(stream);

	if (fname.length() > 0) {
		stream << fname;
	}
	else {
		stream << std::dec << time(nullptr);
		stream << default_extension;
	}
	return stream.str();
}

bool dumpAsShellcode(std::string dumpFileName, HANDLE processHandle, PBYTE moduleBase, size_t moduleSize)
{
	if (!moduleSize) {
		moduleSize = fetch_region_size(processHandle, moduleBase);
	}

	BYTE *buf = peconv::alloc_unaligned(moduleSize);
	if (!buf) return false;

	bool is_ok = false;

	if (peconv::read_remote_memory(processHandle, moduleBase, buf, moduleSize)) {
		is_ok = peconv::dump_to_file(dumpFileName.c_str(), buf, moduleSize);
	}
	
	peconv::free_unaligned(buf);
	buf = nullptr;
	return is_ok;
}

std::string get_payload_ext(ModuleScanReport* mod)
{
	ArtefactScanReport* artefactRepot = dynamic_cast<ArtefactScanReport*>(mod);
	if (!artefactRepot) {
		return ".dll"; //default
	}
	if (artefactRepot->artefacts.isDll) {
		return ".dll";
	}
	return ".exe";
}

std::string get_dump_mode_name(peconv::t_pe_dump_mode dump_mode)
{
	switch (dump_mode) {
	case peconv::PE_DUMP_VIRTUAL:
		return "Virtual";
	case peconv::PE_DUMP_UNMAP:
		return "Unmapped";
	case peconv::PE_DUMP_REALIGN:
		return "Realigned";
	}
	return "";
}

size_t ResultsDumper::dumpAllModified(HANDLE processHandle, ProcessScanReport &process_report, const peconv::t_pe_dump_mode dump_mode)
{
	if (processHandle == nullptr) {
		return 0;
	}

	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

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
		const std::string payload_ext = get_payload_ext(mod);
		std::string dumpFileName = makeModuleDumpPath((ULONGLONG)mod->module, modulePath, payload_ext);
		peconv::t_pe_dump_mode curr_dump_mode = dump_mode;

		bool is_module_dumped = false;
		bool dump_shellcode = false;
		//whenever the artefactReport is available, use it to reconstruct a PE
		ArtefactScanReport* artefactReport = dynamic_cast<ArtefactScanReport*>(mod);
		if (artefactReport) {
			if (artefactReport->has_shellcode) {
				dump_shellcode = true;
			}
			if (artefactReport->has_pe) {
				ULONGLONG found_pe_base = artefactReport->artefacts.peImageBase();
				PeReconstructor peRec(artefactReport->artefacts, curr_dump_mode);
				if (peRec.reconstruct(processHandle)) {
					dumpFileName = makeModuleDumpPath(found_pe_base, modulePath, ".rec" + payload_ext);
					is_module_dumped = peRec.dumpToFile(dumpFileName, process_report.exportsMap);
				}
			}
		}
		else {
			//artefacts report not available, do a simple dump:
			is_module_dumped = peconv::dump_remote_pe(
				dumpFileName.c_str(), //output file
				processHandle,
				(PBYTE)mod->module,
				curr_dump_mode, //PE dump mode
				process_report.exportsMap);
		}

		if (!is_module_dumped || dump_shellcode)
		{
			dumpFileName = makeModuleDumpPath((ULONGLONG)mod->module, modulePath, ".shc");
			if (!dumpAsShellcode(dumpFileName, processHandle, (PBYTE)mod->module, mod->moduleSize)) {
				std::cerr << "[-] Failed dumping module!" << std::endl;
			}
		}
		if (is_module_dumped) {
			dumped++;
			mod->generateTags(dumpFileName + ".tag");
			if (!this->quiet) {
				std::cout << "[*] Dumped module to: " + dumpFileName + " as " + get_dump_mode_name(curr_dump_mode) << "\n";
			}
		}
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

	//ensure that the directory is created:
	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

	std::ofstream json_report;
	std::string report_path = makeOutPath("report.json");
	json_report.open(report_path);
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
	stream << "process_";
	stream << process_id;
	return stream.str();
}

