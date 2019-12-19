#include "results_dumper.h"

#include <Windows.h>
#include <Psapi.h>

#include <fstream>

#include "../utils/util.h"
#include "../utils/workingset_enum.h"
#include "pe_reconstructor.h"
#include "imp_rec/imp_reconstructor.h"

#define DIR_SEPARATOR "\\"

using namespace pesieve;
//---
std::string get_payload_ext(const ArtefactScanReport& artefactRepot)
{
	if (!artefactRepot.has_pe) {
		return "shc";
	}
	if (artefactRepot.artefacts.isDll) {
		return "dll";
	}
	return "exe";
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

peconv::t_pe_dump_mode convert_to_peconv_dump_mode(const pesieve::t_dump_mode dump_mode)
{
	switch (dump_mode) {
	case pesieve::PE_DUMP_AUTO:
		return peconv::PE_DUMP_AUTO;

	case pesieve::PE_DUMP_VIRTUAL:
		return peconv::PE_DUMP_VIRTUAL;

	case pesieve::PE_DUMP_UNMAP:
		return peconv::PE_DUMP_UNMAP;

	case pesieve::PE_DUMP_REALIGN:
		return peconv::PE_DUMP_REALIGN;
	}
	return peconv::PE_DUMP_AUTO;
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

bool make_dump_dir(const std::string directory)
{
	if (directory.length() == 0) {
		return true;
	}
	return create_dir_recursively(directory);
}

std::string get_module_file_name(HANDLE processHandle, const ModuleScanReport& mod)
{
	if (mod.moduleFile.length() > 0) {
		return peconv::get_file_name(mod.moduleFile);
	}

	char szModName[MAX_PATH] = { 0 };
	memset(szModName, 0, MAX_PATH);

	std::string modulePath = "";
	if (GetModuleFileNameExA(processHandle, (HMODULE)mod.module, szModName, MAX_PATH)) {
		modulePath = peconv::get_file_name(szModName);
	}
	return modulePath;
}
//---

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

size_t ResultsDumper::dumpDetectedModules(HANDLE processHandle, 
	ProcessScanReport &process_report, 
	const pesieve::t_dump_mode dump_mode, 
	const t_imprec_mode imprec_mode)
{
	if (processHandle == nullptr) {
		return 0;
	}

	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

	size_t dumped = 0;

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.module_reports.begin();
		itr != process_report.module_reports.end();
		++itr)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status != SCAN_SUSPICIOUS) {
			continue;
		}

		if (dumpModule(processHandle,
			mod,
			process_report.exportsMap,
			dump_mode,
			imprec_mode)
			)
		{
			dumped++;
		}
	}
	return dumped;
}

bool ResultsDumper::dumpModule(HANDLE processHandle,
	ModuleScanReport* mod,
	const peconv::ExportsMapper *exportsMap,
	const pesieve::t_dump_mode dump_mode,
	const t_imprec_mode imprec_mode
)
{
	if (!mod) return false;

	bool save_imp_report = true;

	peconv::t_pe_dump_mode curr_dump_mode = convert_to_peconv_dump_mode(dump_mode);

	bool dump_shellcode = false;
	std::string payload_ext = "";

	PeBuffer module_buf;
	bool is_corrupt_pe = false;

	ArtefactScanReport* artefactReport = dynamic_cast<ArtefactScanReport*>(mod);
	if (artefactReport) {
		payload_ext = get_payload_ext(*artefactReport);
		//whenever the artefactReport is available, use it to reconstruct a PE
		if (artefactReport->has_shellcode) {
			dump_shellcode = true;
		}
		if (artefactReport->has_pe) {
			ULONGLONG found_pe_base = artefactReport->artefacts.peImageBase();
			PeReconstructor peRec(artefactReport->artefacts, module_buf);
			if (!peRec.reconstruct(processHandle)) {
				is_corrupt_pe = true;
				payload_ext = "corrupt_" + payload_ext;
				std::cout << "[-] Reconstructing PE at: " << std::hex << (ULONGLONG)mod->module << " failed." << std::endl;
			}
		}
	}
	// if it is not an artefact report, or reconstructing by artefacts failed, read it from the memory:
	if (!artefactReport || is_corrupt_pe) {
		size_t img_size = mod->moduleSize;
		if (img_size == 0) {
			//some of the reports may not have moduleSize filled
			img_size = peconv::get_remote_image_size(processHandle, (BYTE*)mod->module);
		}
		module_buf.readRemote(processHandle, (ULONGLONG)mod->module, img_size);
	}
	//if no extension selected yet, do it now:
	if (payload_ext.length() == 0) {
		payload_ext = module_buf.isValidPe() ? "dll" : "shc";
	}
	const std::string module_name = get_module_file_name(processHandle, *mod);
	std::string dumpFileName = makeModuleDumpPath(module_buf.getModuleBase(), module_name, payload_ext);
	bool is_module_dumped = false;

	if (module_buf.isFilled()) {
		ImpReconstructor impRec(module_buf);
		bool is_imp_rec = impRec.rebuildImportTable(exportsMap, imprec_mode);
		
		is_module_dumped = module_buf.dumpPeToFile(dumpFileName, curr_dump_mode, exportsMap);
		if (!is_module_dumped) {
			is_module_dumped = module_buf.dumpToFile(dumpFileName);
			curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
		}
		if (!is_imp_rec || save_imp_report) {
			impRec.printFoundIATs(dumpFileName + ".imports.txt");
		}
	}

	if (!is_module_dumped || dump_shellcode)
	{
		if (dump_shellcode) {
			payload_ext = "shc";
		}
		module_buf.readRemote(processHandle, (ULONGLONG)mod->module, mod->moduleSize);
		dumpFileName = makeModuleDumpPath(module_buf.getModuleBase(), module_name, payload_ext);
		is_module_dumped = module_buf.dumpToFile(dumpFileName);
		curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
	}
	if (is_module_dumped) {
		mod->generateTags(dumpFileName + ".tag");
		if (!this->quiet) {
			std::string mode_info = get_dump_mode_name(curr_dump_mode);
			if (mode_info.length() > 0) mode_info = " as " + mode_info;
			std::cout << "[*] Dumped module to: " + dumpFileName + mode_info << "\n";
		}
	}
	else {
		std::cerr << "[-] Failed dumping module!" << std::endl;
	}
	return is_module_dumped;
}

void ResultsDumper::makeAndJoinDirectories(std::stringstream& stream)
{
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

std::string ResultsDumper::makeModuleDumpPath(ULONGLONG modBaseAddr, std::string fname, const std::string &default_extension)
{
	std::stringstream stream;
	makeAndJoinDirectories(stream);
	stream << std::hex << modBaseAddr;
	if (fname.length() > 0) {
		stream << ".";
		stream << fname;
	} else {
		stream << "." << default_extension;
	}
	return stream.str();
}

std::string ResultsDumper::makeOutPath(std::string fname, const std::string& default_extension)
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

std::string ResultsDumper::makeDirName(const DWORD process_id)
{
	std::stringstream stream;
	stream << "process_";
	stream << process_id;
	return stream.str();
}
