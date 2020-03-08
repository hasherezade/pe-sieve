#include "results_dumper.h"

#include <Windows.h>
#include <Psapi.h>

#include <fstream>

#include "../utils/format_util.h"
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
		return "VIRTUAL";
	case peconv::PE_DUMP_UNMAP:
		return "UNMAPPED";
	case peconv::PE_DUMP_REALIGN:
		return "REALIGNED";
	}
	return "";
}

std::string get_imprec_res_name(const ImpReconstructor::t_imprec_res &res)
{
	switch (res) {
	case ImpReconstructor::IMP_NOT_FOUND:
		return "IMP_NOT_FOUND";
	case ImpReconstructor::IMP_RECOVERY_ERROR:
		return "IMP_RECOVERY_ERROR";
	case ImpReconstructor::IMP_RECOVERY_NOT_APLICABLE:
		return "IMP_RECOVERY_NOT_APLICABLE";
	case ImpReconstructor::IMP_RECOVERY_SKIPPED:
		return "";
	case ImpReconstructor::IMP_ALREADY_OK:
		return "IMP_ALREADY_OK";
	case ImpReconstructor::IMP_DIR_FIXED:
		return "IMP_DIR_FIXED";
	case ImpReconstructor::IMP_FIXED:
		return "IMP_FIXED";
	case ImpReconstructor::IMP_RECREATED:
		return "IMP_RECREATED";
	}
	return "Undefined";
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

bool make_dump_dir(const std::string& directory)
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

bool ResultsDumper::dumpJsonReport(ProcessScanReport &process_report, ProcessScanReport::t_report_filter filter)
{
	std::stringstream stream;
	size_t level = 1;

	if (!process_report.toJSON(stream, level, filter)) {
		return false;
	}
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return false;
	}
	//ensure that the directory is created:
	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

	std::ofstream json_report;
	std::string report_path = makeOutPath("scan_report.json");
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

bool ResultsDumper::dumpJsonReport(ProcessDumpReport &process_report)
{
	if (!process_report.isFilled()) {
		return false;
	}
	std::stringstream stream;
	size_t level = 1;
	process_report.toJSON(stream, level);
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return false;
	}
	//ensure that the directory is created:
	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

	std::ofstream json_report;
	std::string report_path = makeOutPath("dump_report.json");
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

ProcessDumpReport* ResultsDumper::dumpDetectedModules(HANDLE processHandle,
	ProcessScanReport &process_report, 
	const pesieve::t_dump_mode dump_mode, 
	const t_imprec_mode imprec_mode)
{
	if (processHandle == nullptr) {
		return nullptr;
	}
	ProcessDumpReport *dumpReport = new ProcessDumpReport(process_report.getPid());
	this->dumpDir = ResultsDumper::makeDirName(process_report.getPid());

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.module_reports.begin();
		itr != process_report.module_reports.end();
		++itr)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status != SCAN_SUSPICIOUS) {
			continue;
		}
		dumpModule(processHandle,
			mod,
			process_report.exportsMap,
			dump_mode,
			imprec_mode,
			*dumpReport
		);
	}
	return dumpReport;
}

bool ResultsDumper::dumpModule(IN HANDLE processHandle,
	IN ModuleScanReport* mod,
	IN const peconv::ExportsMapper *exportsMap,
	IN const pesieve::t_dump_mode dump_mode,
	IN const t_imprec_mode imprec_mode,
	OUT ProcessDumpReport &dumpReport
)
{
	if (!mod) return nullptr;

	bool save_imp_report = true;
	bool is_dumped = false;

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
				if (!this->quiet) {
					std::cout << "[-] Reconstructing PE at: " << std::hex << (ULONGLONG)mod->module << " failed." << std::endl;
				}
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

	ModuleDumpReport *modDumpReport = new ModuleDumpReport(module_buf.getModuleBase(), module_buf.getBufferSize());
	dumpReport.appendReport(modDumpReport);

	modDumpReport->dumpFileName = makeModuleDumpPath(module_buf.getModuleBase(), module_name, payload_ext);
	modDumpReport->is_corrupt_pe = is_corrupt_pe;
	modDumpReport->is_shellcode = !module_buf.isValidPe();

	if (module_buf.isFilled()) {
		// Try to fix imports:
		ImpReconstructor impRec(module_buf);
		ImpReconstructor::t_imprec_res imprec_res = impRec.rebuildImportTable(exportsMap, imprec_mode);

		modDumpReport->impRecMode = get_imprec_res_name(imprec_res);
		module_buf.setRelocBase(mod->getRelocBase());
		modDumpReport->isDumped = module_buf.dumpPeToFile(modDumpReport->dumpFileName, curr_dump_mode, exportsMap);

		if (!modDumpReport->isDumped) {
			modDumpReport->isDumped = module_buf.dumpToFile(modDumpReport->dumpFileName);
			curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
		}
		modDumpReport->mode_info = get_dump_mode_name(curr_dump_mode);
		bool iat_not_rebuilt = (imprec_res == ImpReconstructor::IMP_RECOVERY_ERROR) || (imprec_res = ImpReconstructor::IMP_RECOVERY_NOT_APLICABLE);
		if (iat_not_rebuilt || save_imp_report) {
			std::string imports_file = modDumpReport->dumpFileName + ".imports.txt";
			if (impRec.printFoundIATs(imports_file)) {
				modDumpReport->impListFileName = imports_file;
			}
		}
	}

	if (!modDumpReport->isDumped || dump_shellcode)
	{
		if (dump_shellcode) {
			payload_ext = "shc";
		}
		module_buf.readRemote(processHandle, (ULONGLONG)mod->module, mod->moduleSize);

		modDumpReport = new ModuleDumpReport(module_buf.getModuleBase(), module_buf.getBufferSize());
		dumpReport.appendReport(modDumpReport);

		modDumpReport->is_shellcode = dump_shellcode;
		modDumpReport->dumpFileName = makeModuleDumpPath(module_buf.getModuleBase(), module_name, payload_ext);
		modDumpReport->isDumped = module_buf.dumpToFile(modDumpReport->dumpFileName);
		curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
		modDumpReport->mode_info = get_dump_mode_name(curr_dump_mode);
	}
	if (modDumpReport->isDumped) {
		std::string tags_file = modDumpReport->dumpFileName + ".tag";
		if (mod->generateTags(tags_file)) {
			modDumpReport->tagsFileName = tags_file;
		}
		is_dumped = true;
		if (!this->quiet) {
			std::string mode_info = modDumpReport->mode_info;
			if (mode_info.length() > 0) mode_info = " as " + mode_info;
			std::cout << "[*] Dumped module to: " + modDumpReport->dumpFileName + mode_info << "\n";
		}
	}
	else {
		std::cerr << "[-] Failed dumping module!" << std::endl;
		is_dumped = false;
	}
	return is_dumped;
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
