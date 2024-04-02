#include "results_dumper.h"

#include <windows.h>
#include <psapi.h>

#include <fstream>

#include "../utils/format_util.h"
#include "../utils/workingset_enum.h"
#include "pe_reconstructor.h"
#include "imp_rec/imp_reconstructor.h"
#include "../scanners/iat_scanner.h"
#include "../scanners/code_scanner.h"

#define DIR_SEPARATOR "\\"

//---
namespace pesieve {

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
		case ImpReconstructor::IMP_RECOVERY_NOT_APPLICABLE:
			return "IMP_RECOVERY_NOT_APPLICABLE";
		case ImpReconstructor::IMP_RECOVERY_SKIPPED:
			return "";
		case ImpReconstructor::IMP_ALREADY_OK:
			return "IMP_ALREADY_OK";
		case ImpReconstructor::IMP_DIR_FIXED:
			return "IMP_DIR_FIXED";
		case ImpReconstructor::IMP_FIXED:
			return "IMP_FIXED";
		case ImpReconstructor::IMP_RECREATED_FILTER0:
			return "IMP_RECREATED_FILTER0";
		case ImpReconstructor::IMP_RECREATED_FILTER1:
			return "IMP_RECREATED_FILTER1";
		case ImpReconstructor::IMP_RECREATED_FILTER2:
			return "IMP_RECREATED_FILTER2";
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
		return util::create_dir_recursively(directory);
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
}; //namespace pesieve


bool pesieve::ResultsDumper::dumpJsonReport(pesieve::ProcessScanReport &process_report, const ProcessScanReport::t_report_filter &filter, const pesieve::t_json_level &jdetails)
{
	std::stringstream stream;
	size_t level = 1;

	if (!process_report.hasAnyShownType(filter)) {
		return false;
	}
	if (!process_report.toJSON(stream, level, filter, jdetails)) {
		return false;
	}
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return false;
	}
	//ensure that the directory is created:
	this->dumpDir = pesieve::ResultsDumper::makeDirName(process_report.getPid());

	std::ofstream json_report;
	std::string report_path = makeOutPath("scan_report.json");
	json_report.open(report_path);
	if (json_report.is_open() == false) {
		return false;
	}
	json_report << report_all << std::endl;
	if (json_report.is_open()) {
		json_report.close();
		return true;
	}
	return false;
}

bool pesieve::ResultsDumper::dumpJsonReport(ProcessDumpReport &process_report)
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
	this->dumpDir = pesieve::ResultsDumper::makeDirName(process_report.getPid());

	std::ofstream json_report;
	std::string report_path = makeOutPath("dump_report.json");
	json_report.open(report_path);
	if (json_report.is_open() == false) {
		return false;
	}
	json_report << report_all << std::endl;
	if (json_report.is_open()) {
		json_report.close();
		return true;
	}
	return false;
}

pesieve::ProcessDumpReport* pesieve::ResultsDumper::dumpDetectedModules(
	HANDLE processHandle,
	bool isRefl,
	ProcessScanReport &process_report, 
	const pesieve::t_dump_mode dump_mode, 
	const t_imprec_mode imprec_mode)
{
	if (processHandle == nullptr) {
		return nullptr;
	}
	ProcessDumpReport *dumpReport = new ProcessDumpReport(process_report.getPid());
	this->dumpDir = pesieve::ResultsDumper::makeDirName(process_report.getPid());

	std::vector<ModuleScanReport*>::iterator itr;
	for (itr = process_report.moduleReports.begin();
		itr != process_report.moduleReports.end();
		++itr)
	{
		ModuleScanReport* mod = *itr;
		if (mod->status != SCAN_SUSPICIOUS) {
			continue;
		}
		dumpModule(processHandle,
			isRefl,
			process_report.modulesInfo,
			mod,
			process_report.exportsMap,
			dump_mode,
			imprec_mode,
			*dumpReport
		);
	}
	return dumpReport;
}

bool pesieve::ResultsDumper::fillModuleCopy(IN ModuleScanReport* mod, IN OUT PeBuffer& module_buf)
{
	if (!mod) return false;

	bool filled = false;

	// first try to use cache:
	WorkingSetScanReport* wsReport = dynamic_cast<WorkingSetScanReport*>(mod);
	if (wsReport && wsReport->data_cache.isFilled()) {
		filled = module_buf.fillFromBuffer((ULONGLONG)mod->module, wsReport->data_cache);
	}
	// if no cache, or loading from cache failed, read from the process memory:
	if (!filled) {
		filled = module_buf.readRemote((ULONGLONG)mod->module, mod->moduleSize);
	}
	return filled;
}

bool pesieve::ResultsDumper::dumpModule(IN HANDLE processHandle,
	IN bool isRefl,
	IN const ModulesInfo &modulesInfo,
	IN ModuleScanReport* mod,
	IN const peconv::ExportsMapper *exportsMap,
	IN const pesieve::t_dump_mode dump_mode,
	IN const t_imprec_mode imprec_mode,
	OUT ProcessDumpReport &dumpReport
)
{
	if (!mod) return false;

	const bool save_imp_report = true;
	bool is_dumped = false;

	peconv::t_pe_dump_mode curr_dump_mode = convert_to_peconv_dump_mode(dump_mode);

	bool dump_shellcode = false;
	std::string payload_ext = "";

	PeBuffer module_buf(processHandle, isRefl);
	bool is_corrupt_pe = false;
	ArtefactScanReport* artefactReport = dynamic_cast<ArtefactScanReport*>(mod);
	if (artefactReport) {
		payload_ext = get_payload_ext(*artefactReport);
		// whenever the artefactReport is available, use it to reconstruct a PE
		if (artefactReport->has_shellcode) {
			dump_shellcode = true;
		}
		if (artefactReport->has_pe) {
			ULONGLONG found_pe_base = artefactReport->artefacts.peImageBase();
			PeReconstructor peRec(artefactReport->artefacts, module_buf);
			if (!peRec.reconstruct()) {
				is_corrupt_pe = true;
				payload_ext = "corrupt_" + payload_ext;
				if (!this->quiet) {
					std::cout << "[-] Reconstructing PE at: " << std::hex << (ULONGLONG)found_pe_base << " failed." << std::endl;
				}
			}
		}
	}
	// if it is not an artefact report, or reconstructing by artefacts failed, read it from the memory:
	if (!artefactReport || is_corrupt_pe) {
		fillModuleCopy(mod, module_buf);
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
	modDumpReport->is_shellcode = !module_buf.isValidPe() && module_buf.isCode();
	
	peconv::ImpsNotCovered notCovered;

	if (module_buf.isFilled()) {

		// Try to fix imports:
		ImpReconstructor impRec(module_buf);
		ImpReconstructor::t_imprec_res imprec_res = impRec.rebuildImportTable(exportsMap, imprec_mode);
		modDumpReport->impRecMode = get_imprec_res_name(imprec_res);


		module_buf.setRelocBase(mod->getRelocBase());
		if (imprec_mode == pesieve::PE_IMPREC_NONE) {
			modDumpReport->isDumped = module_buf.dumpPeToFile(modDumpReport->dumpFileName, curr_dump_mode);
		}
		else {
			modDumpReport->isDumped = module_buf.dumpPeToFile(modDumpReport->dumpFileName, curr_dump_mode, exportsMap, &notCovered);
		}
		

		if (!modDumpReport->isDumped) {
			modDumpReport->isDumped = module_buf.dumpToFile(modDumpReport->dumpFileName);
			curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
		}
		modDumpReport->mode_info = get_dump_mode_name(curr_dump_mode);
		bool iat_not_rebuilt = (imprec_res == ImpReconstructor::IMP_RECOVERY_ERROR) || (imprec_res == ImpReconstructor::IMP_RECOVERY_NOT_APPLICABLE);
		if (iat_not_rebuilt || save_imp_report) {
			std::string imports_file = modDumpReport->dumpFileName + ".imports.txt";
			if (impRec.printFoundIATs(imports_file)) {
				modDumpReport->impListFileName = imports_file;
			}
		}
		std::string imports_not_rec_file = modDumpReport->dumpFileName + ".not_fixed_imports.txt";
		if (IATScanReport::saveNotRecovered(imports_not_rec_file, processHandle, nullptr, notCovered, modulesInfo, exportsMap)) {
			modDumpReport->notRecoveredFileName = imports_not_rec_file;
		}
	}

	if (!modDumpReport->isDumped || dump_shellcode)
	{
		if (dump_shellcode) {
			payload_ext = "shc";
		}

		fillModuleCopy(mod, module_buf);

		modDumpReport = new ModuleDumpReport(module_buf.getModuleBase(), module_buf.getBufferSize());
		dumpReport.appendReport(modDumpReport);

		modDumpReport->is_shellcode = dump_shellcode;
		modDumpReport->dumpFileName = makeModuleDumpPath(module_buf.getModuleBase(), module_name, payload_ext);
		modDumpReport->isDumped = module_buf.dumpToFile(modDumpReport->dumpFileName);
		curr_dump_mode = peconv::PE_DUMP_VIRTUAL;
		modDumpReport->mode_info = get_dump_mode_name(curr_dump_mode);
	}
	if (modDumpReport->isDumped) {
		is_dumped = true;
		if (!this->quiet) {
			std::string mode_info = modDumpReport->mode_info;
			if (mode_info.length() > 0) mode_info = " as " + mode_info;
			std::cout << "[*] Dumped module to: " + modDumpReport->dumpFileName + mode_info << "\n";
		}
	}
	else {
		if (!this->quiet) {
			std::cerr << "[-] Failed dumping module!" << std::endl;
		}
		is_dumped = false;
	}

	pesieve::CodeScanReport *codeScanReport = dynamic_cast<pesieve::CodeScanReport*>(mod);
	if (codeScanReport) {
		std::string tags_file = modDumpReport->dumpFileName + ".tag";

		if (codeScanReport->generateTags(tags_file)) {
			modDumpReport->hooksTagFileName = tags_file;
			modDumpReport->isReportDumped = true;
		}
	}

	pesieve::WorkingSetScanReport* wsScanReport = dynamic_cast<pesieve::WorkingSetScanReport*>(mod);
	if (wsScanReport) {
		std::string tags_file = modDumpReport->dumpFileName + ".pattern.tag";

		if (wsScanReport->generateTags(tags_file)) {
			modDumpReport->patternsTagFileName = tags_file;
			modDumpReport->isReportDumped = true;
		}
	}


	IATScanReport* iatHooksReport = dynamic_cast<IATScanReport*>(mod);
	if (iatHooksReport) {
		std::string imports_not_rec_file = modDumpReport->dumpFileName + ".iat_hooks.txt";

		if (iatHooksReport->generateList(imports_not_rec_file, processHandle, modulesInfo, exportsMap)) {
			modDumpReport->iatHooksFileName = imports_not_rec_file;
			modDumpReport->isReportDumped = true;
		}
	}
	return is_dumped;
}

void pesieve::ResultsDumper::makeAndJoinDirectories(std::stringstream& stream)
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

std::string pesieve::ResultsDumper::makeModuleDumpPath(ULONGLONG modBaseAddr, const std::string &fname, const std::string &default_extension)
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

std::string pesieve::ResultsDumper::makeOutPath(const std::string &fname, const std::string& default_extension)
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

std::string pesieve::ResultsDumper::makeDirName(const DWORD process_id)
{
	std::stringstream stream;
	stream << "process_";
	stream << process_id;
	return stream.str();
}
