#include "scan_report.h"

#include "headers_scanner.h"
#include "code_scanner.h"
#include "iat_scanner.h"
#include "workingset_scanner.h"
#include "artefact_scanner.h"
#include "mapping_scanner.h"

#include "../utils/format_util.h"

using namespace pesieve;
using namespace pesieve::util;

namespace pesieve {

	bool is_shown_type(t_scan_status status, ProcessScanReport::t_report_filter filter)
	{
		if (filter == ProcessScanReport::REPORT_ALL) {
			return true;
		}
		if (filter & ProcessScanReport::REPORT_ERRORS) {
			if (status == SCAN_ERROR) return true;
		}
		if (filter & ProcessScanReport::REPORT_SUSPICIOUS) {
			if (status == SCAN_SUSPICIOUS) return true;
		}
		if (filter & ProcessScanReport::REPORT_NOT_SUSPICIOUS) {
			if (status == SCAN_NOT_SUSPICIOUS) return true;
		}
		return false;
	}

}; //namespace pesieve

bool pesieve::ProcessScanReport::hasAnyShownType(const pesieve::ProcessScanReport::t_report_filter &filter)
{
	t_report summary = this->generateSummary();
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
//----

bool pesieve::ProcessScanReport::appendToModulesList(ModuleScanReport *report)
{
	if (!report || report->moduleSize == 0) {
		return false; //skip
	}
	ULONGLONG module_start = (ULONGLONG)report->module;
	LoadedModule* mod = modulesInfo.getModuleAt(module_start);
	if (mod == nullptr) {
		//create new only if it was not found
		mod = new LoadedModule(report->pid, module_start, report->moduleSize);
		if (!modulesInfo.appendModule(mod)) {
			delete mod; //delete the module as it was not appended
			return false;
		}
	}
	size_t old_size = mod->getSize();
	if (old_size < report->moduleSize) {
		mod->resize(report->moduleSize);
	}
	if (!mod->isSuspicious()) {
		//update the status
		mod->setSuspicious(report->status == SCAN_SUSPICIOUS);
	}
	return true;
}

pesieve::ProcessScanReport::t_report_type pesieve::ProcessScanReport::getReportType(ModuleScanReport *report)
{
	if (!report) {
		return pesieve::ProcessScanReport::REPORT_TYPES_COUNT;
	}
	if (dynamic_cast<HeadersScanReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_HEADERS_SCAN;
	}
	if (dynamic_cast<WorkingSetScanReport*>(report)) {
		if (dynamic_cast<ArtefactScanReport*>(report)) {
			return pesieve::ProcessScanReport::REPORT_ARTEFACT_SCAN;
		}
		return pesieve::ProcessScanReport::REPORT_MEMPAGE_SCAN;
	}
	if (dynamic_cast<MappingScanReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_MAPPING_SCAN;
	}
	if (dynamic_cast<CodeScanReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_CODE_SCAN;
	}
	if (dynamic_cast<IATScanReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_IAT_SCAN;
	}
	if (dynamic_cast<UnreachableModuleReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_UNREACHABLE_SCAN;
	}
	if (dynamic_cast<SkippedModuleReport*>(report)) {
		return pesieve::ProcessScanReport::REPORT_SKIPPED_SCAN;
	}
	return pesieve::ProcessScanReport::REPORT_TYPES_COUNT;
}

size_t pesieve::ProcessScanReport::countResultsPerType(const t_report_type type, const t_scan_status result) const
{
	if (type >= REPORT_TYPES_COUNT) {
		return 0; //invalid type
	}
	size_t counter = 0;
	std::set<ModuleScanReport*>::iterator itr;
	for (itr = this->reportsByType[type].begin(); itr != this->reportsByType[type].end(); ++itr) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == result) {
			counter++;
		}
	}
	return counter;
}

void pesieve::ProcessScanReport::appendToType(ModuleScanReport *report)
{
	if (report == nullptr) return;

	t_report_type type = pesieve::ProcessScanReport::getReportType(report);
	if (type >= REPORT_TYPES_COUNT) {
		return;
	}

	this->reportsByType[type].insert(report);
}

size_t pesieve::ProcessScanReport::countHdrsReplaced() const
{
	size_t replaced = 0;
	const t_report_type type = REPORT_HEADERS_SCAN;

	std::set<ModuleScanReport*>::iterator itr;
	for (itr = this->reportsByType[type].begin(); itr != this->reportsByType[type].end(); ++itr) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			HeadersScanReport *hdrRep = dynamic_cast<HeadersScanReport*>(report);
			if (!hdrRep) continue; //it should not happen

			if (hdrRep->isHdrReplaced()) {
				replaced++;
			}
		}
	}
	return replaced;
}

pesieve::t_report pesieve::ProcessScanReport::generateSummary() const
{
	t_report summary = { 0 };
	summary.pid = this->pid;
	summary.is_64bit = this->is64bit;
	summary.is_managed = this->isManaged;
	summary.errors = static_cast<DWORD>(this->errorsCount);
	summary.skipped = static_cast<DWORD>(this->reportsByType[REPORT_SKIPPED_SCAN].size());
	summary.scanned = static_cast<DWORD>(this->reportsByType[REPORT_HEADERS_SCAN].size());

	std::vector<ModuleScanReport*>::const_iterator itr = moduleReports.begin();
	for (; itr != moduleReports.end(); ++itr) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			summary.suspicious++;
		}
		if (ModuleScanReport::get_scan_status(report) == SCAN_ERROR) {
			summary.errors++;
		}
	}
	summary.replaced = countHdrsReplaced();
	summary.patched = countSuspiciousPerType(REPORT_CODE_SCAN);
	summary.iat_hooked = countSuspiciousPerType(REPORT_IAT_SCAN);
	summary.implanted_shc = countSuspiciousPerType(REPORT_MEMPAGE_SCAN);
	summary.implanted_pe = countSuspiciousPerType(REPORT_ARTEFACT_SCAN);
	summary.implanted = summary.implanted_shc + summary.implanted_pe;
	summary.hdr_mod = countSuspiciousPerType(REPORT_HEADERS_SCAN) - summary.replaced;
	summary.unreachable_file = countSuspiciousPerType(REPORT_UNREACHABLE_SCAN) + countResultsPerType(REPORT_UNREACHABLE_SCAN, pesieve::SCAN_ERROR);
	summary.other = summary.suspicious - (summary.patched + summary.replaced + summary.implanted + summary.hdr_mod + summary.iat_hooked);
	return summary;
}

std::string pesieve::ProcessScanReport::listModules(size_t level, const pesieve::ProcessScanReport::t_report_filter &filter) const
{
	std::stringstream stream;
	//summary:
	OUT_PADDED(stream, level, "\"scans\" : [\n");
	bool is_first = true;
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = this->moduleReports.begin(); itr != this->moduleReports.end(); ++itr) {
		ModuleScanReport *mod = *itr;
		if (is_shown_type(mod->status, filter)) {
			if (!is_first) {
				stream << ",\n";
			}
			OUT_PADDED(stream, level + 1, "{\n");
			mod->toJSON(stream, level + 2);
			stream << "\n";
			OUT_PADDED(stream, level + 1, "}");
			is_first = false;
		}
	}
	if (moduleReports.size()) {
		stream << "\n";
	}
	OUT_PADDED(stream, level, "]\n");
	return stream.str();
}

const bool pesieve::ProcessScanReport::toJSON(std::stringstream &stream, size_t level, const pesieve::ProcessScanReport::t_report_filter &filter) const
{
	const t_report report = this->generateSummary();
	//summary:
	size_t other = report.other;
	stream << "{\n";
	OUT_PADDED(stream, level, "\"pid\" : ");
	stream << std::dec << report.pid << ",\n";
	OUT_PADDED(stream, level, "\"is_64_bit\" : ");
	stream << std::dec << report.is_64bit << ",\n";
	OUT_PADDED(stream, level, "\"is_managed\" : ");
	stream << std::dec << report.is_managed << ",\n";
	OUT_PADDED(stream, level, "\"main_image_path\" : \"");
	stream << escape_path_separators(this->mainImagePath) << "\",\n";
	OUT_PADDED(stream, level, "\"scanned\" : \n");
	OUT_PADDED(stream, level, "{\n");
	//stream << " {\n";
	OUT_PADDED(stream, level + 1, "\"total\" : ");
	stream << std::dec << report.scanned << ",\n";
	OUT_PADDED(stream, level + 1, "\"skipped\" : ");
	stream << std::dec << report.skipped << ",\n";
	OUT_PADDED(stream, level + 1, "\"modified\" : \n");
	OUT_PADDED(stream, level + 1, "{\n");
	//stream << "  {\n";
	OUT_PADDED(stream, level + 2, "\"total\" : ");
	stream << std::dec << report.suspicious << ",\n";
	OUT_PADDED(stream, level + 2, "\"patched\" : ");
	stream << std::dec << report.patched << ",\n";
	OUT_PADDED(stream, level + 2, "\"iat_hooked\" : ");
	stream << std::dec << report.iat_hooked << ",\n";
	OUT_PADDED(stream, level + 2, "\"replaced\" : ");
	stream << std::dec << report.replaced << ",\n";
	OUT_PADDED(stream, level + 2, "\"hdr_modified\" : ");
	stream << std::dec << report.hdr_mod << ",\n";
	OUT_PADDED(stream, level + 2, "\"implanted_pe\" : ");
	stream << std::dec << report.implanted_pe << ",\n";
	OUT_PADDED(stream, level + 2, "\"implanted_shc\" : ");
	stream << std::dec << report.implanted_shc << ",\n";
	OUT_PADDED(stream, level + 2, "\"unreachable_file\" : ");
	stream << std::dec << report.unreachable_file << ",\n";
	OUT_PADDED(stream, level + 2, "\"other\" : ");
	stream << std::dec << other << "\n";
	OUT_PADDED(stream, level + 1, "},\n"); // modified
	OUT_PADDED(stream, level + 1, "\"errors\" : ");
	stream << std::dec << report.errors << "\n";
	OUT_PADDED(stream, level, "},\n"); // scanned
	stream << listModules(level, filter);
	stream << "}\n";
	return true;
}

