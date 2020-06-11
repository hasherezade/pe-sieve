#include "scan_report.h"

#include "headers_scanner.h"
#include "code_scanner.h"
#include "iat_scanner.h"
#include "workingset_scanner.h"
#include "mapping_scanner.h"

#include "../utils/format_util.h"

using namespace pesieve;
using namespace pesieve::util;

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

bool ProcessScanReport::hasAnyShownType(const ProcessScanReport::t_report_filter &filter)
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

bool ProcessScanReport::appendToModulesList(ModuleScanReport *report)
{
	if (report->moduleSize == 0) {
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

void ProcessScanReport::appendToType(ModuleScanReport *report)
{
	if (report == nullptr) return;

	if (dynamic_cast<HeadersScanReport*>(report)) {
		this->reportsByType[REPORT_HEADERS_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<WorkingSetScanReport*>(report)) {
		this->reportsByType[REPORT_MEMPAGE_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<MappingScanReport*>(report)) {
		this->reportsByType[REPORT_MAPPING_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<CodeScanReport*>(report)) {
		this->reportsByType[REPORT_CODE_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<IATScanReport*>(report)) {
		this->reportsByType[REPORT_IAT_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<UnreachableModuleReport*>(report)) {
		this->reportsByType[REPORT_UNREACHABLE_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<SkippedModuleReport*>(report)) {
		this->reportsByType[REPORT_SKIPPED_SCAN].insert(report);
		return;
	}
}

size_t ProcessScanReport::countSuspiciousPerType(t_report_type type) const
{
	if (type >= REPORT_TYPES_COUNT) {
		return 0; //invalid type
	}
	size_t suspicious = 0;
	std::set<ModuleScanReport*>::iterator itr;
	for (itr = this->reportsByType[type].begin(); itr != this->reportsByType[type].end(); ++itr) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			suspicious++;
		}
	}
	return suspicious;
}

size_t ProcessScanReport::countHdrsReplaced() const
{
	size_t replaced = 0;
	const t_report_type type = t_report_type::REPORT_HEADERS_SCAN;

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

pesieve::t_report ProcessScanReport::generateSummary() const
{
	t_report summary = { 0 };
	summary.pid = this->pid;
	summary.errors = static_cast<DWORD>(this->errorsCount);
	summary.skipped = static_cast<DWORD>(this->reportsByType[REPORT_SKIPPED_SCAN].size());
	summary.scanned = static_cast<DWORD>(this->reportsByType[REPORT_HEADERS_SCAN].size());

	std::vector<ModuleScanReport*>::const_iterator itr = module_reports.begin();
	for (; itr != module_reports.end(); ++itr) {
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
	summary.implanted = countSuspiciousPerType(REPORT_MEMPAGE_SCAN);
	summary.hdr_mod = countSuspiciousPerType(REPORT_HEADERS_SCAN) - summary.replaced;
	summary.detached = countSuspiciousPerType(REPORT_UNREACHABLE_SCAN);
	
	return summary;
}

std::string ProcessScanReport::list_modules(size_t level, const ProcessScanReport::t_report_filter &filter) const
{
	std::stringstream stream;
	//summary:
	OUT_PADDED(stream, level, "\"scans\" : [\n");
	bool is_first = true;
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = this->module_reports.begin(); itr != this->module_reports.end(); ++itr) {
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
	if (module_reports.size()) {
		stream << "\n";
	}
	OUT_PADDED(stream, level, "]\n");
	return stream.str();
}

const bool ProcessScanReport::toJSON(std::stringstream &stream, size_t level, const ProcessScanReport::t_report_filter &filter) const
{
	const t_report report = this->generateSummary();
	//summary:
	size_t other = report.suspicious - (report.patched + report.replaced + report.detached + report.implanted + report.hdr_mod);
	stream << "{\n";
	OUT_PADDED(stream, level, "\"pid\" : ");
	stream << std::dec << report.pid << ",\n";
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
	OUT_PADDED(stream, level + 2, "\"detached\" : ");
	stream << std::dec << report.detached << ",\n";
	OUT_PADDED(stream, level + 2, "\"implanted\" : ");
	stream << std::dec << report.implanted << ",\n";
	OUT_PADDED(stream, level + 2, "\"other\" : ");
	stream << std::dec << other << "\n";
	OUT_PADDED(stream, level + 1, "},\n"); // modified
	OUT_PADDED(stream, level + 1, "\"errors\" : ");
	stream << std::dec << report.errors << "\n";
	OUT_PADDED(stream, level, "},\n"); // scanned
	stream << list_modules(level, filter);
	stream << "}\n";
	return true;
}

