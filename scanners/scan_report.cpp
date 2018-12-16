#include "scan_report.h"

#include "headers_scanner.h"
#include "code_scanner.h"
#include "workingset_scanner.h"
#include "mapping_scanner.h"


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
		modulesInfo.appendModule(mod);
	}
	if (mod->is_suspicious == false) {
		//update the status
		mod->is_suspicious = (report->status == SCAN_SUSPICIOUS);
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
	if (dynamic_cast<UnreachableModuleReport*>(report)) {
		this->reportsByType[REPORT_UNREACHABLE_SCAN].insert(report);
		return;
	}
	if (dynamic_cast<SkippedModuleReport*>(report)) {
		this->reportsByType[REPORT_SKIPPED_SCAN].insert(report);
		return;
	}
}

size_t ProcessScanReport::countSuspiciousPerType(report_type_t type) const
{
	if (type >= REPORT_TYPES_COUNT) {
		return 0; //invalid type
	}
	size_t suspicious = 0;
	std::set<ModuleScanReport*>::iterator itr;
	for (itr = this->reportsByType[type].begin(); itr != this->reportsByType[type].end(); itr++) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			suspicious++;
		}
	}
	return suspicious;
}

t_report ProcessScanReport::generateSummary() const
{
	t_report summary = { 0 };
	summary.pid = this->pid;
	summary.errors = static_cast<DWORD>(this->errorsCount);
	summary.skipped = static_cast<DWORD>(this->reportsByType[REPORT_SKIPPED_SCAN].size());
	summary.scanned = static_cast<DWORD>(this->reportsByType[REPORT_HEADERS_SCAN].size());

	std::vector<ModuleScanReport*>::const_iterator itr = module_reports.begin();
	for (; itr != module_reports.end(); itr++) {
		ModuleScanReport* report = *itr;
		if (ModuleScanReport::get_scan_status(report) == SCAN_SUSPICIOUS) {
			summary.suspicious++;
		}
		if (ModuleScanReport::get_scan_status(report) == SCAN_ERROR) {
			summary.errors++;
		}
		
	}
	summary.hooked = countSuspiciousPerType(REPORT_CODE_SCAN);
	summary.implanted = countSuspiciousPerType(REPORT_MEMPAGE_SCAN);
	summary.replaced = countSuspiciousPerType(REPORT_HEADERS_SCAN);
	summary.detached = countSuspiciousPerType(REPORT_UNREACHABLE_SCAN);
	
	return summary;
}

