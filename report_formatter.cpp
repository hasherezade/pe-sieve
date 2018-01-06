#include "report_formatter.h"
#include <string>
#include <sstream>

bool is_shown_type(t_scan_status status, t_report_filter filter)
{
	if (filter == REPORT_ALL) {
		return true;
	}
	if (filter & REPORT_ERRORS) {
		if (status == SCAN_ERROR) return true;
	}
	if (filter & REPORT_MODIFIED) {
		if (status == SCAN_MODIFIED) return true;
	}
	if (filter & REPORT_NOT_MODIFIED) {
		if (status == SCAN_NOT_MODIFIED) return true;
	}
	return false;
}

std::string list_modules(const ProcessScanReport &report, t_report_filter filter)
{
	std::stringstream stream;
	stream << "\"scans\" : [\n";
	//summary:
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = report.module_reports.begin() ; itr != report.module_reports.end(); itr++) {
		ModuleScanReport *mod = *itr;
		if (is_shown_type(mod->status, filter)) {
			if (itr != report.module_reports.begin()) {
				stream << ",\n";
			}
			stream << "{\n";
			mod->toJSON(stream);
			stream << "\n}";
		}
	}
	stream << "\n";
	stream << "]\n";
	return stream.str();
}

std::string report_to_string(const ProcessScanReport &process_report)
{
	const t_report &report = process_report.summary;
	std::stringstream stream;
	//summary:
	size_t total_modified = report.hooked + report.replaced + report.suspicious;
	stream << "PID:    " << std::dec << report.pid << "\n";
	stream << "---" << std::endl;
	stream << "SUMMARY: \n" << std::endl;
	stream << "Total scanned:    " << std::dec << report.scanned << "\n";
	stream << "-\n";
	stream << "Hooked:           " << std::dec << report.hooked << "\n";
	stream << "Replaced:         " << std::dec << report.replaced << "\n";
	stream << "Other suspicious: " << std::dec << report.suspicious << "\n";
	stream << "-\n";
	stream << "Total modified:   " << std::dec << total_modified << "\n";
	if (report.errors) {
		stream << "[!] Reading errors: " << std::dec << report.errors << "\n";
	}
	return stream.str();
}

std::string report_to_json(const ProcessScanReport &process_report, t_report_filter filter)
{
	const t_report &report = process_report.summary;
	std::stringstream stream;
	//summary:
	size_t total_modified = report.hooked + report.replaced + report.suspicious;
	stream << "{\n";
	stream << " \"pid\" : " << std::dec << report.pid << ",\n";
	stream << " \"scanned\" : \n";
	stream << " {\n";
	stream << "  \"total\" : " << std::dec << report.scanned  << ",\n";
	stream << "  \"modified\" : \n";
	stream << "  {\n";
	stream << "   \"total\" : " << std::dec << total_modified << ",\n";
	stream << "   \"hooked\" : " << std::dec << report.hooked << ",\n";
	stream << "   \"replaced\" : "  << std::dec << report.replaced << ",\n";
	stream << "   \"suspicious\" : "  << std::dec << report.suspicious << "\n";
	stream << "  },\n";// modified
	stream << "  \"errors\" : "<< std::dec << report.errors << "\n";
	stream << " },\n";// scanned
	stream << list_modules(process_report, filter);
	stream << "}\n";
	return stream.str();
}
