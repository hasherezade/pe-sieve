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
	if (filter & REPORT_SUSPICIOUS) {
		if (status == SCAN_SUSPICIOUS) return true;
	}
	if (filter & REPORT_NOT_SUSPICIOUS) {
		if (status == SCAN_NOT_SUSPICIOUS) return true;
	}
	return false;
}

std::string list_modules(const ProcessScanReport &report, t_report_filter filter)
{
	std::stringstream stream;
	stream << "\"scans\" : [\n";
	//summary:
	bool is_first = true;
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = report.module_reports.begin() ; itr != report.module_reports.end(); itr++) {
		ModuleScanReport *mod = *itr;
		if (is_shown_type(mod->status, filter)) {
			if (!is_first) {
				stream << ",\n";
			}
			stream << "{\n";
			mod->toJSON(stream);
			stream << "\n}";
			is_first = false;
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
	size_t other = report.suspicious - (report.hooked + report.replaced + report.detached + report.implanted);
	stream << "PID:    " << std::dec << report.pid << "\n";
	stream << "---" << std::endl;
	stream << "SUMMARY: \n" << std::endl;
	stream << "Total scanned:    " << std::dec << report.scanned << "\n";
	stream << "Skipped:          " << std::dec << report.skipped << "\n";
	stream << "-\n";
	stream << "Hooked:           " << std::dec << report.hooked << "\n";
	stream << "Replaced:         " << std::dec << report.replaced << "\n";
	stream << "Detached:         " << std::dec << report.detached << "\n";
	stream << "Implanted:        " << std::dec << report.implanted << "\n";
	stream << "Other:            " << std::dec << other << "\n";
	stream << "-\n";
	stream << "Total suspicious:   " << std::dec << report.suspicious << "\n";
	if (report.errors) {
		stream << "[!] Errors: " << std::dec << report.errors << "\n";
	}
	return stream.str();
}

std::string report_to_json(const ProcessScanReport &process_report, t_report_filter filter)
{
	const t_report &report = process_report.summary;
	std::stringstream stream;
	//summary:
	size_t other = report.suspicious - (report.hooked + report.replaced + report.detached + report.implanted);
	stream << "{\n";
	stream << " \"pid\" : " << std::dec << report.pid << ",\n";
	stream << " \"main_image_path\" : \"" << process_report.mainImagePath << "\",\n";
	stream << " \"scanned\" : \n";
	stream << " {\n";
	stream << "  \"total\" : " << std::dec << report.scanned  << ",\n";
	stream << "  \"skipped\" : " << std::dec << report.skipped  << ",\n";
	stream << "  \"modified\" : \n";
	stream << "  {\n";
	stream << "   \"total\" : " << std::dec << report.suspicious << ",\n";
	stream << "   \"hooked\" : " << std::dec << report.hooked << ",\n";
	stream << "   \"replaced\" : "  << std::dec << report.replaced << ",\n";
	stream << "   \"detached\" : " << std::dec << report.detached << ",\n";
	stream << "   \"implanted\" : "  << std::dec << report.implanted << ",\n";
	stream << "   \"other\" : "  << std::dec << other << "\n";
	stream << "  },\n";// modified
	stream << "  \"errors\" : "<< std::dec << report.errors << "\n";
	stream << " },\n";// scanned
	stream << list_modules(process_report, filter);
	stream << "}\n";
	return stream.str();
}
