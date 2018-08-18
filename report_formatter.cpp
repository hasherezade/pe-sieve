#include "report_formatter.h"
#include <string>
#include <sstream>

#include "utils\util.h"

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
	//summary:
	size_t level = 1;
	OUT_PADDED(stream, level, "\"scans\" : [\n");
	bool is_first = true;
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = report.module_reports.begin() ; itr != report.module_reports.end(); itr++) {
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
	stream << "\n";
	OUT_PADDED(stream, level, "]\n");
	return stream.str();
}

std::string report_to_string(const ProcessScanReport &process_report)
{
	const t_report report = process_report.generateSummary();
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
	const t_report report = process_report.generateSummary();
	std::stringstream stream;
	//summary:
	size_t level = 1;
	size_t other = report.suspicious - (report.hooked + report.replaced + report.detached + report.implanted);
	stream << "{\n";
	OUT_PADDED(stream, level, "\"pid\" : ");
	stream << std::dec << report.pid << ",\n";
	OUT_PADDED(stream, level, "\"main_image_path\" : \"");
	stream <<  escape_path_separators(process_report.mainImagePath) << "\",\n";
	OUT_PADDED(stream, level, "\"scanned\" : \n");
	OUT_PADDED(stream, level, "{\n");
	//stream << " {\n";
	OUT_PADDED(stream, level + 1, "\"total\" : ");
	stream << std::dec << report.scanned  << ",\n";
	OUT_PADDED(stream, level + 1, "\"skipped\" : ");
	stream <<  std::dec << report.skipped  << ",\n";
	OUT_PADDED(stream, level + 1, "\"modified\" : \n");
	OUT_PADDED(stream, level + 1, "{\n");
	//stream << "  {\n";
	OUT_PADDED(stream, level + 2, "\"total\" : ");
	stream <<  std::dec << report.suspicious << ",\n";
	OUT_PADDED(stream, level + 2, "\"hooked\" : ");
	stream << std::dec << report.hooked << ",\n";
	OUT_PADDED(stream, level + 2, "\"replaced\" : ");
	stream << std::dec << report.replaced << ",\n";
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
	stream << list_modules(process_report, filter);
	stream << "}\n";
	return stream.str();
}
