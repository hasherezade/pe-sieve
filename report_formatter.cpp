#include "report_formatter.h"
#include <string>
#include <sstream>

std::string list_modules(const t_report &report)
{
	std::stringstream stream;
	stream << "[\n";
	//summary:
	std::vector<ModuleScanReport*>::const_iterator itr;
	for (itr = report.module_reports.begin() ; itr != report.module_reports.end(); itr++) {
		ModuleScanReport *mod = *itr;
		if (mod->status == SCAN_MODIFIED) {
			if (itr != report.module_reports.begin()) {
				stream << ",\n";
			}
			(*itr)->toJSON(stream);
		}
	}
	stream << "\n]\n";
	return stream.str();
}

std::string report_to_string(const t_report &report)
{
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

std::string report_to_json(const t_report &report)
{
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
	stream << " }\n";// scanned
	stream << "}\n";
	stream << "\"scans\" : " << list_modules(report);
	return stream.str();
}
