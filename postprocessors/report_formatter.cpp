#include "report_formatter.h"
#include <string>
#include <sstream>

using namespace pesieve;

std::string pesieve::scan_report_to_string(const ProcessScanReport &process_report)
{
	const t_report report = process_report.generateSummary();
	std::stringstream stream;
	//summary:
	size_t other = report.other;
	stream << "---" << std::endl;
	stream << "PID: " << std::dec << report.pid << "\n";
	stream << "---" << std::endl;
	stream << "SUMMARY: \n" << std::endl;
	stream << "Total scanned:      " << std::dec << report.scanned << "\n";
	stream << "Skipped:            " << std::dec << report.skipped << "\n";
	stream << "-\n";
	stream << "Hooked:             " << std::dec << report.patched << "\n";
	stream << "Replaced:           " << std::dec << report.replaced << "\n";
	stream << "Hdrs Modified:      " << std::dec << report.hdr_mod << "\n";
	stream << "IAT Hooks:          " << std::dec << report.iat_hooked << "\n";
	stream << "Implanted:          " << std::dec << report.implanted << "\n";
	if (report.implanted) {
		stream << "Implanted PE:       " << std::dec << report.implanted_pe << "\n";
		stream << "Implanted shc:      " << std::dec << report.implanted_shc << "\n";
	}
	stream << "Unreachable files:  " << std::dec << report.unreachable_file << "\n";
	stream << "Other:              " << std::dec << other << "\n";
	stream << "-\n";
	stream << "Total suspicious:   " << std::dec << report.suspicious << "\n";
	if (report.errors) {
		stream << "[!] Errors:         " << std::dec << report.errors << "\n";
	}
	return stream.str();
}

std::string pesieve::scan_report_to_json(const ProcessScanReport &process_report, ProcessScanReport::t_report_filter filter)
{
	//summary:
	std::stringstream stream;
	size_t level = 1;

	if (!process_report.toJSON(stream, level, filter)) {
		return "";
	}
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return "";
	}
	return report_all;
}
