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

std::string pesieve::scan_report_to_json(
	const ProcessScanReport &process_report,
	ProcessScanReport::t_report_filter filter,
	const pesieve::t_json_level &jdetails,
	size_t start_level
)
{
	//summary:
	std::stringstream stream;

	if (!process_report.toJSON(stream, start_level, filter, jdetails)) {
		return "";
	}
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return "";
	}
	return report_all;
}

std::string pesieve::dump_report_to_json(
	const ProcessDumpReport& process_report,
	const pesieve::t_json_level& jdetails,
	size_t start_level
)
{
	//summary:
	std::stringstream stream;

	if (!process_report.toJSON(stream, start_level)) {
		return "";
	}
	std::string report_all = stream.str();
	if (report_all.length() == 0) {
		return "";
	}
	return report_all;
}

std::string pesieve::report_to_json(const pesieve::ReportEx& report, const t_report_type rtype, ProcessScanReport::t_report_filter filter, const pesieve::t_json_level& jdetails, size_t start_level)
{
	if (!report.scan_report || rtype == REPORT_NONE) return 0;

	size_t level = 1;
	std::stringstream stream;
	const bool has_dumps = (report.dump_report && report.dump_report->countDumped() > 0) ? true : false;
	stream << "{\n";
	if (rtype == REPORT_ALL || rtype == REPORT_SCANNED) {
		OUT_PADDED(stream, level, "\"scan_report\" :\n");
		stream << scan_report_to_json(*report.scan_report, filter, jdetails, level);
		if (rtype == REPORT_ALL && has_dumps) {
			stream << ",";
		}
		stream << "\n";
	}
	if (rtype == REPORT_ALL || rtype == REPORT_DUMPED) {
		if (has_dumps || rtype == REPORT_DUMPED) { // do not output an empty report, unless requested specifically
			OUT_PADDED(stream, level, "\"dump_report\" :\n");
			stream << dump_report_to_json(*report.dump_report, jdetails, level);
			stream << "\n";
		}
	}
	stream << "}\n";
	return stream.str();
}
