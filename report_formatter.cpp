#include "report_formatter.h"

#include <sstream>

std::string report_to_string(const t_report report)
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

