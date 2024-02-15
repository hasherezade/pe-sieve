#include "dump_report.h"

#include "../utils/format_util.h"

using namespace pesieve::util;

const bool pesieve::ModuleDumpReport::toJSON(std::stringstream &outs, size_t level)
{
	OUT_PADDED(outs, level, "\"module\" : ");
	outs << "\"" << std::hex << moduleStart << "\"" << ",\n";
	OUT_PADDED(outs, level, "\"module_size\" : ");
	outs << "\"" << std::hex << moduleSize << "\"" << ",\n";
	if (dumpFileName.length()) {
		OUT_PADDED(outs, level, "\"dump_file\" : ");
		outs << "\"" << peconv::get_file_name(dumpFileName) << "\"" << ",\n";
	}
	if (hooksTagFileName.length()) {
		OUT_PADDED(outs, level, "\"tags_file\" : ");
		outs << "\"" << peconv::get_file_name(hooksTagFileName) << "\"" << ",\n";
	}
	if (patternsTagFileName.length()) {
		OUT_PADDED(outs, level, "\"pattern_tags_file\" : ");
		outs << "\"" << peconv::get_file_name(patternsTagFileName) << "\"" << ",\n";
	}
	if (impListFileName.length()) {
		OUT_PADDED(outs, level, "\"imports_file\" : ");
		outs << "\"" << peconv::get_file_name(impListFileName) << "\"" << ",\n";
	}
	if (impRecMode.length()) {
		OUT_PADDED(outs, level, "\"imp_rec_result\" : ");
		outs << "\"" << impRecMode << "\"" << ",\n";
		if (notRecoveredFileName.length()) {
			OUT_PADDED(outs, level, "\"imp_not_recovered_file\" : ");
			outs << "\"" << peconv::get_file_name(notRecoveredFileName) << "\"" << ",\n";
		}
	}
	if (this->iatHooksFileName.length()) {
		OUT_PADDED(outs, level, "\"iat_hooks_file\" : ");
		outs << "\"" << peconv::get_file_name(iatHooksFileName) << "\"" << ",\n";
	}
	if (mode_info.length()) {
		OUT_PADDED(outs, level, "\"dump_mode\" : ");
		outs << "\"" << mode_info << "\"" << ",\n";
	}
	OUT_PADDED(outs, level, "\"is_shellcode\" : ");
	outs << std::dec << is_shellcode << ",\n";
	if (is_corrupt_pe) {
		OUT_PADDED(outs, level, "\"is_corrupt_pe\" : ");
		outs << std::dec << is_corrupt_pe << ",\n";
	}

	OUT_PADDED(outs, level, "\"status\" : ");
	outs << std::dec << this->isDumped;
	return true;
}

// ProcessDumpReport

bool pesieve::ProcessDumpReport::toJSON(std::stringstream &stream, size_t start_level) const
{
	size_t level = start_level + 1;
	OUT_PADDED(stream, start_level, "{\n"); // beginning of the report

	OUT_PADDED(stream, level, "\"pid\" : ");
	stream << std::dec << getPid() << ",\n";

	OUT_PADDED(stream, level, "\"output_dir\" : \"");
	stream << escape_path_separators(outputDir) << "\",\n";
	if (minidumpPath.length()) {
		OUT_PADDED(stream, level, "\"minidump_path\" : \"");
		stream << escape_path_separators(this->minidumpPath) << "\",\n";
	}

	OUT_PADDED(stream, level, "\"dumped\" : \n");
	OUT_PADDED(stream, level, "{\n");
	//stream << " {\n";
	OUT_PADDED(stream, level + 1, "\"total\" : ");
	stream << std::dec << countTotal() << ",\n";
	OUT_PADDED(stream, level + 1, "\"dumped\" : ");
	stream << std::dec << countDumped() << "\n";
	OUT_PADDED(stream, level, "},\n"); // scanned
	stream << list_dumped_modules(level);

	OUT_PADDED(stream, start_level, "}"); // end of the report

	return true;
}

std::string pesieve::ProcessDumpReport::list_dumped_modules(size_t level) const
{
	std::stringstream stream;
	//summary:
	OUT_PADDED(stream, level, "\"dumps\" : [\n");
	bool is_first = true;
	std::vector<ModuleDumpReport*>::const_iterator itr;
	for (itr = moduleReports.begin(); itr != moduleReports.end(); ++itr) {
		ModuleDumpReport *mod = *itr;
		if (mod->isDumped || mod->isReportDumped) {
			if (!is_first) {
				stream << ",\n";
			}
			OUT_PADDED(stream, level + 1, "{\n");
			if (mod->toJSON(stream, level + 2)) {
				stream << "\n";
			}
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
