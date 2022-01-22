#include "mapping_scanner.h"

#include "../utils/path_converter.h"

using namespace pesieve;
using namespace pesieve::util;

MappingScanReport* pesieve::MappingScanner::scanRemote()
{
	MappingScanReport *my_report = new MappingScanReport(moduleData.moduleHandle, moduleData.original_size);

	std::string mapped_name = RemoteModuleData::getMappedName(processHandle, moduleData.moduleHandle);
	std::string module_name = moduleData.szModName;
	bool is_same = (to_lowercase(mapped_name) == to_lowercase(module_name));
	
	my_report->mappedFile = mapped_name;
	my_report->moduleFile = module_name;
	my_report->isDotNetModule = moduleData.isDotNet();

	size_t mod_name_len = module_name.length();
	if (!is_same && mod_name_len > 0) {
		//check Wow64
		char path_copy[MAX_PATH] = { 0 };
		memcpy(path_copy, moduleData.szModName, mod_name_len);
		convert_to_wow64_path(path_copy);
		is_same = (to_lowercase(mapped_name) == to_lowercase(path_copy));
		if (is_same) {
			moduleData.switchToWow64Path();
		}
	}
	if (!is_same) {
		my_report->status = SCAN_SUSPICIOUS;
		return my_report;
	}
	my_report->status = SCAN_NOT_SUSPICIOUS;
	return my_report;
}
