
#pragma once

#include <windows.h>

#include "module_scanner.h"
#include "../utils/path_util.h"
#include "process_feature_scanner.h"

namespace pesieve {

	class MappingScanReport : public ModuleScanReport
	{
	public:
		MappingScanReport(HMODULE _module, size_t _moduleSize)
			: ModuleScanReport(_module, _moduleSize)
		{
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level, const pesieve::t_json_level &jdetails)
		{
			OUT_PADDED(outs, level, "\"module\" : ");
			outs << "\"" << std::hex << (ULONGLONG)module << "\"" << ",\n";

			OUT_PADDED(outs, level, "\"module_file\" : \"" << pesieve::util::escape_path_separators(this->moduleFile) << "\"");
			outs << ",\n";
			OUT_PADDED(outs, level, "\"mapped_file\" : \"" << pesieve::util::escape_path_separators(this->mappedFile) << "\"");

			outs << ",\n";
			OUT_PADDED(outs, level, "\"status\" : ");
			outs << std::dec << status;
		}

		const virtual bool toJSON(std::stringstream& outs, size_t level, const pesieve::t_json_level &jdetails)
		{
			OUT_PADDED(outs, level, "\"mapping_scan\" : ");
			outs << "{\n";
			fieldsToJSON(outs, level + 1, jdetails);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		std::string mappedFile;
	};


	//!  A scanner for detection of inconsistencies in mapping. Checks if the mapped file name is different than the module file name.
	class MappingScanner : public ProcessFeatureScanner {
	public:
		MappingScanner(HANDLE hProc, ModuleData &moduleData)
			: ProcessFeatureScanner(hProc), moduleData(moduleData)
		{
		}

		virtual MappingScanReport* scanRemote();

		ModuleData &moduleData;
	};

}; //namespace pesieve
