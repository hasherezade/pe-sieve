
#pragma once

#include <windows.h>

#include "module_scanner.h"
#include "../utils/path_util.h"

namespace pesieve {

	class MappingScanReport : public ModuleScanReport
	{
	public:
		MappingScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
			: ModuleScanReport(processHandle, _module, _moduleSize)
		{
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
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

		const virtual bool toJSON(std::stringstream& outs, size_t level = JSON_LEVEL)
		{
			OUT_PADDED(outs, level, "\"mapping_scan\" : ");
			outs << "{\n";
			fieldsToJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		std::string mappedFile;
	};

	//is the mapped file name different than the module file name?
	class MappingScanner {
	public:
		MappingScanner(HANDLE hProc, ModuleData &moduleData)
			: processHandle(hProc), moduleData(moduleData)
		{
		}

		virtual MappingScanReport* scanRemote();

		HANDLE processHandle;
		ModuleData &moduleData;
	};

}; //namespace pesieve
