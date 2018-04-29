
#pragma once

#include <Windows.h>

#include "module_scanner.h"
#include "../utils/util.h"

class MappingScanReport : public ModuleScanReport
{
public:
	MappingScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize)
	{
	}

	const virtual bool toJSON(std::stringstream& outs)
	{
		outs << "\"mapping_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"mapped_file\" : \"" << escape_path_separators(this->mappedFile) << "\"";
		outs << ",\n";
		outs << "\"module_file\" : \"" << escape_path_separators(this->moduleFile) << "\"";
		outs << "\n";
		outs << "}";
		return true;
	}
	std::string mappedFile;
	std::string moduleFile;
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
