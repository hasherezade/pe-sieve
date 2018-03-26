
#pragma once

#include <Windows.h>

#include "module_scanner.h"



class MappingScanReport : public ModuleScanReport
{
public:
	MappingScanReport(HANDLE processHandle, HMODULE _module)
		: ModuleScanReport(processHandle, _module)
	{
	}

	const virtual bool toJSON(std::stringstream& outs)
	{
		outs << "\"mapping_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"mapped_file\" : \"" << this->mappedFile << "\"";
		outs << ",\n";
		outs << "\"module_file\" : \"" << this->moduleFile << "\"";
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
